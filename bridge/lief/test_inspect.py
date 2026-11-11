"""Helper regressions with controlled LIEF-shaped objects, not real-LIEF qualification."""
import enum
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


BRIDGE = Path(__file__).with_name("inspect.py")
SPEC = importlib.util.spec_from_file_location("rea_lief_inspect", BRIDGE)
inspect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspect)


class Binding(enum.Enum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    GNU_UNIQUE = 10


class Visibility(enum.Enum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3


class Kind(enum.Enum):
    NOTYPE = 0
    FUNC = 2


FAKE_LIEF = types.SimpleNamespace(
    ELF=types.SimpleNamespace(Symbol=types.SimpleNamespace(BINDING=Binding, VISIBILITY=Visibility)),
)


def symbol(name, shndx, binding, visibility=Visibility.DEFAULT, value=0x1000):
    return types.SimpleNamespace(
        name=name, shndx=shndx, binding=binding, visibility=visibility, type=Kind.FUNC, value=value, has_version=False,
    )


def raises_decode(raw):
    def read():
        raise UnicodeDecodeError("utf-8", raw, 1, 2, "invalid start byte")
    return read


class StringTests(unittest.TestCase):
    def test_valid_utf8_stays_a_string_and_other_bytes_keep_their_identity(self):
        self.assertEqual(inspect.text(lambda: "libc.so.6"), "libc.so.6")
        self.assertEqual(inspect.text(lambda: b"libc.so.6"), "libc.so.6")
        self.assertEqual(inspect.text(lambda: b"\xffib.so"), {"text": None, "bytes_hex": "ff69622e736f"})
        # An accessor that raises carries the exact source bytes in the exception.
        self.assertEqual(
            inspect.text(raises_decode(b"/\xffib64/ld.so")),
            {"text": None, "bytes_hex": "2fff69623634" + b"/ld.so".hex()},
        )

    def test_one_unreadable_field_is_reported_without_aborting_the_rest(self):
        fields = inspect.Fields()
        self.assertIsNone(fields.read("elf.soname", lambda: (_ for _ in ()).throw(RuntimeError("x" * 1000))))
        self.assertEqual(fields.read("elf.interpreter", lambda: "ok"), "ok")
        self.assertEqual(len(fields.unread), 1)
        self.assertEqual(fields.unread[0]["field"], "elf.soname")
        self.assertLessEqual(len(fields.unread[0]["error"].encode()), 256)
        with self.assertRaises(MemoryError):
            fields.read("x", lambda: (_ for _ in ()).throw(MemoryError()))


class TableTests(unittest.TestCase):
    def test_elf_dynamic_symbols_split_imports_and_exports_by_section_binding_and_visibility(self):
        binary = types.SimpleNamespace(dynamic_symbols=[
            symbol("", 0, Binding.LOCAL),
            symbol("__gmon_start__", 0, Binding.WEAK),
            symbol("puts", 0, Binding.GLOBAL),
            symbol("local_undef", 0, Binding.LOCAL),
            symbol("demo_add", 10, Binding.GLOBAL),
            symbol("weak_def", 10, Binding.WEAK),
            symbol("unique", 10, Binding.GNU_UNIQUE),
            symbol("hidden", 10, Binding.GLOBAL, Visibility.HIDDEN),
            symbol("local_def", 10, Binding.LOCAL),
        ])
        imports = [build() for build in inspect.elf_dynamic_symbols(FAKE_LIEF, binary, False)]
        exports = [build() for build in inspect.elf_dynamic_symbols(FAKE_LIEF, binary, True)]
        self.assertEqual([row["name"] for row in imports], ["__gmon_start__", "puts"])
        self.assertEqual([row["binding"] for row in imports], ["WEAK", "GLOBAL"])
        self.assertTrue(all(row["address"] is None for row in imports))
        self.assertEqual([row["name"] for row in exports], ["demo_add", "weak_def", "unique"])
        self.assertEqual(exports[0]["address"], "0x1000")

    def test_window_counts_every_row_but_builds_only_the_requested_ones(self):
        built = []

        def rows():
            for index in range(10_000):
                yield lambda index=index: built.append(index) or index

        self.assertEqual(inspect.window(rows(), 9_998, 5), (10_000, [9_998, 9_999]))
        self.assertEqual(built, [9_998, 9_999])
        self.assertEqual(inspect.count(rows()), 10_000)
        self.assertEqual(len(built), 2)

    def test_summary_lists_stop_at_the_bound_and_name_the_paging_operation(self):
        listing = inspect.Listing(3)
        built = []
        kept = listing.take("libraries", ((lambda index=index: built.append(index) or index) for index in range(7)), "libraries")
        self.assertEqual(kept, [0, 1, 2])
        self.assertEqual(built, [0, 1, 2])
        self.assertEqual(listing.truncated, [{"field": "libraries", "total": 7, "returned": 3, "operation": "libraries"}])
        self.assertEqual(listing.take("elf.rpath", (lambda: "x" for _ in range(2)), "rpaths"), ["x", "x"])
        self.assertEqual(len(listing.truncated), 1)


class ReplyTests(unittest.TestCase):
    def run_main(self, inspect_result=None, inspect_error=None, encode_failures=0, message_bytes=64):
        with tempfile.TemporaryDirectory() as directory:
            request = {
                "reply_path": os.path.join(directory, "reply.json"),
                "output_bytes": 1024 * 1024,
                "message_bytes": message_bytes,
                "address_space_bytes": 1 << 40,
            }
            path = os.path.join(directory, "request.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(request, handle)
            real_encode = inspect.encode
            calls = {"encode": 0}

            def encode(reply):
                calls["encode"] += 1
                if calls["encode"] <= encode_failures:
                    raise MemoryError()
                return real_encode(reply)

            def run(_request):
                if inspect_error is not None:
                    raise inspect_error
                return dict(inspect_result)

            limits = {"address_space_bytes": 123, "file_size_bytes": 456, "core_file_bytes": 0}
            with patch.object(inspect, "inspect", run), patch.object(inspect, "encode", encode), \
                    patch.object(inspect, "lower_resource_limits", lambda *_: limits):
                inspect.main(path)
            with open(request["reply_path"], encoding="utf-8") as handle:
                return json.load(handle)

    def test_memory_exhaustion_while_encoding_the_reply_is_a_resource_refusal(self):
        reply = self.run_main(inspect_result={"format": "elf"}, encode_failures=1)
        self.assertEqual(reply["ok"], False)
        self.assertEqual(reply["reason"], "resource-limit")
        self.assertEqual(reply["resource_limits"]["address_space_bytes"], 123)

    def test_refusal_messages_are_bounded_excerpts_with_their_full_size(self):
        message = "é" * 500
        reply = self.run_main(inspect_error=ValueError(message), message_bytes=64)
        self.assertEqual(reply["reason"], "decoder")
        self.assertLessEqual(len(reply["message"].encode("utf-8")), 64)
        self.assertEqual(reply["message_bytes"], len(f"ValueError: {message}".encode("utf-8")))
        self.assertEqual(reply["resource_limits"]["file_size_bytes"], 456)

    def test_success_records_the_effective_limits(self):
        reply = self.run_main(inspect_result={"format": "elf"})
        self.assertEqual(reply, {"ok": True, "value": {"format": "elf", "resource_limits": {"address_space_bytes": 123, "file_size_bytes": 456, "core_file_bytes": 0}}})


if __name__ == "__main__":
    unittest.main()
