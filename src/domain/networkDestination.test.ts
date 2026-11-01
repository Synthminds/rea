import { describe, expect, it, vi } from "vitest";

import {
  allowedPrivateDestinations,
  canonicalHost,
  classifyAddress,
  isUnresolved,
  refuseWithoutLookup,
  refusalSentence,
  urlPort,
  vetDestination,
  type DestinationPolicy,
  type DestinationResolver,
} from "./networkDestination.js";

const policy = (
  resolve: DestinationResolver,
  allowedOrigins: readonly string[] = [],
): DestinationPolicy => ({
  allowedPrivate: allowedPrivateDestinations(allowedOrigins),
  resolve,
});

const unreachableResolver: DestinationResolver = () => {
  throw new Error("literal destinations must not be resolved");
};

describe("classifyAddress for IPv4", () => {
  it.each([
    ["0.0.0.0", "unspecified"],
    ["0.1.2.3", "unspecified"],
    ["10.0.0.1", "private"],
    ["10.255.255.255", "private"],
    ["100.64.0.1", "shared"],
    ["100.127.255.254", "shared"],
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback"],
    ["169.254.0.1", "link-local"],
    ["169.254.169.254", "link-local"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["192.0.0.8", "protocol-assignment"],
    ["192.0.2.1", "documentation"],
    ["192.88.99.1", "reserved"],
    ["192.168.1.1", "private"],
    ["198.18.0.1", "benchmarking"],
    ["198.19.255.255", "benchmarking"],
    ["198.51.100.7", "documentation"],
    ["203.0.113.9", "documentation"],
    ["224.0.0.1", "multicast"],
    ["239.255.255.250", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "broadcast"],
  ] as const)("refuses %s as %s", (address, addressClass) => {
    expect(classifyAddress(address)).toMatchObject({
      address,
      family: 4,
      nonPublic: addressClass,
    });
  });

  it("names the cloud metadata service", () => {
    expect(classifyAddress("169.254.169.254")?.description).toBe(
      "169.254.169.254 is a link-local address (cloud instance metadata)",
    );
  });

  it.each([
    "8.8.8.8",
    "1.1.1.1",
    "93.184.215.14",
    "172.32.0.1",
    "172.15.255.255",
    "100.128.0.1",
    "100.63.255.255",
    "169.255.0.1",
    "192.169.0.1",
    "198.20.0.1",
    "223.255.255.255",
  ])("keeps %s public", (address) => {
    expect(classifyAddress(address)).toMatchObject({
      address,
      family: 4,
      nonPublic: undefined,
    });
  });

  it.each([
    ["2130706433", "127.0.0.1"],
    ["0x7f000001", "127.0.0.1"],
    ["0X7F000001", "127.0.0.1"],
    ["017700000001", "127.0.0.1"],
    ["0x7f.1", "127.0.0.1"],
    ["127.1", "127.0.0.1"],
    ["127.0.1", "127.0.0.1"],
    ["0177.0.0.01", "127.0.0.1"],
    ["0xa9.0xfe.0xa9.0xfe", "169.254.169.254"],
    ["0251.0376.0251.0376", "169.254.169.254"],
    ["2852039166", "169.254.169.254"],
    ["0", "0.0.0.0"],
    ["0x", "0.0.0.0"],
    ["127.0.0.1.", "127.0.0.1"],
  ])("reads the numeric form %s as %s", (text, address) => {
    expect(classifyAddress(text)?.address).toBe(address);
    expect(classifyAddress(text)?.nonPublic).toBeDefined();
  });

  it.each([
    "example.com",
    "256.0.0.1",
    "1.2.3.4.5",
    "0x1g",
    "08",
    "1..1",
    "4294967296",
    "",
  ])("does not read %j as an address", (text) => {
    expect(classifyAddress(text)).toBeUndefined();
  });
});

describe("classifyAddress for IPv6", () => {
  it.each([
    ["::", "::", "unspecified"],
    ["::1", "::1", "loopback"],
    ["[::1]", "::1", "loopback"],
    ["0:0:0:0:0:0:0:1", "::1", "loopback"],
    ["fe80::1", "fe80::1", "link-local"],
    ["fe80::1%eth0", "fe80::1", "link-local"],
    ["febf::1", "febf::1", "link-local"],
    ["fec0::1", "fec0::1", "site-local"],
    ["fc00::1", "fc00::1", "unique-local"],
    ["fd00:ec2::254", "fd00:ec2::254", "unique-local"],
    ["ff02::1", "ff02::1", "multicast"],
    ["2001:db8::1", "2001:db8::1", "documentation"],
    ["3fff::1", "3fff::1", "documentation"],
    ["2001::1", "2001::1", "tunnel"],
    ["2001:2::1", "2001:2::1", "protocol-assignment"],
    ["2002:7f00:1::1", "2002:7f00:1::1", "tunnel"],
    ["100::1", "100::1", "reserved"],
    ["64:ff9b:1::1", "64:ff9b:1::1", "address-translation"],
    ["::7f00:1", "::7f00:1", "ipv4-compatible"],
    ["::127.0.0.1", "::7f00:1", "ipv4-compatible"],
    ["4000::1", "4000::1", "reserved"],
  ] as const)("refuses %s as %s", (text, address, addressClass) => {
    expect(classifyAddress(text)).toMatchObject({
      address,
      family: 6,
      nonPublic: addressClass,
    });
  });

  it.each([
    ["::ffff:127.0.0.1", "::ffff:7f00:1", "embeds loopback 127.0.0.1"],
    ["::ffff:7f00:1", "::ffff:7f00:1", "embeds loopback 127.0.0.1"],
    ["[::ffff:7f00:1]", "::ffff:7f00:1", "embeds loopback 127.0.0.1"],
    [
      "::ffff:169.254.169.254",
      "::ffff:a9fe:a9fe",
      "embeds link-local 169.254.169.254",
    ],
    ["0:0:0:0:0:ffff:a00:1", "::ffff:a00:1", "embeds private 10.0.0.1"],
    ["::ffff:8.8.8.8", "::ffff:808:808", "embeds public 8.8.8.8"],
  ])(
    "refuses every IPv4-mapped address, naming the embedded one: %s",
    (text, address, detail) => {
      const verdict = classifyAddress(text);
      expect(verdict).toMatchObject({
        address,
        family: 6,
        nonPublic: "ipv4-mapped",
      });
      expect(verdict?.description).toBe(
        `${address} is an IPv4-mapped IPv6 address (${detail})`,
      );
    },
  );

  it("keeps NAT64 public only when the embedded IPv4 address is public", () => {
    expect(classifyAddress("64:ff9b::808:808")?.nonPublic).toBeUndefined();
    expect(classifyAddress("64:ff9b::a9fe:a9fe")).toMatchObject({
      nonPublic: "address-translation",
      description:
        "64:ff9b::a9fe:a9fe is a local address-translation address (NAT64 of link-local 169.254.169.254)",
    });
  });

  it.each(["2606:4700:4700::1111", "2a00:1450:4001::200e", "2001:4860::8888"])(
    "keeps %s public",
    (address) => {
      expect(classifyAddress(address)).toMatchObject({
        address,
        family: 6,
        nonPublic: undefined,
      });
    },
  );

  it.each([
    ":::1",
    "1::2::3",
    "1:2:3:4:5:6:7:8:9",
    "12345::1",
    "::g",
    "::1.2.3",
  ])("does not read %j as an address", (text) => {
    expect(classifyAddress(text)).toBeUndefined();
  });

  it("formats as the URL standard serializes hosts", () => {
    for (const host of [
      "[::ffff:127.0.0.1]",
      "[2001:db8:0:0:1:0:0:1]",
      "[fe80:0:0:0:0:0:0:1]",
      "[0:0:0:0:0:0:0:0]",
    ])
      expect(canonicalHost(host)).toBe(new URL(`http://${host}/`).hostname);
  });
});

describe("vetDestination", () => {
  it.each([
    ["127.0.0.1", "loopback"],
    ["169.254.169.254", "link-local"],
    ["::ffff:7f00:1", "ipv4-mapped"],
    ["0.0.0.0", "unspecified"],
    ["fd00::1", "unique-local"],
  ] as const)(
    "refuses literal %s without resolving it",
    async (host, addressClass) => {
      const result = await vetDestination(
        host,
        80,
        policy(unreachableResolver),
      );
      expect(result).toMatchObject({ ok: false, error: { addressClass } });
    },
  );

  it.each(["localhost", "LOCALHOST.", "app.localhost", "a.b.localhost"])(
    "refuses the localhost name %s without DNS",
    async (host) => {
      const result = await vetDestination(
        host,
        3000,
        policy(unreachableResolver),
      );
      expect(result).toMatchObject({
        ok: false,
        error: { addressClass: "localhost-name" },
      });
    },
  );

  it("keeps a name whose every answer is public and returns those answers to connect to", async () => {
    const resolve = vi.fn<DestinationResolver>(async () => [
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
    expect(await vetDestination("public.test", 443, policy(resolve))).toEqual({
      ok: true,
      value: {
        host: "public.test",
        port: 443,
        allowance: "public",
        addresses: [
          { address: "93.184.215.14", family: 4 },
          { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
        ],
      },
    });
    expect(resolve).toHaveBeenCalledExactlyOnceWith("public.test");
  });

  it.each([
    [["10.0.0.7"], "private"],
    [["93.184.215.14", "169.254.169.254"], "link-local"],
    [["169.254.169.254", "93.184.215.14"], "link-local"],
    [["2606:4700:4700::1111", "::1"], "loopback"],
    [["93.184.215.14", "::ffff:127.0.0.1"], "ipv4-mapped"],
    [["0.0.0.0"], "unspecified"],
  ] as const)(
    "refuses a name when any answer of %j is non-public",
    async (answers, addressClass) => {
      const resolve: DestinationResolver = async () =>
        answers.map((address) => ({
          address,
          family: address.includes(":") ? 6 : 4,
        }));
      const result = await vetDestination("mixed.test", 80, policy(resolve));
      expect(result).toMatchObject({ ok: false, error: { addressClass } });
      if (!result.ok)
        expect(result.error.reason).toMatch(/^mixed\.test resolves to /u);
    },
  );
});

describe("vetDestination resolution and allowances", () => {
  it("refuses an empty answer, a failed lookup and a non-address answer", async () => {
    expect(
      await vetDestination(
        "empty.test",
        80,
        policy(async () => []),
      ),
    ).toMatchObject({ ok: false, error: { addressClass: "unresolved" } });
    expect(
      await vetDestination(
        "missing.test",
        80,
        policy(async () => {
          throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
        }),
      ),
    ).toMatchObject({
      ok: false,
      error: {
        addressClass: "unresolved",
        reason: "missing.test could not be resolved (ENOTFOUND)",
      },
    });
    expect(
      await vetDestination(
        "odd.test",
        80,
        policy(async () => [{ address: "not-an-address", family: 4 }]),
      ),
    ).toMatchObject({ ok: false, error: { addressClass: "unresolved" } });
  });

  it("resolves exactly once, so a rebinding resolver cannot change the vetted answer", async () => {
    let calls = 0;
    const rebinding: DestinationResolver = async () => {
      calls += 1;
      return [
        calls === 1
          ? { address: "93.184.215.14", family: 4 }
          : { address: "127.0.0.1", family: 4 },
      ];
    };
    const result = await vetDestination("rebind.test", 80, policy(rebinding));
    expect(calls).toBe(1);
    expect(result).toMatchObject({
      ok: true,
      value: { addresses: [{ address: "93.184.215.14", family: 4 }] },
    });
  });

  it("allows only the exact host and port of an allowed private origin", async () => {
    const allowed = policy(
      async () => [{ address: "127.0.0.1", family: 4 }],
      ["http://127.0.0.1:5173", "http://localhost:3000", "https://[::1]"],
    );
    expect(await vetDestination("127.0.0.1", 5173, allowed)).toMatchObject({
      ok: true,
      value: { allowance: "allowed-private-origin" },
    });
    expect(await vetDestination("localhost", 3000, allowed)).toMatchObject({
      ok: true,
      value: {
        allowance: "allowed-private-origin",
        addresses: [{ address: "127.0.0.1", family: 4 }],
      },
    });
    expect(await vetDestination("::1", 443, allowed)).toMatchObject({
      ok: true,
    });
    for (const [host, port] of [
      ["127.0.0.1", 5174],
      ["127.0.0.1", 80],
      ["::ffff:7f00:1", 5173],
      ["localhost", 5173],
      ["127.0.0.2", 5173],
      ["169.254.169.254", 80],
    ] as const)
      expect(await vetDestination(host, port, allowed)).toMatchObject({
        ok: false,
      });
  });

  it("accepts a URL's bracketed IPv6 hostname as the host it names", async () => {
    expect(
      await vetDestination("[::1]", 80, policy(unreachableResolver)),
    ).toMatchObject({
      ok: false,
      error: { host: "::1", addressClass: "loopback" },
    });
    expect(
      await vetDestination(
        "[2606:4700:4700::1111]",
        443,
        policy(unreachableResolver),
      ),
    ).toMatchObject({
      ok: true,
      value: { addresses: [{ address: "2606:4700:4700::1111", family: 6 }] },
    });
    expect(
      refuseWithoutLookup(
        "[::1]",
        3000,
        allowedPrivateDestinations(["http://[::1]:3000"]),
      ),
    ).toBeUndefined();
  });

  it("marks only a failed or empty lookup as unresolved", async () => {
    const missing = await vetDestination(
      "missing.test",
      80,
      policy(async () => []),
    );
    expect(!missing.ok && isUnresolved(missing.error)).toBe(true);
    const loopback = await vetDestination(
      "127.0.0.1",
      80,
      policy(unreachableResolver),
    );
    expect(!loopback.ok && isUnresolved(loopback.error)).toBe(false);
  });

  it("names the refused destination and its class in one sentence", async () => {
    const result = await vetDestination(
      "169.254.169.254",
      80,
      policy(unreachableResolver),
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(refusalSentence(result.error)).toBe(
        "Refused 169.254.169.254:80: 169.254.169.254 is a link-local address (cloud instance metadata). Only public internet addresses are reached unless the exact origin is allowed with allow_private_origins.",
      );
  });
});

describe("URL host normalisation", () => {
  it.each([
    ["http://2130706433/", "loopback"],
    ["http://0x7f000001/", "loopback"],
    ["http://0x7f.1/", "loopback"],
    ["http://[::ffff:169.254.169.254]/", "ipv4-mapped"],
    ["http://[::ffff:127.0.0.1]:8080/", "ipv4-mapped"],
    ["http://foo.localhost/", "localhost-name"],
    ["https://0/", "unspecified"],
  ] as const)("refuses %s", async (href, addressClass) => {
    const url = new URL(href);
    const host = url.hostname.replace(/^\[|\]$/gu, "");
    expect(
      await vetDestination(host, urlPort(url), policy(unreachableResolver)),
    ).toMatchObject({ ok: false, error: { addressClass } });
  });

  it("derives default ports by scheme", () => {
    expect(urlPort(new URL("http://example.test/"))).toBe(80);
    expect(urlPort(new URL("https://example.test/"))).toBe(443);
    expect(urlPort(new URL("ws://example.test/"))).toBe(80);
    expect(urlPort(new URL("wss://example.test:8443/"))).toBe(8443);
  });
});
