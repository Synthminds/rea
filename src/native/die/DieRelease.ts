import type { FileSignatureBackend } from "../../domain/native/fileSignatures.js";

/**
 * Detect It Easy profiles this adapter knows. die-python 0.5.0 is the
 * real-verified profile and reports DiE 3.09 with dielib 0.1.0. The diec
 * contract is derived from the DIE-engine 3.09 console source only.
 */
export const DIE_ENGINE_VERSION = "3.09";
export const DIE_PYTHON_PACKAGE_VERSION = "0.5.0";

export const DIE_PROVIDER_IDENTITY = {
  id: "detect-it-easy",
  name: "REA Detect It Easy adapter",
  version: `die@${DIE_ENGINE_VERSION};die-python@${DIE_PYTHON_PACKAGE_VERSION}`,
} as const;

/**
 * Backends that selection admits. diec stays out until a real diec 3.09 lane
 * passes: no real diec has run, and a Qt6 diec is expected to die from
 * SIGXFSZ under the zero-byte file-size ceiling (see DIE_LIMITS).
 */
export const DIE_VERIFIED_BACKENDS: readonly FileSignatureBackend[] = [
  "die-python",
];

/** Default util-linux limiter; REA_DIE_PRLIMIT_COMMAND selects another absolute path. */
export const DIE_PRLIMIT_COMMAND_DEFAULT = "/usr/bin/prlimit";

/**
 * Fixed per-command allowances. The zero-byte file-size ceiling refuses any
 * file growth, including anonymous memfd sizing: DiE's embedded Qt QML engine
 * calls memfd_create then ftruncate, which fails with EFBIG and raises
 * SIGXFSZ. CPython ignores SIGXFSZ, so die-python continues past it; a native
 * diec keeps the default disposition and is expected to die. The ceiling does
 * not stop creating empty files or directories, renaming, unlinking,
 * truncation or permission changes. The address-space ceiling is not resident
 * memory.
 */
export const DIE_LIMITS = {
  toolBytes: 256 * 1024 * 1024,
  outputBytes: 16 * 1024 * 1024,
  addressSpaceBytes: 4 * 1024 * 1024 * 1024,
  cpuSeconds: 120,
  fileBytes: 0,
  maxFileParts: 4096,
  maxDetections: 65_536,
  maxDepth: 64,
} as const;

/** The verified host profile; discovery and execution share this check. */
export const dieHostSupported = (
  platform: NodeJS.Platform,
  arch: string,
): boolean => platform === "linux" && arch === "x64";
