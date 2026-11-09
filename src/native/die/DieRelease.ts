/**
 * Detect It Easy profiles this adapter admits. The diec contract is derived
 * from the DIE-engine 3.09 console source; die-python 0.5.0 is the
 * real-verified profile and reports DiE 3.09 with dielib 0.1.0.
 */
export const DIE_ENGINE_VERSION = "3.09";
export const DIE_PYTHON_PACKAGE_VERSION = "0.5.0";

export const DIE_PROVIDER_IDENTITY = {
  id: "detect-it-easy",
  name: "REA Detect It Easy adapter",
  version: `die@${DIE_ENGINE_VERSION};die-python@${DIE_PYTHON_PACKAGE_VERSION}`,
} as const;

/** Default util-linux limiter; REA_DIE_PRLIMIT_COMMAND selects another absolute path. */
export const DIE_PRLIMIT_COMMAND_DEFAULT = "/usr/bin/prlimit";

/**
 * Fixed per-command allowances. DiE writes no files for a scan, so the file
 * ceiling is zero; the address-space ceiling is not resident memory.
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
