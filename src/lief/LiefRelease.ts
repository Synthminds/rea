/** LIEF major.minor release line whose Python API the helper reads. */
export const LIEF_ADMITTED_RELEASE = "1.0";
/** Exact upstream release used for real-provider verification. */
export const LIEF_VERIFIED_VERSION = "1.0.0";

/** Static identity; Evidence records the observed `lief.__version__` instead. */
export const LIEF_PROVIDER_IDENTITY = {
  id: "lief",
  name: "REA LIEF adapter",
  version: `lief@${LIEF_ADMITTED_RELEASE}.x`,
} as const;

/**
 * Fixed byte budgets for one helper run. The reply holds one complete facet;
 * diagnostics hold LIEF parser warnings and Python stderr. The helper lowers
 * its address-space soft limit to the value REA sends in each request.
 */
export const LIEF_LIMITS = {
  replyBytes: 32 * 1024 * 1024,
  diagnosticBytes: 4 * 1024 * 1024,
  addressSpaceBytes: 4 * 1024 * 1024 * 1024,
  /** Distinct diagnostic lines kept inline in a result; the digest covers the rest. */
  diagnosticExcerptBytes: 4 * 1024,
  /** Longest single diagnostic line kept in that excerpt. */
  diagnosticLineBytes: 512,
  /** Head and tail of each output stream kept in a typed failure. */
  failureOutputBytes: 4 * 1024,
  /** Excerpt of a helper refusal message; the full size is reported. */
  messageBytes: 1024,
  /** Largest interpreter or native LIEF module file REA digests. */
  toolBytes: 256 * 1024 * 1024,
} as const;

/** Only Linux x64 has real verification of the helper's resource limits. */
export const liefHostSupported = (
  platform: NodeJS.Platform,
  arch: string,
): boolean => platform === "linux" && arch === "x64";

/** Configuration and recovery guidance shared by errors and availability. */
export const LIEF_CONFIGURATION_GUIDANCE = `Set absolute REA_LIEF_PYTHON to a caller-supplied Python 3 executable that can import LIEF ${LIEF_ADMITTED_RELEASE}.x (verified with ${LIEF_VERIFIED_VERSION}), for example a virtual environment created with python3 -m venv and pip install lief==${LIEF_VERIFIED_VERSION}. REA never installs Python or LIEF. Set it in the shell for the next CLI call, or in the MCP server launch environment and restart that server.`;
