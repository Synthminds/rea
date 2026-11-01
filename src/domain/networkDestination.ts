import { err, ok, type Result } from "./result.js";

/**
 * The single owner of "may REA connect to this host?". It classifies literal
 * addresses, refuses names it cannot prove public, and returns the addresses a
 * caller must connect to so a later resolution cannot swap them.
 */

/** Why an address is not a public internet destination. */
export type NonPublicAddressClass =
  | "unspecified"
  | "loopback"
  | "private"
  | "shared"
  | "link-local"
  | "unique-local"
  | "site-local"
  | "multicast"
  | "broadcast"
  | "reserved"
  | "documentation"
  | "benchmarking"
  | "protocol-assignment"
  | "ipv4-mapped"
  | "ipv4-compatible"
  | "address-translation"
  | "tunnel";

/** What one literal address is. */
export interface AddressVerdict {
  readonly address: string;
  readonly family: 4 | 6;
  /** Undefined when the address is a public internet address. */
  readonly nonPublic: NonPublicAddressClass | undefined;
  /** A sentence fragment naming the address and its class. */
  readonly description: string;
}

/**
 * Why a destination was refused; `addressClass` names the class of the refused
 * address. `unresolved` means no address could be vetted: callers report it
 * as a network failure (see `isUnresolved`), not as a policy refusal.
 */
export interface DestinationRefusal {
  readonly host: string;
  readonly port: number;
  readonly addressClass:
    | NonPublicAddressClass
    | "localhost-name"
    | "unresolved";
  readonly reason: string;
}

/** A destination REA may reach, with the only addresses it may connect to. */
export interface VettedDestination {
  readonly host: string;
  readonly port: number;
  readonly addresses: readonly ResolvedAddress[];
  readonly allowance: "public" | "allowed-private-origin";
}

export interface ResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

/** Resolves one name to every address it currently has; called at most once per vetting. */
export type DestinationResolver = (
  hostname: string,
) => Promise<readonly { readonly address: string; readonly family: number }[]>;

/** Which non-public destinations a caller explicitly allowed, and how names resolve. */
export interface DestinationPolicy {
  /** Exact `host:port` keys from `allowedPrivateDestinations`. */
  readonly allowedPrivate: ReadonlySet<string>;
  readonly resolve: DestinationResolver;
}

const RANGES_V4: readonly (readonly [
  number,
  number,
  NonPublicAddressClass,
  string?,
])[] = [
  [0x00000000, 8, "unspecified", "this-network"],
  [0x0a000000, 8, "private"],
  [0x64400000, 10, "shared", "carrier-grade NAT"],
  [0x7f000000, 8, "loopback"],
  [0xa9fea9fe, 32, "link-local", "cloud instance metadata"],
  [0xa9fe0000, 16, "link-local"],
  [0xac100000, 12, "private"],
  [0xc0000000, 24, "protocol-assignment"],
  [0xc0000200, 24, "documentation"],
  [0xc0586300, 24, "reserved", "6to4 relay anycast"],
  [0xc0a80000, 16, "private"],
  [0xc6120000, 15, "benchmarking"],
  [0xc6336400, 24, "documentation"],
  [0xcb007100, 24, "documentation"],
  [0xe0000000, 4, "multicast"],
  [0xffffffff, 32, "broadcast"],
  [0xf0000000, 4, "reserved"],
];

const ARTICLES: Readonly<Record<NonPublicAddressClass, string>> = {
  unspecified: "an unspecified",
  loopback: "a loopback",
  private: "a private",
  shared: "a shared",
  "link-local": "a link-local",
  "unique-local": "a unique-local",
  "site-local": "a site-local",
  multicast: "a multicast",
  broadcast: "a broadcast",
  reserved: "a reserved",
  documentation: "a documentation",
  benchmarking: "a benchmarking",
  "protocol-assignment": "an IETF protocol-assignment",
  "ipv4-mapped": "an IPv4-mapped IPv6",
  "ipv4-compatible": "an IPv4-compatible IPv6",
  "address-translation": "a local address-translation",
  tunnel: "a tunnel-relay",
};

const describe = (
  address: string,
  addressClass: NonPublicAddressClass,
  detail?: string,
): string =>
  `${address} is ${ARTICLES[addressClass]} address${detail === undefined ? "" : ` (${detail})`}`;

/** Parse one IPv4 part as the URL standard and inet_aton do: 0x hex, leading-0 octal, else decimal. */
const ipv4Part = (part: string): number | undefined => {
  if (/^0[xX][0-9a-fA-F]*$/u.test(part))
    return part.length === 2 ? 0 : Number.parseInt(part.slice(2), 16);
  if (/^0[0-7]+$/u.test(part)) return Number.parseInt(part.slice(1), 8);
  if (/^(?:0|[1-9][0-9]*)$/u.test(part)) return Number(part);
  return undefined;
};

/** The 32-bit value of a dotted, decimal, octal or hex IPv4 literal, as `http://0x7f000001/` names 127.0.0.1. */
const parseIpv4 = (text: string): number | undefined => {
  const parts = text.split(".");
  if (parts.length > 1 && parts.at(-1) === "") parts.pop();
  if (parts.length === 0 || parts.length > 4) return undefined;
  const values = parts.map(ipv4Part);
  let value = 0;
  for (const [index, part] of values.entries()) {
    if (part === undefined || !Number.isSafeInteger(part)) return undefined;
    const last = index === values.length - 1;
    const bytes = last ? 4 - index : 1;
    if (part >= 2 ** (8 * bytes)) return undefined;
    value = last ? value * 2 ** (8 * bytes) + part : value * 256 + part;
  }
  return value;
};

const dotted = (value: number): string =>
  [24, 16, 8, 0].map((shift) => String((value >>> shift) & 0xff)).join(".");

const inRange = (value: number, base: number, bits: number): boolean =>
  bits === 0 || value >>> (32 - bits) === base >>> (32 - bits);

const classifyIpv4 = (value: number): AddressVerdict => {
  const address = dotted(value);
  for (const [base, bits, addressClass, detail] of RANGES_V4)
    if (inRange(value, base, bits))
      return {
        address,
        family: 4,
        nonPublic: addressClass,
        description: describe(address, addressClass, detail),
      };
  return {
    address,
    family: 4,
    nonPublic: undefined,
    description: `${address} is a public address`,
  };
};

/** Eight 16-bit groups of an IPv6 literal, accepting a zone id and an embedded IPv4 tail. */
const parseIpv6 = (text: string): readonly number[] | undefined => {
  const unzoned = text.split("%")[0] ?? "";
  if (!unzoned.includes(":") || /[^0-9a-fA-F:.]/u.test(unzoned))
    return undefined;
  let tail: number[] = [];
  let head = unzoned;
  const lastColon = unzoned.lastIndexOf(":");
  const ipv4 = unzoned.slice(lastColon + 1);
  if (ipv4.includes(".")) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(ipv4)) return undefined;
    const octets = ipv4.split(".").map(Number);
    if (octets.some((octet) => octet > 255)) return undefined;
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    tail = [a * 256 + b, c * 256 + d];
    // Keep a `::` that precedes the IPv4 tail; drop a lone separating colon.
    head = unzoned.slice(0, lastColon + 1);
    if (!head.endsWith("::")) head = head.slice(0, -1);
  }
  const halves = head.split("::");
  if (halves.length > 2) return undefined;
  const groups = (part: string): number[] | undefined => {
    if (part === "") return [];
    const values = part
      .split(":")
      .map((group) =>
        /^[0-9a-fA-F]{1,4}$/u.test(group) ? Number.parseInt(group, 16) : NaN,
      );
    return values.some(Number.isNaN) ? undefined : values;
  };
  const left = groups(halves[0] ?? "");
  const right = halves.length === 2 ? groups(halves[1] ?? "") : [];
  if (left === undefined || right === undefined) return undefined;
  const width = left.length + right.length + tail.length;
  if (halves.length === 1 ? width !== 8 : width > 7) return undefined;
  return [...left, ...Array<number>(8 - width).fill(0), ...right, ...tail];
};

const formatIpv6 = (groups: readonly number[]): string => {
  let best = { start: -1, length: 0 };
  for (let start = 0; start < 8;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - start > best.length && end - start > 1)
      best = { start, length: end - start };
    start = end;
  }
  const hex = groups.map((group) => group.toString(16));
  if (best.start === -1) return hex.join(":");
  const left = hex.slice(0, best.start).join(":");
  const right = hex.slice(best.start + best.length).join(":");
  return `${left}::${right}`;
};

const embeddedIpv4 = (groups: readonly number[]): number =>
  ((groups[6] ?? 0) * 65_536 + (groups[7] ?? 0)) >>> 0;

const nonPublic6 = (
  address: string,
  addressClass: NonPublicAddressClass,
  detail?: string,
): AddressVerdict => ({
  address,
  family: 6,
  nonPublic: addressClass,
  description: describe(address, addressClass, detail),
});

const prefixIs = (
  groups: readonly number[],
  prefix: readonly number[],
): boolean => prefix.every((value, index) => groups[index] === value);

/** Embedded IPv4 forms are classed as IPv6 so a refusal names both layers. */
const classifyEmbeddedIpv6 = (
  groups: readonly number[],
  address: string,
): AddressVerdict | undefined => {
  if (prefixIs(groups, [0, 0, 0, 0, 0, 0xffff])) {
    const inner = classifyIpv4(embeddedIpv4(groups));
    return nonPublic6(
      address,
      "ipv4-mapped",
      `embeds ${inner.nonPublic === undefined ? "public" : inner.nonPublic} ${inner.address}`,
    );
  }
  if (prefixIs(groups, [0, 0, 0, 0, 0, 0])) {
    if (groups[6] === 0 && groups[7] === 0)
      return nonPublic6(address, "unspecified");
    if (groups[6] === 0 && groups[7] === 1)
      return nonPublic6(address, "loopback");
    return nonPublic6(address, "ipv4-compatible");
  }
  if (prefixIs(groups, [0x64, 0xff9b, 0, 0, 0, 0])) {
    const inner = classifyIpv4(embeddedIpv4(groups));
    return inner.nonPublic === undefined
      ? undefined
      : nonPublic6(
          address,
          "address-translation",
          `NAT64 of ${inner.nonPublic} ${inner.address}`,
        );
  }
  return undefined;
};

const classifyIpv6 = (groups: readonly number[]): AddressVerdict => {
  const address = formatIpv6(groups);
  const embedded = classifyEmbeddedIpv6(groups, address);
  if (embedded !== undefined) return embedded;
  const [first = 0, second = 0] = groups;
  if (prefixIs(groups, [0x64, 0xff9b])) {
    if (prefixIs(groups, [0x64, 0xff9b, 0, 0, 0, 0]))
      return {
        address,
        family: 6,
        nonPublic: undefined,
        description: `${address} is a public address`,
      };
    return nonPublic6(address, "address-translation");
  }
  if (prefixIs(groups, [0x100, 0, 0, 0]))
    return nonPublic6(address, "reserved", "discard-only");
  if (first === 0x2001 && second === 0x0db8)
    return nonPublic6(address, "documentation");
  if (first === 0x2001 && second < 0x200)
    return second === 0
      ? nonPublic6(address, "tunnel", "Teredo")
      : nonPublic6(address, "protocol-assignment");
  if (first === 0x2002) return nonPublic6(address, "tunnel", "6to4");
  if (first === 0x3fff && second < 0x1000)
    return nonPublic6(address, "documentation");
  if ((first & 0xfe00) === 0xfc00) return nonPublic6(address, "unique-local");
  if ((first & 0xffc0) === 0xfe80) return nonPublic6(address, "link-local");
  if ((first & 0xffc0) === 0xfec0) return nonPublic6(address, "site-local");
  if ((first & 0xff00) === 0xff00) return nonPublic6(address, "multicast");
  if ((first & 0xe000) !== 0x2000) return nonPublic6(address, "reserved");
  return {
    address,
    family: 6,
    nonPublic: undefined,
    description: `${address} is a public address`,
  };
};

/** A host as a resolver or socket takes it: a URL's bracketed IPv6 hostname loses its brackets. */
const bareHost = (host: string): string =>
  host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

/** Classify one literal IPv4 or IPv6 address; undefined when the text is not an address. */
export const classifyAddress = (text: string): AddressVerdict | undefined => {
  const unbracketed = bareHost(text);
  if (unbracketed.includes(":")) {
    const groups = parseIpv6(unbracketed);
    return groups === undefined ? undefined : classifyIpv6(groups);
  }
  const value = parseIpv4(unbracketed);
  return value === undefined ? undefined : classifyIpv4(value);
};

/** `localhost` and `*.localhost` always mean this host, and browsers answer them without DNS. */
const isLocalhostName = (hostname: string): boolean => {
  const name = hostname.toLowerCase().replace(/\.$/u, "");
  return name === "localhost" || name.endsWith(".localhost");
};

/** The comparable host spelling for an origin, a URL hostname or a SOCKS destination. */
export const canonicalHost = (host: string): string => {
  const verdict = classifyAddress(host);
  if (verdict !== undefined)
    return verdict.family === 6 ? `[${verdict.address}]` : verdict.address;
  return host.toLowerCase().replace(/\.$/u, "");
};

const destinationKey = (host: string, port: number): string =>
  `${canonicalHost(host)}:${String(port)}`;

const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  "http:": 80,
  "https:": 443,
  "ws:": 80,
  "wss:": 443,
};

/** The destination port a URL connects to. */
export const urlPort = (url: URL): number =>
  url.port === "" ? (DEFAULT_PORTS[url.protocol] ?? 0) : Number(url.port);

/**
 * Exact `host:port` keys a caller allowed even though they are not public,
 * such as a local dev server. Every scheme on that host and port is allowed,
 * so a dev server's WebSocket reaches it too.
 */
export const allowedPrivateDestinations = (
  origins: readonly string[],
): ReadonlySet<string> =>
  new Set(
    origins.map((origin) => {
      const url = new URL(origin);
      return destinationKey(url.hostname, urlPort(url));
    }),
  );

const refusal = (
  host: string,
  port: number,
  addressClass: DestinationRefusal["addressClass"],
  reason: string,
): DestinationRefusal => ({ host, port, addressClass, reason });

const familyOf = (family: number): 4 | 6 => (family === 6 ? 6 : 4);

/** Resolve a name once and keep it only when every answer is public. */
const vetName = async (
  host: string,
  port: number,
  policy: DestinationPolicy,
  allowed: boolean,
): Promise<Result<VettedDestination, DestinationRefusal>> => {
  let answers: readonly { readonly address: string; readonly family: number }[];
  try {
    answers = await policy.resolve(host);
  } catch (cause: unknown) {
    const code =
      cause instanceof Error && "code" in cause ? String(cause.code) : "failed";
    return err(
      refusal(
        host,
        port,
        "unresolved",
        `${host} could not be resolved (${code})`,
      ),
    );
  }
  if (answers.length === 0)
    return err(
      refusal(host, port, "unresolved", `${host} resolved to no address`),
    );
  const addresses: ResolvedAddress[] = [];
  for (const answer of answers) {
    const verdict = classifyAddress(answer.address);
    if (verdict === undefined)
      return err(
        refusal(
          host,
          port,
          "unresolved",
          `${host} resolved to a value that is not an address`,
        ),
      );
    if (verdict.nonPublic !== undefined && !allowed)
      return err(
        refusal(
          host,
          port,
          verdict.nonPublic,
          `${host} resolves to ${verdict.description}`,
        ),
      );
    addresses.push({
      address: verdict.address,
      family: familyOf(answer.family),
    });
  }
  return ok({
    host,
    port,
    addresses,
    allowance: allowed ? "allowed-private-origin" : "public",
  });
};

/**
 * The refusal a destination earns without any lookup: a non-public literal, a
 * `localhost` name or no host at all, unless the caller allowed that exact
 * host and port. Undefined means the literal is public, the destination is
 * allowed, or the host is a name whose addresses are still unknown.
 */
export const refuseWithoutLookup = (
  hostname: string,
  port: number,
  allowedPrivate: ReadonlySet<string>,
): DestinationRefusal | undefined => {
  const host = bareHost(hostname);
  if (allowedPrivate.has(destinationKey(host, port))) return undefined;
  const verdict = classifyAddress(host);
  if (verdict !== undefined)
    return verdict.nonPublic === undefined
      ? undefined
      : refusal(host, port, verdict.nonPublic, verdict.description);
  if (host === "")
    return refusal(host, port, "unresolved", "the destination names no host");
  return isLocalhostName(host)
    ? refusal(
        host,
        port,
        "localhost-name",
        `${host} is a localhost name, which always means this host`,
      )
    : undefined;
};

/**
 * Decide whether REA may connect to `host:port`. A literal is classified
 * directly; a `localhost` name is loopback; any other name is resolved exactly
 * once and refused unless every answer is public. Connect only to the returned
 * addresses. An allowed private destination skips classification but is still
 * pinned to the addresses resolved here.
 */
export const vetDestination = async (
  hostname: string,
  port: number,
  policy: DestinationPolicy,
): Promise<Result<VettedDestination, DestinationRefusal>> => {
  const host = bareHost(hostname);
  const refused = refuseWithoutLookup(host, port, policy.allowedPrivate);
  if (refused !== undefined) return err(refused);
  const allowed = policy.allowedPrivate.has(destinationKey(host, port));
  const verdict = classifyAddress(host);
  if (verdict !== undefined)
    return ok({
      host,
      port,
      addresses: [{ address: verdict.address, family: verdict.family }],
      allowance:
        verdict.nonPublic === undefined ? "public" : "allowed-private-origin",
    });
  return vetName(host, port, policy, allowed);
};

/** No address could be vetted (a failed or empty lookup): a network failure, not a policy refusal. */
export const isUnresolved = (value: DestinationRefusal): boolean =>
  value.addressClass === "unresolved";

/** One line for evidence and errors: the refused destination and its address class. */
export const refusalSentence = (value: DestinationRefusal): string =>
  `Refused ${canonicalHost(value.host)}:${String(value.port)}: ${value.reason}. Only public internet addresses are reached unless the exact origin is allowed with allow_private_origins.`;
