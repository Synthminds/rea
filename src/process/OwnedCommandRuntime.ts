import { isAbsolute, relative, sep } from "node:path";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { PrivateRuntimeRoot } from "./PrivateRuntimeRoot.js";
import type { ProviderProcessSupervisor } from "./ProviderProcess.js";
import { OwnedCommandFailure } from "./OwnedCommand.js";

/** Whether a cleanup label is an absolute path strictly inside `root`. */
const isWithin = (root: string, resource: string): boolean => {
  if (!isAbsolute(resource)) return false;
  const path = relative(root, resource);
  return (
    path !== "" &&
    path !== ".." &&
    !path.startsWith(`..${sep}`) &&
    !isAbsolute(path)
  );
};

/**
 * A private runtime cannot be removed until every retained command has stopped
 * and every descriptor `resources` retains inside it has closed. `label` names
 * the caller-supplied tool in cleanup diagnostics.
 */
export class OwnedCommandRuntime {
  readonly lease: AnalysisCleanupLease;
  readonly path: string;
  readonly #resources: ArtifactResourceScope;
  readonly #commands = new Map<
    ProviderProcessSupervisor,
    AnalysisCleanupLease
  >();
  #unknownCommand: string | undefined;

  constructor(
    root: Pick<PrivateRuntimeRoot, "path" | "close">,
    label: string,
    resources: ArtifactResourceScope,
  ) {
    this.path = root.path;
    this.#resources = resources;
    this.lease = new AnalysisCleanupLease(async () => {
      const pending = [...this.#commands.values()].filter(
        (lease) => !lease.released,
      );
      if (pending.length > 0 || this.#unknownCommand !== undefined)
        throw new ArtifactReaderFailure(
          "unavailable",
          `${label} commands must stop before runtime removal`,
          {
            cleanup: {
              reason:
                this.#unknownCommand ??
                `${label} command cleanup remains incomplete`,
              resources: [
                ...new Set([
                  root.path,
                  ...pending.flatMap((lease) => lease.cleanupResources ?? []),
                ]),
              ],
            },
          },
        );
      // Owners report their exact paths; a held child keeps its containing root.
      const held = resources.cleanupResources.filter((resource) =>
        isWithin(root.path, resource),
      );
      if (held.length > 0) {
        const reason = `${label} runtime is kept until its retained contents close: ${held.join(", ")}`;
        throw new ArtifactReaderFailure("unavailable", reason, {
          cleanup: { reason, resources: [root.path] },
        });
      }
      await root.close();
    }, [root.path]);
  }

  /** Adopt only the supervisor supplied by the command boundary, never a PID or label. */
  retainCommandFailure(cause: unknown, failure: AnalysisError): void {
    if (
      !(cause instanceof OwnedCommandFailure) ||
      cause.cleanupFailure === null
    )
      return;
    const owner = cause.cleanupOwner;
    if (owner === undefined) {
      this.#unknownCommand = cause.cleanupFailure;
      return;
    }
    let lease = this.#commands.get(owner);
    if (lease === undefined) {
      lease = new AnalysisCleanupLease(async () => {
        const stopped = await owner.stop();
        if (stopped.status === "incomplete")
          throw new ArtifactReaderFailure("unavailable", stopped.reason, {
            cleanup: { reason: stopped.reason, resources: cause.resources },
          });
      }, cause.resources);
      this.#commands.set(owner, lease);
      this.#resources.retain({
        kind: "lease",
        resource: cause.resources[0] ?? this.path,
        lease,
      });
    }
    new AnalysisCleanupLeaseGroup(failure, [lease]);
  }
}
