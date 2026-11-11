import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { PassThrough } from "node:stream";
import { expect, it, vi } from "vitest";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import {
  ArtifactResourceScope,
  ArtifactResourceRetryFailure,
} from "../artifacts/ArtifactResourceScope.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { OwnedCommandFailure } from "./OwnedCommand.js";
import { ProviderProcessSupervisor } from "./ProviderProcess.js";
import { OwnedCommandRuntime } from "./OwnedCommandRuntime.js";

/** The cleanup failure a provider reports for a command it could not stop. */
const commandFailure = (cause: OwnedCommandFailure) =>
  new ProviderCleanupError(
    "owned-command",
    cause.resources,
    { reason: cause.cleanupFailure },
    { operation: "owned_command", cause },
  );

it("retries exact command owners before runtime removal and preserves mixed outcomes", async () => {
  const resources = new ArtifactResourceScope();
  const close = vi.fn(async () => undefined);
  const runtime = new OwnedCommandRuntime(
    { path: "owned-runtime", close },
    "Tool",
    resources,
  );
  const controls = [true, false].map((allowed, index) => {
    const process = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null,
      signalCode: null,
      kill: () => false,
    });
    const owner = new ProviderProcessSupervisor({
      process,
      ownsProcessLifetime: false,
    });
    const state = { allowed };
    const stop = vi
      .spyOn(owner, "stop")
      .mockImplementation(async () =>
        state.allowed
          ? { status: "already-exited" }
          : { status: "incomplete", reason: "authored cleanup denial" },
      );
    const cause = new OwnedCommandFailure(
      "process",
      "authored command failure",
      null,
      "authored cleanup denial",
      undefined,
      [`command-${String(index)}`],
      owner,
    );
    const error = commandFailure(cause);
    runtime.retainCommandFailure(cause, error);
    return { owner, state, stop, error };
  });
  const rootError = new ProviderCleanupError(
    "owned-command",
    [runtime.path],
    {},
  );
  new AnalysisCleanupLeaseGroup(rootError, [runtime.lease]);
  try {
    expect(
      await resources.release({
        kind: "lease",
        resource: runtime.path,
        lease: runtime.lease,
      }),
    ).toMatchObject({ kind: "failed" });
    expect(close).not.toHaveBeenCalled();
    let aggregate: ProviderCleanupError | undefined;
    try {
      await resources.close();
    } catch (cause) {
      expect(cause).toBeInstanceOf(ArtifactResourceRetryFailure);
      if (
        !(cause instanceof ArtifactResourceRetryFailure) ||
        cause.cleanupLeases === undefined
      )
        throw cause;
      aggregate = new ProviderCleanupError("owned-command", [], {});
      new AnalysisCleanupLeaseGroup(aggregate, cause.cleanupLeases);
    }
    expect(controls[0]?.error.cleanupIncomplete).toBe(false);
    expect(controls[1]?.error.cleanupIncomplete).toBe(true);
    expect(aggregate?.cleanupResources).toEqual(["command-1", "owned-runtime"]);
    expect(rootError.cleanupIncomplete).toBe(true);
    expect(close).not.toHaveBeenCalled();
    controls[1]!.state.allowed = true;
    await resources.close();
    expect(controls.map((control) => control.error.cleanupIncomplete)).toEqual([
      false,
      false,
    ]);
    expect(aggregate?.cleanupIncomplete).toBe(false);
    expect(rootError.cleanupIncomplete).toBe(false);
    expect(close).toHaveBeenCalledOnce();
    expect(controls.map((control) => control.stop.mock.calls.length)).toEqual([
      1, 2,
    ]);
  } finally {
    for (const control of controls) control.owner.dispose();
  }
});

it("keeps runtime removal unconfirmed when a failed command supplies no ownership capability", async () => {
  const close = vi.fn(async () => undefined);
  const runtime = new OwnedCommandRuntime(
    { path: "owned-runtime", close },
    "Tool",
    new ArtifactResourceScope(),
  );
  const cause = new OwnedCommandFailure(
    "process",
    "unconfirmed command",
    null,
    "no cleanup owner",
  );
  runtime.retainCommandFailure(cause, commandFailure(cause));
  await expect(runtime.lease.release()).rejects.toThrow(
    "Tool commands must stop",
  );
  expect(runtime.lease.released).toBe(false);
  expect(close).not.toHaveBeenCalled();
});

it("keeps the runtime while a retained descriptor inside it remains owned", async () => {
  const resources = new ArtifactResourceScope();
  const close = vi.fn(async () => undefined);
  const root = join(tmpdir(), "owned-runtime");
  const runtime = new OwnedCommandRuntime(
    { path: root, close },
    "Tool",
    resources,
  );
  const descriptor = (path: string) => {
    const state = { open: true };
    resources.retain({
      kind: "lease",
      resource: path,
      lease: new AnalysisCleanupLease(async () => {
        if (state.open) throw new Error("authored close denial");
      }, [path]),
    });
    return state;
  };
  // A sibling sharing the root's name prefix is not inside the runtime.
  descriptor(`${root}-sibling${sep}file`);
  const inside = descriptor(join(root, "target", "file"));
  const release = () =>
    resources.release({ kind: "lease", resource: root, lease: runtime.lease });
  await expect(release()).resolves.toMatchObject({
    kind: "failed",
    cause: { cleanup: { resources: [root] } },
  });
  expect(close).not.toHaveBeenCalled();
  inside.open = false;
  await expect(resources.retryCleanup()).rejects.toThrow(`${root}-sibling`);
  expect(close).toHaveBeenCalledOnce();
});
