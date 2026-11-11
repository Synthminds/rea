import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { expect, it } from "vitest";

import {
  cleanupOwnedProcessGroup,
  verifyNoTokenOwnedProcesses,
} from "../../../src/process/ProcessOwnership.js";
import { createSystemProcessOwnershipHost } from "../../../src/process/ProcessOwnershipObservation.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import {
  spawnProviderProcessFixture,
  stopProviderProcessFixture,
  waitForProviderProcessReady,
} from "../../fixtures/providerProcess.js";

it.skipIf(process.platform !== "linux")(
  "accepts native absence after a baseline process exits between table and identity reads",
  async () => {
    const child = spawnProviderProcessFixture("graceful");
    const native = createSystemProcessOwnershipHost("linux", process.env);
    try {
      await waitForProviderProcessReady(child);
      const baseline = await native.captureBaseline?.();
      expect(baseline).toContainEqual({
        pid: child.pid,
        identity: expect.stringMatching(/^linux-starttime:\d+$/u),
      });
      const rows = (await native.listProcesses()).filter(
        ({ pid }) => pid === child.pid,
      );
      expect(rows).toHaveLength(1);

      await expect(
        verifyNoTokenOwnedProcesses(
          randomUUID(),
          {
            ...native,
            listProcesses: async () => {
              // Keep one real candidate row, then force the enumeration race
              // before the unmodified native identity/token observer runs.
              await stopProviderProcessFixture(child);
              return rows;
            },
          },
          baseline,
        ),
      ).resolves.toEqual({ cleaned: true, signaled: false });
    } finally {
      await stopProviderProcessFixture(child);
      await native.close?.();
    }
  },
);

/** PF_KTHREAD in the task flags of one Linux `/proc/<pid>/stat` record. */
const isKernelThread = async (pid: number): Promise<boolean> => {
  try {
    const stat = await readFile(`/proc/${String(pid)}/stat`, "utf8");
    const flags = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[6]);
    return (flags & 0x00200000) !== 0;
  } catch {
    return false;
  }
};

it.skipIf(process.platform !== "linux")(
  "completes a token sweep when kernel threads appear after the baseline",
  async ({ skip }) => {
    const native = createSystemProcessOwnershipHost("linux", process.env);
    try {
      const kernelThreads: number[] = [];
      for (const { pid } of await native.listProcesses())
        if (kernelThreads.length < 3 && (await isKernelThread(pid)))
          kernelThreads.push(pid);
      // A private PID namespace hides kernel threads from procps.
      if (kernelThreads.length === 0) skip();
      const launched = await spawnOwnedProviderProcess({
        command: process.execPath,
        arguments: ["-e", ""],
        runId: randomUUID(),
        sweepTokenOwnedProcesses: true,
      });
      await new Promise((resolve) => launched.process.once("close", resolve));
      if (launched.ownership.sweepTokenOwnedProcesses !== true)
        throw new Error("Expected a token-swept launch.");
      // Kernel workers are created on demand. Omitting live ones from the
      // pre-launch baseline makes the real sweep examine them as new rows.
      await expect(
        cleanupOwnedProcessGroup(
          {
            ...launched.ownership,
            captureBaseline: (launched.ownership.captureBaseline ?? []).filter(
              ({ pid }) => !kernelThreads.includes(pid),
            ),
          },
          native,
        ),
      ).resolves.toEqual({ cleaned: true, signaled: false });
    } finally {
      await native.close?.();
    }
  },
);
