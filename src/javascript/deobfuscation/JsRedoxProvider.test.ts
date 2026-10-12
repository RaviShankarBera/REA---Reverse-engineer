import { access, readFile } from "node:fs/promises";
import { expect, it, onTestFinished, vi } from "vitest";

import {
  assertDeobfuscationCleanup,
  deobfuscationFixture,
} from "../../../tests/fixtures/javascript-deobfuscation/provider.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { JS_REDOX_LIMITS } from "./JsRedoxRelease.js";

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "publishes source, proof report and safe rewritten JavaScript through the owned-process boundary",
  async () => {
    const fixture = await deobfuscationFixture();
    onTestFinished(async () => fixture.provider.close?.());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
      max_iterations: 16,
    });
    if (!response.ok) throw response.error;
    expect(response.value).toMatchObject({
      operation: "deobfuscate_javascript_source",
      provider: { id: "js-redox", version: "0.1.0" },
      normalized_result: {
        status: "changed",
        runtime_execution: "not-performed",
        proof: {
          schema: "js-safe-deobfuscate/v1",
          transforms: { static_array_lookup: 2, constant_fold: 1 },
          runtime_semantics_preserved_by_design: true,
        },
      },
    });
    await expect(
      readFile(`${fixture.output}/deobfuscated/source.js`, "utf8"),
    ).resolves.toContain('console.log("hello world")');
    await expect(
      access(`${fixture.output}/manifest.json`),
    ).resolves.toBeUndefined();
    expect(fixture.engineSnapshots).toHaveLength(2);
    expect(new Set(fixture.engineSnapshots.map(({ path }) => path)).size).toBe(
      1,
    );
    expect(fixture.engineSnapshots[0]?.path).not.toBe(fixture.command);
    expect(fixture.engineSnapshots[0]?.bytes.toString("utf8")).toBe(
      "#!/bin/sh\nexit 0\n",
    );
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "rejects a proof report whose output digest does not match published bytes",
  async () => {
    const fixture = await deobfuscationFixture("bad-digest");
    onTestFinished(async () => fixture.provider.close?.());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (response.ok) throw new Error("expected proof mismatch");
    expect(response.error._tag).toBe("AnalysisOutputError");
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "releases a published tree before returning success when commit cleanup reports failure",
  async () => {
    const fixture = await deobfuscationFixture();
    onTestFinished(async () => fixture.provider.close?.());
    const originalCommit = SafeOutputTree.prototype.commit;
    const rollback = vi.spyOn(SafeOutputTree.prototype, "rollback");
    vi.spyOn(SafeOutputTree.prototype, "commit").mockImplementationOnce(
      async function (this: SafeOutputTree) {
        await originalCommit.call(this);
        throw new Error("fixture directory-handle close failure");
      },
    );
    onTestFinished(() => vi.restoreAllMocks());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (!response.ok) throw response.error;
    expect(rollback).toHaveBeenCalledTimes(1);
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "preserves cancellation during publication I/O",
  async () => {
    const fixture = await deobfuscationFixture();
    onTestFinished(async () => fixture.provider.close?.());
    const controller = new AbortController();
    const originalWrite = SafeOutputTree.prototype.write;
    vi.spyOn(SafeOutputTree.prototype, "write").mockImplementationOnce(
      async function (this: SafeOutputTree, ...args) {
        controller.abort();
        return originalWrite.apply(this, args);
      },
    );
    onTestFinished(() => vi.restoreAllMocks());
    const response = await fixture.service.deobfuscate(
      {
        path: fixture.path,
        output_directory: fixture.output,
      },
      { signal: controller.signal },
    );
    if (response.ok) throw new Error("expected cancellation");
    expect(response.error._tag).toBe("AnalysisCancelledError");
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "shares one wall deadline across the version and transformation launches",
  async () => {
    const fixture = await deobfuscationFixture("slow-both");
    onTestFinished(async () => fixture.provider.close?.());
    const limits = JS_REDOX_LIMITS as { timeoutMs: number };
    const originalTimeout = limits.timeoutMs;
    limits.timeoutMs = 1_000;
    onTestFinished(() => {
      limits.timeoutMs = originalTimeout;
    });
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (response.ok) throw new Error("expected shared deadline timeout");
    expect(response.error._tag).toBe("AnalysisTimeoutError");
    expect(fixture.launches).toHaveLength(2);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "rejects transformed JavaScript that is not valid UTF-8",
  async () => {
    const fixture = await deobfuscationFixture("invalid-output-utf8");
    onTestFinished(async () => fixture.provider.close?.());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (response.ok) throw new Error("expected malformed output rejection");
    expect(response.error._tag).toBe("AnalysisOutputError");
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "rejects a relative resource-limiter override before launch",
  async () => {
    const fixture = await deobfuscationFixture("normal", undefined, {
      REA_JAVASCRIPT_PRLIMIT_COMMAND: "prlimit",
    });
    onTestFinished(async () => fixture.provider.close?.());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (response.ok) throw new Error("expected relative limiter rejection");
    expect(response.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(fixture.launches).toHaveLength(0);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "observes cancellation immediately before output publication",
  async () => {
    const fixture = await deobfuscationFixture();
    onTestFinished(async () => fixture.provider.close?.());
    const controller = new AbortController();
    const originalClose = PrivateRuntimeRoot.prototype.close;
    vi.spyOn(PrivateRuntimeRoot.prototype, "close").mockImplementationOnce(
      async function (this: PrivateRuntimeRoot) {
        await originalClose.call(this);
        controller.abort();
      },
    );
    onTestFinished(() => vi.restoreAllMocks());
    const response = await fixture.service.deobfuscate(
      {
        path: fixture.path,
        output_directory: fixture.output,
      },
      { signal: controller.signal },
    );
    if (response.ok) throw new Error("expected pre-commit cancellation");
    expect(response.error._tag).toBe("AnalysisCancelledError");
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);

it.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "retains bounded process diagnostics for a nonzero engine exit",
  async () => {
    const fixture = await deobfuscationFixture("nonzero");
    onTestFinished(async () => fixture.provider.close?.());
    const response = await fixture.service.deobfuscate({
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (response.ok) throw new Error("expected engine failure");
    expect(response.error).toMatchObject({
      _tag: "ProviderAdapterError",
      diagnostics: {
        exit_code: 23,
        exit_signal: null,
        diagnostic_truncated: false,
        stdout: {
          text: "fixture stdout diagnostic\n",
          bytes: 26,
          retained_bytes: 26,
        },
        stderr: {
          text: "fixture stderr diagnostic\n",
          bytes: 26,
          retained_bytes: 26,
        },
      },
    });
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertDeobfuscationCleanup(fixture.launches);
  },
);
