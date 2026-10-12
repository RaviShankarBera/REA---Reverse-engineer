import { createHash } from "node:crypto";
import { open, realpath } from "node:fs/promises";

import { z } from "zod";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisProvider,
  type CapabilityDescriptor,
  type ExecutionOptions,
  type ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  windowsWindowPngSchema,
  windowsWindowHandleSchema,
  windowsWindowScreenshotInputSchema,
  windowsWindowScreenshotResultSchema,
  type WindowsWindowScreenshotResult,
} from "../domain/native/windowsWindowScreenshot.js";
import { err, ok, type Result } from "../domain/result.js";
import { requireWindowsNativeAuthority } from "./WindowsNativeLoader.js";
import {
  NATIVE_WINDOWS_UI_PROVIDER_IDENTITY as IDENTITY,
  nativeWindowsUiCapabilities,
} from "./NativeWindowsUiProviderMetadata.js";

const OPERATION = "capture_windows_window_screenshot" as const;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;

const rawCaptureSchema = z.strictObject({
  pid: z.number().int().positive(),
  window_handle: windowsWindowHandleSchema,
  process_image_path: z.string().min(1),
  process_start_time_unix_ms: z.number().int().nonnegative(),
  title: z.string(),
  source_width: z
    .number()
    .int()
    .positive()
    .max(4 * 1024 * 1024),
  source_height: z
    .number()
    .int()
    .positive()
    .max(4 * 1024 * 1024),
  width: z.number().int().positive().max(4096),
  height: z.number().int().positive().max(4096),
  png: z.custom<Buffer>(Buffer.isBuffer, "Expected a native PNG buffer"),
});

interface ExecutableIdentity {
  readonly canonicalPath: string;
  readonly sha256: string;
}

/** Narrow test seam: no test needs a Windows desktop or a packaged addon. */
export interface WindowsWindowCaptureHost {
  capture(pid: number, windowHandle: string, maximumDimension: number): unknown;
  identifyExecutable(
    path: string,
    signal?: AbortSignal,
  ): Promise<ExecutableIdentity>;
}

const systemCaptureHost = (): WindowsWindowCaptureHost => ({
  capture: (pid, windowHandle, maximumDimension) =>
    requireWindowsNativeAuthority().call("capture_window_png", [
      pid,
      windowHandle,
      maximumDimension,
    ]),
  identifyExecutable: hashExecutable,
});

/** Optional auxiliary provider for one passive, target-bound Windows PNG observation. */
export class NativeWindowsUiProvider implements AnalysisProvider {
  readonly #capabilities: readonly CapabilityDescriptor[];

  constructor(
    private readonly captureHost: WindowsWindowCaptureHost = systemCaptureHost(),
    platform: NodeJS.Platform = process.platform,
  ) {
    this.#capabilities = nativeWindowsUiCapabilities(platform);
  }

  identity(): ProviderIdentity {
    return IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return this.#capabilities;
  }

  createClient(target: BinaryTarget): AnalysisClient {
    return {
      execute: async (operation, parameters, options) => {
        if (operation === "health")
          return ok(createAnalysisExecution(null, IDENTITY));
        if (operation !== OPERATION)
          return err(
            new AnalysisCapabilityUnavailableError(
              IDENTITY.id,
              operation,
              "Operation is not implemented by the Windows selected-window adapter.",
            ),
          );
        const result = await captureWindowsWindowScreenshot(
          target,
          parameters,
          this.captureHost,
          options,
        );
        return result.ok
          ? ok(
              createAnalysisExecution(result.value, IDENTITY, {
                limitations: [
                  "One target-bound client-area frame was requested through WM_PRINT; no desktop, region, title-search, or input fallback exists.",
                  "GPU-composited, minimized, protected, elevated, or custom-drawn windows can refuse or incompletely render WM_PRINT; a successful PNG does not prove what was visible on a physical display.",
                  "WM_PRINT can execute the selected process's paint handler, which can change UI state or cause target filesystem and network effects. The title and PNG can contain private application data and REA retains them only in returned Evidence for this selected window.",
                  "The selected on-disk executable matched the active target before and after capture. That comparison does not prove every byte originally mapped into the process.",
                ],
              }),
            )
          : result;
      },
      close: async () => ok(null),
    };
  }
}

/** Validate target identity around one short native capture without broad fallback. */
export const captureWindowsWindowScreenshot = async (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
  host: WindowsWindowCaptureHost = systemCaptureHost(),
  options: ExecutionOptions = {},
): Promise<Result<WindowsWindowScreenshotResult, AnalysisError>> => {
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));
  const input = windowsWindowScreenshotInputSchema.safeParse(parameters);
  if (!input.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, input.error.issues, parameters, {
        cause: input.error,
      }),
    );
  if (
    target.kind !== "executable" ||
    target.format !== "pe" ||
    target.executableRole !== "application"
  )
    return err(
      new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        "Selected-window capture requires an active PE application target.",
      ),
    );
  let before: ExecutableIdentity;
  try {
    before = await host.identifyExecutable(target.path, options.signal);
  } catch (cause) {
    return err(identityError(target.path, cause));
  }
  if (before.sha256 !== target.sha256)
    return err(
      new AnalysisArtifactChangedError(
        OPERATION,
        target.path,
        "The active target bytes no longer match its opened SHA-256 identity.",
      ),
    );
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));

  let raw: z.infer<typeof rawCaptureSchema>;
  try {
    raw = rawCaptureSchema.parse(
      host.capture(
        input.data.pid,
        input.data.window_handle,
        input.data.max_dimension,
      ),
    );
  } catch (cause) {
    return err(
      new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        nativeFailureReason(cause),
        { cause },
      ),
    );
  }
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));
  if (
    raw.pid !== input.data.pid ||
    raw.window_handle !== input.data.window_handle
  )
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture returned a different process or window handle.",
      ),
    );
  if (
    raw.width > input.data.max_dimension ||
    raw.height > input.data.max_dimension ||
    raw.width > raw.source_width ||
    raw.height > raw.source_height ||
    raw.source_width * raw.source_height > 4 * 1024 * 1024
  )
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture violated the declared pixel bounds.",
      ),
    );

  let afterTarget: ExecutableIdentity;
  let processImage: ExecutableIdentity;
  try {
    [afterTarget, processImage] = await Promise.all([
      host.identifyExecutable(target.path, options.signal),
      host.identifyExecutable(raw.process_image_path, options.signal),
    ]);
  } catch (cause) {
    return err(identityError(target.path, cause));
  }
  if (
    afterTarget.sha256 !== target.sha256 ||
    afterTarget.canonicalPath !== before.canonicalPath
  )
    return err(
      new AnalysisArtifactChangedError(
        OPERATION,
        target.path,
        "The active target path or bytes changed during capture.",
      ),
    );
  if (
    processImage.sha256 !== target.sha256 ||
    processImage.canonicalPath !== before.canonicalPath
  )
    return err(
      new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        "Selected PID does not map to the active PE target bytes.",
      ),
    );

  try {
    const screenshot = windowsWindowPngSchema.parse({
      media_type: "image/png",
      data_base64: raw.png.toString("base64"),
      sha256: createHash("sha256").update(raw.png).digest("hex"),
      bytes: raw.png.byteLength,
      width: raw.width,
      height: raw.height,
      source_width: raw.source_width,
      source_height: raw.source_height,
    });
    return ok(
      windowsWindowScreenshotResultSchema.parse({
        target_sha256: target.sha256,
        window: {
          pid: raw.pid,
          window_handle: raw.window_handle,
          executable: target.path,
          process_image_path: raw.process_image_path,
          process_start_time_unix_ms: raw.process_start_time_unix_ms,
          title: raw.title,
        },
        screenshot,
        gaps: [
          "Accessibility-tree capture and UI actions are unavailable in this screenshot-only Windows capability.",
        ],
      }),
    );
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture returned an invalid PNG result.",
        { cause },
      ),
    );
  }
};

const hashExecutable = async (
  path: string,
  signal?: AbortSignal,
): Promise<ExecutableIdentity> => {
  const canonicalPath = canonicalWindowsPath(await realpath(path));
  const handle = await open(canonicalPath, "r");
  try {
    const metadata = await handle.stat();
    if (metadata.size > MAX_EXECUTABLE_BYTES)
      throw new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        "Selected executable exceeds the 256 MiB target-identity budget.",
        { maximum_bytes: MAX_EXECUTABLE_BYTES },
      );
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < metadata.size) {
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      const { bytesRead } = await handle.read(
        buffer,
        0,
        buffer.byteLength,
        position,
      );
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    if (position !== metadata.size)
      throw new Error(
        "Selected executable changed while its identity was read",
      );
    return { canonicalPath, sha256: digest.digest("hex") };
  } finally {
    await handle.close();
  }
};

const canonicalWindowsPath = (path: string): string =>
  path
    .replaceAll("/", "\\")
    .replace(/^\\\\\?\\/u, "")
    .toLowerCase();

const identityError = (path: string, cause: unknown): AnalysisError =>
  cause instanceof AnalysisError
    ? cause
    : new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        `Cannot establish selected executable identity: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );

const nativeFailureReason = (cause: unknown): string =>
  cause instanceof Error && cause.message.length > 0
    ? cause.message
    : "Selected window capture is unavailable on this host.";
