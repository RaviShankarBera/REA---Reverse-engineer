import { fileURLToPath } from "node:url";
import type { HistoricalCaptureFormatAdapter } from "./HistoricalCaptureFormatAdapter.js";
import {
  HAR_CAPTURE_PROVIDER_IDENTITY,
  QLOG_CAPTURE_PROVIDER_IDENTITY,
  JSON_CAPTURE_HEAP_LIMITS,
  JSON_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES,
} from "./CaptureRelease.js";

/** JSON capture parsers run in one bounded heap, without network or target execution. */
export class JsonCaptureAdapter implements HistoricalCaptureFormatAdapter {
  constructor(readonly format: "har" | "qlog") {}
  get identity() {
    return this.format === "har"
      ? HAR_CAPTURE_PROVIDER_IDENTITY
      : QLOG_CAPTURE_PROVIDER_IDENTITY;
  }
  async command(requestPath: string): Promise<{
    command: string;
    arguments: readonly string[];
    memoryLimitBytes?: number;
  }> {
    return {
      command: process.execPath,
      arguments: [
        `--max-old-space-size=${JSON_CAPTURE_HEAP_LIMITS.oldGenerationMiB}`,
        `--max-semi-space-size=${JSON_CAPTURE_HEAP_LIMITS.semiSpaceMiB}`,
        "--v8-pool-size=1",
        "--single-threaded",
        fileURLToPath(new URL("./JsonCaptureProcess.js", import.meta.url)),
        requestPath,
        this.format,
      ],
      ...(JSON_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES === null
        ? {}
        : { memoryLimitBytes: JSON_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES }),
    };
  }
}
