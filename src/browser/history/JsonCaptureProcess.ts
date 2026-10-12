import { readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { decodeQlogCapture } from "./QlogCapture.js";
import { decodeHarCapture } from "./HarCapture.js";
import { decodeCaptureText } from "./CaptureJson.js";

const requestSchema = z.strictObject({
  snapshot_path: z.string(),
  reply_path: z.string(),
  sensitive_values: z.array(z.string().min(1)),
});

/** Decode untrusted JSON captures in an owned heap rather than the long-lived MCP process. */
const main = async (): Promise<void> => {
  const request = requestSchema.parse(
    JSON.parse(await readFile(process.argv[2] ?? "", "utf8")),
  );
  const format = z.enum(["har", "qlog"]).parse(process.argv[3]);
  const decoder = format === "har" ? decodeHarCapture : decodeQlogCapture;
  let reply: unknown;
  try {
    const snapshot = await readStableArtifact(
      request.snapshot_path,
      WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
    );
    reply = {
      ok: true,
      value: decoder(
        decodeCaptureText(snapshot.bytes, format === "har" ? "HAR" : "qlog"),
        request.sensitive_values,
      ),
    };
  } catch (cause: unknown) {
    reply =
      cause instanceof CaptureFormatError
        ? {
            ok: false,
            reason: cause.reason,
            message: cause.message,
            pointer: cause.pointer,
          }
        : {
            ok: false,
            reason: "decoder",
            message: `${format} decoder failed unexpectedly (${cause instanceof Error ? cause.name : "unknown exception"}).`,
            pointer: "",
          };
  }
  let text = JSON.stringify(reply);
  if (Buffer.byteLength(text) > WEB_NETWORK_CAPTURE_LIMITS.outputBytes)
    text = JSON.stringify({
      ok: false,
      reason: "limit",
      message: `${format} reply exceeds the complete-evidence output budget.`,
      pointer: "",
    });
  await writeFile(request.reply_path, text, { flag: "wx", mode: 0o600 });
};
await main();
