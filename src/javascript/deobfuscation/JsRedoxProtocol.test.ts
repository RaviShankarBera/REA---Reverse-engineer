import { expect, it } from "vitest";

import { parseJsRedoxReport } from "./JsRedoxProtocol.js";

it("rejects proof reports containing malformed UTF-8", () => {
  const report = {
    schema: "js-safe-deobfuscate/v1",
    input: "/tmp/source.js",
    input_sha256: "a".repeat(64),
    output_sha256: "b".repeat(64),
    changed: true,
    iterations: 1,
    transforms: {},
    arithmetic_state_proofs: [],
    analysis_source_sha256: "b".repeat(64),
    static_alias_installer_calls: [],
    safe_static_only: true,
    presentation_formatted: false,
    runtime_semantics_preserved_by_design: true,
    note: "x",
  };
  const bytes = Buffer.from(JSON.stringify(report), "utf8");
  const marker = Buffer.from('"note":"x"', "utf8");
  const markerOffset = bytes.indexOf(marker);
  if (markerOffset < 0) throw new Error("fixture marker missing");
  bytes[markerOffset + marker.length - 2] = 0xff;
  expect(() => parseJsRedoxReport(bytes)).toThrowError(
    expect.objectContaining({ _tag: "AnalysisOutputError" }),
  );
});
