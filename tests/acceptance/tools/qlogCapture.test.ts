import { execFile } from "node:child_process";
import { writeFile, truncate } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import {
  webNetworkCaptureSchema,
  WEB_NETWORK_CAPTURE_LIMITS,
} from "../../../src/domain/webNetworkCapture.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const execute = promisify(execFile);
const cli = fileURLToPath(new URL("../../../scripts/rea.mjs", import.meta.url));
const event = {
  name: "transport:packet_sent",
  time: 1791819895000.25,
  data: {
    header: { packet_type: "1RTT", packet_number: 5 },
    frames: [
      { frame_type: "stream", stream_id: 0, offset: 10, length: 5, fin: true },
    ],
  },
};
const qlog = (events: unknown[]) =>
  JSON.stringify({
    qlog_format: "JSON",
    qlog_version: "0.3",
    traces: [
      {
        vantage_point: { name: "aioquic", type: "server" },
        common_fields: { ODCID: "trace-local" },
        events,
      },
    ],
  });

it("runs built CLI and real stdio SDK with exact evidence parity, selection, retained references and strict schemas", async () => {
  const root = await createTestTempDirectory("rea-qlog-public-");
  const path = join(root, "input.qlog");
  await writeFile(
    path,
    qlog([
      event,
      {
        name: "recovery:packet_lost",
        time: 1791819895001.125,
        data: { packet_number: 5, type: "1RTT" },
      },
    ]),
  );
  const { call, client } = await connectLocalToolsMcp();
  const input = { capture_path: path, format: "qlog", record_ordinals: [1, 0] };
  const response = await call("inspect_web_network_capture", input);
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  const mcp = parseEvidence(response.structuredContent);
  const result = await execute(process.execPath, [
    cli,
    "inspect-web-network-capture",
    path,
    "qlog",
    "--record",
    "1",
    "--record",
    "0",
    "--json",
  ]);
  const cliEvidence = parseEvidence(JSON.parse(result.stdout));
  expect(cliEvidence.evidence_id).toBe(mcp.evidence_id);
  expect(cliEvidence.normalized_result).toEqual(mcp.normalized_result);
  expect(mcp.analysis_profile?.parameters).toMatchObject({
    qlog_profile: "aioquic-1.5.0-json-0.3",
  });
  expect(mcp.authority).toBe("historical-reference");
  const decoded = webNetworkCaptureSchema.parse(mcp.normalized_result);
  expect(decoded.records.map((record) => record.ordinal)).toEqual([1, 0]);
  if (decoded.format !== "qlog") throw new Error("qlog format required");
  expect(decoded.qlog.traces[0]?.streams[0]).toMatchObject({
    unique_bytes: "5",
    covered_ranges: [{ start: "10", end: "15" }],
  });
  const retained = await call("inspect_analysis_view", {
    source: { kind: "retained-evidence", evidence_id: mcp.evidence_id },
    view: { kind: "api-surface" },
  });
  // An unsupported view over an existing retained parent proves lookup without pretending qlog is HAR.
  expect(parseMcpToolError(retained)).toMatchObject({
    error: { code: "unsupported_target" },
  });
  await client.ping();
  for (const record_ordinals of [[2], [0, 0]]) {
    expect(
      parseMcpToolError(
        await call("inspect_web_network_capture", {
          ...input,
          record_ordinals,
        }),
      ),
    ).toMatchObject({ error: { code: "invalid_request" } });
  }
  const hidden = await call("inspect_web_network_capture", {
    capture_path: path,
    format: "qlog",
    sensitive_values: ["trace-local", "/traces/0", "input.qlog"],
  });
  expect(JSON.stringify(hidden)).not.toContain("trace-local");
  expect(JSON.stringify(hidden)).not.toContain("/traces/0");
  expect(JSON.stringify(hidden)).not.toContain("input.qlog");
  const hiddenEvidence = parseEvidence(hidden.structuredContent);
  expect(
    webNetworkCaptureSchema.parse(hiddenEvidence.normalized_result).artifact
      .path,
  ).toBe("");
  const invalid = await call("inspect_web_network_capture", {
    ...input,
    mysecret: true,
    sensitive_values: ["mysecret"],
  });
  expect(parseMcpToolError(invalid)).toMatchObject({
    error: { code: "invalid_request" },
  });
  expect(JSON.stringify(invalid)).not.toContain("mysecret");
}, 60_000);

it("fails whole-capture validation before selection and survives malformed, unsupported and oversized qlog", async () => {
  const root = await createTestTempDirectory("rea-qlog-errors-");
  const path = join(root, "input.qlog");
  const { call, client } = await connectLocalToolsMcp();
  for (const [text, code] of [
    [qlog([event, { ...event, time: "invalid" }]), "invalid_request"],
    [qlog([event]).slice(0, -1), "invalid_request"],
    [
      qlog([event]).replace('"qlog_version":"0.3"', '"qlog_version":"0.4"'),
      "capability_unavailable",
    ],
    [
      qlog([
        {
          ...event,
          extension: JSON.parse("[".repeat(65) + "0" + "]".repeat(65)),
        },
      ]),
      "invalid_request",
    ],
  ] as const) {
    await writeFile(path, text);
    expect(
      parseMcpToolError(
        await call("inspect_web_network_capture", {
          capture_path: path,
          format: "qlog",
          record_ordinals: [0],
        }),
      ),
    ).toMatchObject({ error: { code } });
    const failed: unknown = await execute(process.execPath, [
      cli,
      "inspect-web-network-capture",
      path,
      "qlog",
      "--json",
    ]).catch((cause: unknown) => cause);
    expect(failed).toMatchObject({
      code: 1,
      stdout: expect.stringContaining(`"code":"${code}"`),
    });
  }
  await truncate(path, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  expect(
    parseMcpToolError(
      await call("inspect_web_network_capture", {
        capture_path: path,
        format: "qlog",
      }),
    ),
  ).toMatchObject({ error: { code: "invalid_request" } });
  await writeFile(path, qlog([event]));
  await client.ping();
  expect(
    (
      await call("inspect_web_network_capture", {
        capture_path: path,
        format: "qlog",
      })
    ).isError,
  ).not.toBe(true);
}, 60_000);

it.skipIf(process.versions.bun !== undefined)(
  "contains actual qlog decoder heap exhaustion and keeps MCP usable",
  async () => {
    const root = await createTestTempDirectory("rea-qlog-capacity-");
    const path = join(root, "dense.qlog");
    const dense = qlog(Array<unknown>(100_000).fill(event));
    expect(Buffer.byteLength(dense)).toBeLessThan(
      WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
    );
    await writeFile(path, dense);
    const { call, client } = await connectLocalToolsMcp();
    const response = await call("inspect_web_network_capture", {
      capture_path: path,
      format: "qlog",
      record_ordinals: [0],
    });
    expect(parseMcpToolError(response)).toMatchObject({
      error: {
        code: "resource_constraint",
        details: {
          resource: "memory",
          reported_limits: { old_generation_heap_mib: 192 },
        },
      },
    });
    const failed: unknown = await execute(
      process.execPath,
      [cli, "inspect-web-network-capture", path, "qlog", "--json"],
      { timeout: 40_000, maxBuffer: 1024 * 1024 },
    ).catch((cause: unknown) => cause);
    expect(failed).toMatchObject({
      code: 1,
      stdout: expect.stringContaining('"code":"resource_constraint"'),
    });
    await writeFile(path, qlog([event]));
    await client.ping();
    expect(
      (
        await call("inspect_web_network_capture", {
          capture_path: path,
          format: "qlog",
        })
      ).isError,
    ).not.toBe(true);
  },
  60_000,
);
