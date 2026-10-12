import { ok as resultOk } from "../../../src/domain/result.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it, onTestFinished } from "vitest";

import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/functionComparisonExample.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { jsonObjectSchema } from "../../../src/domain/jsonValue.js";

describe("function call coverage MCP integration", () => {
  it.each([
    { label: "missing coverage", coverage: undefined, unresolvedCalls: [] },
    {
      label: "unknown coverage",
      coverage: {
        status: "unknown" as const,
        reason: "Call graph unavailable.",
      },
      unresolvedCalls: [],
    },
    {
      label: "partial coverage",
      coverage: {
        status: "partial" as const,
        limitations: ["Additional edges omitted."],
      },
      unresolvedCalls: [],
    },
    {
      label: "unresolved calls",
      coverage: { status: "complete" as const },
      unresolvedCalls: [
        { address: "0x1004", reason: "Computed target unresolved." },
      ],
    },
  ])(
    "retains $label through public comparison and calls verification",
    async ({ coverage, unresolvedCalls }) => {
      const session = createTestBinarySession(() => {
        throw new Error("Evidence comparison must not launch a provider");
      });
      const server = createServer({ kind: "session", session });
      const client = new Client({
        name: "function-call-coverage",
        version: "1",
      });
      onTestFinished(async () => {
        await Promise.allSettled([
          client.close(),
          server.close(),
          session.close(),
        ]);
      });
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const left = FUNCTION_COMPARISON_EXAMPLE.left;
      const right = createEvidence(
        {
          path: "/tmp/function-call-coverage",
          sha256: "2".repeat(64),
          format: "mach-o",
        },
        left.provider,
        {
          operation: left.operation,
          parameters: left.parameters,
          result: {
            ...jsonObjectSchema.parse(left.normalized_result),
            unresolved_calls: unresolvedCalls,
          },
          confidence: left.confidence,
          authority: left.authority,
          ...(coverage === undefined ? {} : { relationshipCoverage: coverage }),
        },
      );
      const compared = await client.callTool({
        name: "compare_functions",
        arguments: { left, right },
      });
      expect(compared.isError, JSON.stringify(compared)).not.toBe(true);
      const comparison = parseEvidence(compared.structuredContent);
      expect(comparison.normalized_result).toMatchObject({
        status: "unknown",
        changes: [
          expect.objectContaining({
            dimension: "calls",
            status: "unknown",
            limitations: [expect.any(String)],
          }),
        ],
      });
      expect(session.evidenceById(right.evidence_id)).toEqual(right);
      expect(
        session.listUnknowns({ domain: "function-comparison" }),
      ).toMatchObject([
        {
          status: "open",
          supporting_evidence_ids: expect.arrayContaining([
            left.evidence_id,
            right.evidence_id,
          ]),
        },
      ]);
      const verified = await client.callTool({
        name: "verify_reconstruction",
        arguments: {
          specification: {
            name: "Function calls",
            claims: [
              {
                kind: "structural-function",
                claim_id: "calls",
                title: "Calls agree",
                comparison_evidence_id: comparison.evidence_id,
                dimension: "calls",
              },
            ],
          },
        },
      });
      expect(verified.isError, JSON.stringify(verified)).not.toBe(true);
      expect(
        parseEvidence(verified.structuredContent).normalized_result,
      ).toMatchObject({
        status: "unknown",
        summary: { passed: 0, unknown: 1 },
        claims: {
          items: [
            expect.objectContaining({
              status: "unknown",
              observed_status: "unknown",
              limitations: expect.arrayContaining([
                expect.stringContaining(`Source ${right.evidence_id}:`),
              ]),
            }),
          ],
        },
      });
    },
  );
});

describe("function comparison reconstruction MCP integration", () => {
  it.each([
    { comparisonStatus: "unchanged", verificationStatus: "pass" },
    { comparisonStatus: "changed", verificationStatus: "fail" },
  ] as const)(
    "verifies public $comparisonStatus function comparison as $verificationStatus",
    async ({ comparisonStatus, verificationStatus }) => {
      let providerLaunches = 0;
      const session = createTestBinarySession(() => {
        providerLaunches += 1;
        throw new Error("Function verification must not launch a provider");
      });
      const left = FUNCTION_COMPARISON_EXAMPLE.left;
      const right =
        comparisonStatus === "changed"
          ? FUNCTION_COMPARISON_EXAMPLE.right
          : createEvidence(
              {
                path: "/tmp/function-unchanged",
                sha256: "2".repeat(64),
                format: "mach-o",
              },
              left.provider,
              {
                operation: left.operation,
                parameters: left.parameters,
                result: left.normalized_result,
                confidence: left.confidence,
                authority: left.authority,
                ...(left.relationship_coverage === null
                  ? {}
                  : { relationshipCoverage: left.relationship_coverage }),
              },
            );
      const server = createServer({ kind: "session", session });
      const client = new Client({
        name: "function-verification-test",
        version: "1",
      });
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        const compared = await client.callTool({
          name: "compare_functions",
          arguments: { left, right },
        });
        expect(compared.isError).not.toBe(true);
        const comparison = parseEvidence(compared.structuredContent);
        expect(comparison.normalized_result).toMatchObject({
          status: comparisonStatus,
        });
        expect(comparison.parameters).toEqual({
          left_evidence_id: left.evidence_id,
          right_evidence_id: right.evidence_id,
        });
        expect(comparison.evidence_links).toEqual(
          expect.arrayContaining([left.evidence_id, right.evidence_id]),
        );

        const verified = await client.callTool({
          name: "verify_reconstruction",
          arguments: {
            specification: {
              name: "Function pseudocode comparison",
              claims: [
                {
                  kind: "structural-function",
                  claim_id: "pseudocode",
                  title: "Pseudocode agrees",
                  comparison_evidence_id: comparison.evidence_id,
                  dimension: "pseudocode",
                },
              ],
            },
          },
        });
        expect(
          verified.isError,
          JSON.stringify(verified.structuredContent),
        ).not.toBe(true);
        const verification = parseEvidence(verified.structuredContent);
        expect(verification.normalized_result).toMatchObject({
          status: verificationStatus,
          summary: {
            total: 1,
            passed: verificationStatus === "pass" ? 1 : 0,
            failed: verificationStatus === "fail" ? 1 : 0,
            unknown: 0,
          },
          claims: {
            items: [
              expect.objectContaining({
                status: verificationStatus,
                observed_status: comparisonStatus,
                comparison_evidence_id: comparison.evidence_id,
                left_evidence_ids: [left.evidence_id],
                right_evidence_ids: [right.evidence_id],
              }),
            ],
          },
        });
        expect(
          session
            .exportEvidenceBundle()
            .records.find(
              ({ evidence_id: id }) => id === comparison.evidence_id,
            ),
        ).toEqual(comparison);
      } finally {
        await Promise.allSettled([
          client.close(),
          server.close(),
          session.close(),
        ]);
        expect(providerLaunches).toBe(0);
      }
    },
  );
});

describe("function comparison MCP integration", () => {
  it("records linked comparison Evidence and its residual unknown", async () => {
    const session = createTestBinarySession(() => ({
      health: () => Promise.resolve(),
      execute: () => Promise.resolve(observed(null)),
      close: () => Promise.resolve(resultOk(null)),
    }));
    expect(session.recordEvidence(FUNCTION_COMPARISON_EXAMPLE.left).ok).toBe(
      true,
    );
    expect(session.recordEvidence(FUNCTION_COMPARISON_EXAMPLE.right).ok).toBe(
      true,
    );
    const server = createServer({ kind: "session", session });
    const client = new Client({
      name: "function-comparison-test",
      version: "1",
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "compare_functions",
        arguments: {
          left: FUNCTION_COMPARISON_EXAMPLE.left,
          right: FUNCTION_COMPARISON_EXAMPLE.right,
        },
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        normalized_result: { status: expect.any(String) },
        evidence_id: expect.stringMatching(/^ev_[a-f0-9]{64}$/u),
      });
      const unknowns = await client.callTool({
        name: "list_unknowns",
        arguments: { domain: "function-comparison" },
      });
      expect(unknowns.structuredContent).toMatchObject({
        result: {
          items: [
            expect.objectContaining({
              domain: "function-comparison",
              recommended_probes: [
                expect.objectContaining({
                  rationale:
                    "Capture complete dossiers for both functions under the same target context.",
                }),
              ],
            }),
          ],
        },
      });
    } finally {
      await Promise.allSettled([
        client.close(),
        server.close(),
        session.close(),
      ]);
    }
  });

  it("accepts inline Evidence without prior session registration", async () => {
    const session = createTestBinarySession(() => ({
      health: () => Promise.resolve(),
      execute: () => Promise.resolve(observed(null)),
      close: () => Promise.resolve(resultOk(null)),
    }));
    const server = createServer({ kind: "session", session });
    const client = new Client({ name: "function-link-test", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "compare_functions",
        arguments: {
          left: FUNCTION_COMPARISON_EXAMPLE.left,
          right: FUNCTION_COMPARISON_EXAMPLE.right,
        },
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        normalized_result: { status: expect.any(String) },
      });
    } finally {
      await Promise.allSettled([
        client.close(),
        server.close(),
        session.close(),
      ]);
    }
  });

  it("rejects inline Evidence with the wrong operation", async () => {
    const session = createTestBinarySession(() => ({
      health: () => Promise.resolve(),
      execute: () => Promise.resolve(observed(null)),
      close: () => Promise.resolve(resultOk(null)),
    }));
    const wrong = createEvidence(
      undefined,
      { id: "fixture", name: "Fixture", version: "1" },
      {
        operation: "inventory_artifact",
        parameters: {},
        result: {},
      },
    );
    session.recordEvidence(wrong);
    session.recordEvidence(FUNCTION_COMPARISON_EXAMPLE.right);
    const server = createServer({ kind: "session", session });
    const client = new Client({
      name: "function-authority-test",
      version: "1",
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "compare_functions",
        arguments: {
          left: wrong,
          right: FUNCTION_COMPARISON_EXAMPLE.right,
        },
      });
      expect(result.isError).toBe(true);
      expect(session.exportEvidenceBundle().records).toHaveLength(2);
    } finally {
      await Promise.allSettled([
        client.close(),
        server.close(),
        session.close(),
      ]);
    }
  });
});
