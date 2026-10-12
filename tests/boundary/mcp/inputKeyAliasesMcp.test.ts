import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";

import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { COMPACT_INPUT_SCHEMA_BUDGET_BYTES } from "../../../src/config/mcpInputSchemaProfile.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";

interface Received {
  readonly tool: string;
  readonly args: unknown;
}

// The handlers only record the arguments the SDK validated; output schemas are
// left out so an empty result is accepted.
const connectCatalog = async (compact: boolean) => {
  const server = new EvidenceMcpServer(
    { name: "input-key-aliases", version: "0" },
    { capabilities: {} },
    undefined,
    new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
    compact ? { budgetBytes: COMPACT_INPUT_SCHEMA_BUDGET_BYTES } : undefined,
  );
  const received: Received[] = [];
  for (const contract of TOOL_CONTRACTS) {
    const { outputSchema: _output, ...options } =
      toolRegistrationOptions(contract);
    server.registerTool(contract.name, options, async (args: unknown) => {
      received.push({ tool: contract.name, args });
      return { content: [] };
    });
  }
  const client = new Client({ name: "input-key-aliases", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    received,
    close: () => Promise.allSettled([client.close(), server.close()]),
  };
};

const errorText = (result: Awaited<ReturnType<Client["callTool"]>>): string =>
  JSON.stringify(result.content);

describe("MCP input key aliases", () => {
  for (const compact of [false, true])
    it(`accepts the aliases agents send ${compact ? "with" : "without"} the compact profile`, async () => {
      const { client, received, close } = await connectCatalog(compact);
      try {
        for (const [tool, args, expected] of [
          [
            "procedure_pseudo_code",
            { address: "0x401000" },
            { procedure: "0x401000" },
          ],
          [
            "read_function_instructions",
            { address: "0x401000" },
            { procedure: "0x401000" },
          ],
          ["search_strings", { query: "ACCESS" }, { pattern: "ACCESS" }],
        ] as const) {
          const result = await client.callTool({ name: tool, arguments: args });
          expect(result.isError, errorText(result)).toBeFalsy();
          expect(received.at(-1)).toMatchObject({ tool, args: expected });
          expect(received.at(-1)?.args).not.toHaveProperty(
            Object.keys(args)[0]!,
          );
        }
      } finally {
        await close();
      }
    });

  it("still rejects an alias sent beside its canonical key and keeps other inputs unchanged", async () => {
    const { client, received, close } = await connectCatalog(false);
    try {
      const both = await client.callTool({
        name: "procedure_pseudo_code",
        arguments: { address: "0x401000", procedure: "main" },
      });
      expect(both.isError).toBe(true);
      expect(errorText(both)).toMatch(/Unrecognized key.*address/u);
      const reverse = await client.callTool({
        name: "resolve_containing_procedure",
        arguments: { procedure: "0x401000" },
      });
      expect(reverse.isError).toBe(true);
      expect(received).toEqual([]);
    } finally {
      await close();
    }
  });

  it("advertises only the canonical keys", async () => {
    const { client, close } = await connectCatalog(false);
    try {
      const { tools } = await client.listTools();
      const properties = (name: string) =>
        Object.keys(
          (tools.find((tool) => tool.name === name)?.inputSchema.properties ??
            {}) as Record<string, unknown>,
        );
      expect(properties("procedure_pseudo_code")).toContain("procedure");
      expect(properties("procedure_pseudo_code")).not.toContain("address");
      expect(properties("search_strings")).toContain("pattern");
      expect(properties("search_strings")).not.toContain("query");
    } finally {
      await close();
    }
  });
});
