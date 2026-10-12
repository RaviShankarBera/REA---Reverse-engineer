import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  acceptInputKeyAliases,
  inputKeyAliasesFor,
  renameInputKeyAliases,
} from "./inputKeyAliases.js";

const procedureInput = z.strictObject({
  procedure: z.string(),
  document: z.string().optional(),
});
const searchInput = z.strictObject({
  pattern: z.string(),
  mode: z.enum(["literal", "regex"]).default("literal"),
});

const validate = (schema: z.ZodType, value: unknown) =>
  Promise.resolve(schema["~standard"].validate(value));

describe("input key aliases", () => {
  it("applies only where the canonical key exists and the alias does not", () => {
    expect(inputKeyAliasesFor(procedureInput)).toEqual({
      address: "procedure",
    });
    expect(inputKeyAliasesFor(searchInput)).toEqual({ query: "pattern" });
    expect(
      inputKeyAliasesFor(
        z.strictObject({ procedure: z.string(), address: z.string() }),
      ),
    ).toEqual({});
    expect(inputKeyAliasesFor(z.strictObject({ address: z.string() }))).toEqual(
      {},
    );
  });

  it("renames an alias only when the canonical key is absent", () => {
    const aliases = { address: "procedure" };
    expect(renameInputKeyAliases({ address: "0x401000" }, aliases)).toEqual({
      procedure: "0x401000",
    });
    const both = { address: "0x401000", procedure: "main" };
    expect(renameInputKeyAliases(both, aliases)).toBe(both);
    expect(renameInputKeyAliases(["address"], aliases)).toEqual(["address"]);
  });

  it("validates the alias as the canonical key and keeps strict rejection", async () => {
    const accepting = acceptInputKeyAliases(procedureInput);
    await expect(validate(accepting, { address: "0x401000" })).resolves.toEqual(
      { value: { procedure: "0x401000" } },
    );
    const both = await validate(accepting, {
      address: "0x401000",
      procedure: "main",
    });
    expect(both.issues?.map((issue) => issue.message).join(" ")).toMatch(
      /Unrecognized key.*address/u,
    );
    const unknown = await validate(accepting, { procedure: "main", proc: 1 });
    expect(unknown.issues).toBeDefined();
  });

  it("keeps the advertised JSON Schema and the schema's own methods", () => {
    const accepting = acceptInputKeyAliases(searchInput);
    const project = (schema: z.ZodType) =>
      schema["~standard"].jsonSchema.input({ target: "draft-2020-12" });
    expect(project(accepting)).toEqual(project(searchInput));
    expect(JSON.stringify(project(accepting))).not.toContain('"query"');
    expect(accepting.safeParse({ pattern: "ACCESS" }).success).toBe(true);
    const unaliased = z.strictObject({ name: z.string() });
    expect(acceptInputKeyAliases(unaliased)).toBe(unaliased);
  });
});
