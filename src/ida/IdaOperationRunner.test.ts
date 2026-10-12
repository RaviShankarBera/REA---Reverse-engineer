import { expect, it } from "vitest";
import { RecordingIdaMcp } from "../../tests/fixtures/idaMcp.js";
import { functionDossierSchema } from "../domain/hopperValues.js";
import { IdaOperationRunner } from "./IdaOperationRunner.js";

it.each([false, true])(
  "keeps unavailable callers when the later callee read has more=%s",
  async (more) => {
    const producer = new RecordingIdaMcp(
      {
        path: "/fixture/target",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "elf",
        architecture: "x86_64",
        availableArchitectures: ["x86_64"],
      },
      "headless",
    );
    producer.overrideCall = (name) =>
      name === "callees"
        ? [
            {
              callees: [{ addr: "0x2000", name: "puts", type: "external" }],
              more,
            },
          ]
        : undefined;
    const runner = new IdaOperationRunner(producer, "modern");
    const dossier = functionDossierSchema.parse(
      await runner.run("analyze_function", { procedure: "main" }),
    );
    expect(dossier).toMatchObject({ callers: [], callees: [{ name: "puts" }] });
    expect(runner.relationshipCoverage).toEqual({
      status: "unknown",
      reason:
        "Callers: Modern upstream xrefs do not establish direct caller relationships." +
        (more
          ? " Callees: Upstream callees capped results at 500; additional callees remain unknown."
          : ""),
    });
  },
);
