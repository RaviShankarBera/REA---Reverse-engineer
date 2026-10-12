import { afterEach, expect, it } from "vitest";
import {
  closeEnhancedToolResources,
  connect,
  jsonResult,
} from "./enhancedToolsHarness.js";
import { observed as ok } from "../../fixtures/analysisExecution.js";
import type { SegmentSummary } from "../../../src/domain/hopperValues.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

afterEach(closeEnhancedToolResources);

const segment = {
  name: ".text",
  start: "0x101000",
  end: "0x101100",
  readable: true,
  writable: false,
  executable: true,
  image_base: "0x100000",
  address_space: "ram",
};

const overviewClient = (segments: SegmentSummary[]) =>
  connect({
    execute: (name) => {
      switch (name) {
        case "current_document":
          return Promise.resolve(ok("fixture"));
        case "list_documents":
          return Promise.resolve(ok(["fixture"]));
        case "list_segments":
          return Promise.resolve(ok(segments));
        case "list_procedures":
          return Promise.resolve(ok([{ address: "0x101013", value: "entry" }]));
        case "list_strings":
          return Promise.resolve(ok([]));
        default:
          throw new Error(`Unexpected operation: ${name}`);
      }
    },
  });

it("preserves the observed image base rather than guessing it from the first segment", async () => {
  const client = await overviewClient([segment]);
  expect(
    jsonResult(
      await client.callTool({ name: "binary_overview", arguments: {} }),
    ),
  ).toMatchObject({
    image_base: "0x100000",
    segments: [
      { start: "0x101000", image_base: "0x100000", address_space: "ram" },
    ],
  });
});

it("keeps an unreported image base unknown instead of inventing zero or a segment start", async () => {
  const { image_base: _base, address_space: _space, ...unreported } = segment;
  const client = await overviewClient([unreported]);
  expect(
    jsonResult(
      await client.callTool({ name: "binary_overview", arguments: {} }),
    ),
  ).toMatchObject({ image_base: null });
});

it("preserves an explicitly observed zero image base", async () => {
  const client = await overviewClient([{ ...segment, image_base: "0x0" }]);
  expect(
    jsonResult(
      await client.callTool({ name: "binary_overview", arguments: {} }),
    ),
  ).toMatchObject({ image_base: "0x0" });
});

it("rejects conflicting provider image bases instead of choosing the first", async () => {
  const client = await overviewClient([
    segment,
    {
      ...segment,
      name: ".data",
      start: "other%20space:0x201000",
      end: "other%20space:0x201100",
      image_base: "0x200000",
      address_space: "other space",
    },
  ]);
  const result = await client.callTool({
    name: "binary_overview",
    arguments: {},
  });
  expect(result.isError).toBe(true);
  expect(parseMcpToolError(result).error).toMatchObject({
    code: "unreadable_output",
    details: {
      partial_observation: {
        kind: "image-base-conflict",
        reported_segment_count: 2,
        reported_image_base_count: 2,
        omitted_segment_count: 0,
        omitted_image_base_count: 0,
        representative_segments: [
          {
            name: ".text",
            start: "0x101000",
            end: "0x101100",
            image_base: "0x100000",
            address_space: "ram",
          },
          {
            name: ".data",
            start: "other%20space:0x201000",
            end: "other%20space:0x201100",
            image_base: "0x200000",
            address_space: "other space",
          },
        ],
      },
    },
  });
});

it("retains the conflicting base even when many earlier segments share one base", async () => {
  const client = await overviewClient([
    ...Array.from({ length: 40 }, () => segment),
    { ...segment, name: ".data", image_base: "0x200000" },
  ]);
  const result = await client.callTool({
    name: "binary_overview",
    arguments: {},
  });
  expect(parseMcpToolError(result).error).toMatchObject({
    details: {
      partial_observation: {
        reported_segment_count: 41,
        reported_image_base_count: 2,
        omitted_segment_count: 39,
        omitted_image_base_count: 0,
        representative_segments: [
          { image_base: "0x100000" },
          { image_base: "0x200000" },
        ],
      },
    },
  });
});

it("bounds the conflict sample and reports omitted bases", async () => {
  const client = await overviewClient(
    Array.from({ length: 40 }, (_, index) => ({
      ...segment,
      image_base: `0x${(index + 1).toString(16)}`,
    })),
  );
  const result = await client.callTool({
    name: "binary_overview",
    arguments: {},
  });
  const error = parseMcpToolError(result).error;
  if (error.code !== "unreadable_output")
    throw new Error("Expected an unreadable-output conflict failure");
  const observation = error.details?.partial_observation;
  expect(observation).toMatchObject({
    reported_segment_count: 40,
    reported_image_base_count: 40,
    omitted_segment_count: 8,
    omitted_image_base_count: 8,
  });
  expect(observation).toHaveProperty("representative_segments.length", 32);
});

it("keeps an unreported address space unknown in conflict observations", async () => {
  const { address_space: _space, ...unreported } = segment;
  const client = await overviewClient([
    unreported,
    { ...segment, image_base: "0x200000" },
  ]);
  const result = await client.callTool({
    name: "binary_overview",
    arguments: {},
  });
  expect(parseMcpToolError(result).error).toMatchObject({
    details: {
      partial_observation: {
        representative_segments: [
          { image_base: "0x100000", address_space: null },
          { image_base: "0x200000", address_space: "ram" },
        ],
      },
    },
  });
});
