import { expect, it } from "vitest";

import { indexJavaScriptBindingsSteps } from "./javascriptSemanticAnalysis.js";
import type { JavaScriptSemanticValue } from "./javascriptSemanticValueTypes.js";
import { evaluateSemanticBinding } from "./javascriptSemanticValues.js";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";

const property = (
  value: JavaScriptSemanticValue,
  name: string,
): JavaScriptSemanticValue => {
  if (value.status !== "object")
    throw new Error(`Expected object at ${name}, got ${value.status}`);
  const result = value.properties.find((entry) => entry.name === name)?.value;
  if (result === undefined) throw new Error(`Missing ${name}`);
  return result;
};

it("recomputes a shared cyclic value under a different active ancestor", () => {
  const parsed = parseJavaScriptSource(
    `
const a = { shared: common, own: "a" };
const b = { shared: common, own: "b" };
const common = { a, b };
const result = { first: a, second: b };
`,
    "cycles.js",
  );
  if (parsed === null) throw new Error("Expected parsed source");
  const steps = indexJavaScriptBindingsSteps(parsed.program);
  let step = steps.next();
  while (step.done !== true) step = steps.next();
  const state = step.value;
  const binding = [...state.bindingsById.values()].find(
    (entry) => entry.name === "result",
  );
  if (binding === undefined) throw new Error("Missing result binding");
  const value = evaluateSemanticBinding(binding, state);
  const firstCommon = property(property(value, "first"), "shared");
  const secondCommon = property(property(value, "second"), "shared");
  expect(property(firstCommon, "a").status).toBe("cycle");
  expect(property(property(firstCommon, "b"), "own")).toEqual({
    status: "literal",
    value: "b",
  });
  expect(property(secondCommon, "b").status).toBe("cycle");
  expect(property(property(secondCommon, "a"), "own")).toEqual({
    status: "literal",
    value: "a",
  });
});
