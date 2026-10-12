import { dirname } from "node:path";
import { realpath } from "node:fs/promises";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { ElectronActiveObservationPort } from "./ElectronActiveObservationPort.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  type AnalysisInputIssue,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { ElectronActiveObservationInput } from "../../domain/javascript/electronActiveObservation.js";
import { err, type Result } from "../../domain/result.js";
import { createElectronActiveEvidence } from "./ElectronActiveEvidence.js";

const OPERATION = "capture_electron_scenario" as const;
const PROVIDER_ID = "rea-playwright-electron-active";
type CanonicalElectronActiveObservationInput =
  ElectronActiveObservationInput & {
    readonly application_root: string;
  };

const canonicalizeInput = async (
  input: ElectronActiveObservationInput,
): Promise<Result<CanonicalElectronActiveObservationInput, AnalysisError>> => {
  const fields = [
    "executable_path",
    "application_path",
    "application_root",
  ] as const;
  const paths = await Promise.all(
    fields.map(async (field) => {
      const path = input[field];
      if (path === undefined) return { field, path: undefined };
      try {
        return { field, path: await realpath(path) };
      } catch (cause: unknown) {
        return {
          field,
          cause,
          issue: {
            path: [field],
            reason: "invalid_value",
            message: `Cannot resolve ${field}: ${cause instanceof Error ? cause.message : String(cause)}`,
          } satisfies AnalysisInputIssue,
        };
      }
    }),
  );
  const issues = paths.flatMap((entry) =>
    entry.issue === undefined ? [] : [entry.issue],
  );
  if (issues.length > 0)
    return err(
      new AnalysisInputError(
        OPERATION,
        {
          cause: new AggregateError(
            paths.flatMap((entry) =>
              entry.issue === undefined ? [] : [entry.cause],
            ),
            "Electron paths could not be resolved",
          ),
        },
        issues,
      ),
    );
  const executablePath = paths[0]?.path;
  const applicationPath = paths[1]?.path;
  if (executablePath === undefined || applicationPath === undefined)
    throw new Error("Required Electron paths were not canonicalized");
  return {
    ok: true,
    value: {
      ...input,
      executable_path: executablePath,
      application_path: applicationPath,
      application_root: paths[2]?.path ?? dirname(applicationPath),
    },
  };
};

/** Canonicalize request paths and execute one provider-owned Electron run. */
export const captureElectronScenario = async (
  provider: ElectronActiveObservationPort | undefined,
  input: ElectronActiveObservationInput,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const canonical = await canonicalizeInput(input);
  if (!canonical.ok) return canonical;
  if (provider === undefined)
    return err(
      new AnalysisCapabilityUnavailableError(
        PROVIDER_ID,
        OPERATION,
        "active Electron observation provider is not configured",
      ),
    );
  const captured = await provider.capture(canonical.value, options);
  return captured.ok
    ? {
        ok: true,
        value: createElectronActiveEvidence(
          canonical.value,
          captured.value,
          provider.identity(),
        ),
      }
    : captured;
};
