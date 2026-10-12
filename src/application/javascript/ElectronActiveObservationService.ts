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

const PATH_LABELS = {
  executable_path: "Electron executable",
  application_path: "Electron application",
  application_root: "Electron application root",
} as const;

type ResolvedInputPath =
  | { readonly ok: true; readonly path: string }
  | {
      readonly ok: false;
      readonly cause: unknown;
      readonly issue: AnalysisInputIssue;
    };

const errorCode = (cause: unknown): string | undefined =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  typeof cause.code === "string"
    ? cause.code
    : undefined;

/** Resolve one caller path, reporting a failure against its own field. */
const resolveInputPath = async (
  field: keyof typeof PATH_LABELS,
  path: string,
): Promise<ResolvedInputPath> => {
  try {
    return { ok: true, path: await realpath(path) };
  } catch (cause: unknown) {
    const code = errorCode(cause);
    return {
      ok: false,
      cause,
      issue: {
        path: [field],
        reason: "invalid_value",
        message: `${PATH_LABELS[field]} must resolve to an existing path${
          code === undefined ? "" : ` (${code})`
        }`,
      },
    };
  }
};

const canonicalizeInput = async (
  input: ElectronActiveObservationInput,
): Promise<Result<CanonicalElectronActiveObservationInput, AnalysisError>> => {
  const [executable, application, root] = await Promise.all([
    resolveInputPath("executable_path", input.executable_path),
    resolveInputPath("application_path", input.application_path),
    input.application_root === undefined
      ? undefined
      : resolveInputPath("application_root", input.application_root),
  ]);
  if (!executable.ok || !application.ok || root?.ok === false) {
    const failures = [executable, application, root].filter(
      (resolved) => resolved?.ok === false,
    );
    const causes = failures.map(({ cause }) => cause);
    return err(
      new AnalysisInputError(
        OPERATION,
        {
          cause:
            causes.length === 1
              ? causes[0]
              : new AggregateError(causes, "Electron paths did not resolve"),
        },
        failures.map(({ issue }) => issue),
      ),
    );
  }
  return {
    ok: true,
    value: {
      ...input,
      executable_path: executable.path,
      application_path: application.path,
      application_root: root?.path ?? dirname(application.path),
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
