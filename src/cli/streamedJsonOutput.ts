import { constants } from "node:buffer";
import type { Writable } from "node:stream";

import { Cli, Filter, Formatter } from "incur";

import { parseCliOutputArguments } from "../cliOutput.js";
import { CliCommandFailure } from "../cliLogging.js";
import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import {
  projectAnalysisError,
  type AnalysisErrorProjection,
} from "../domain/analysisErrorProjection.js";
import {
  jsonOutputParts,
  writeCliOutputPart,
  writeJsonOutput,
} from "./jsonOutput.js";
import type { CliInstance } from "./types.js";

/** Result metadata supplied by the command that actually ran. */
export interface CliResultOutputMetadata {
  readonly command: string;
  readonly duration: string;
  readonly format: string;
  readonly operationFailed: boolean;
}

/** Optional executable-owned result surface for one CLI invocation. */
export interface CliResultOutput {
  readonly handled: boolean;
  readonly failed: boolean;
  readonly error: AnalysisErrorProjection | undefined;
  write(value: unknown, metadata: CliResultOutputMetadata): Promise<boolean>;
}

type CommandMap = NonNullable<ReturnType<typeof Cli.toCommands.get>>;
type CommandDefinition = Extract<
  CommandMap extends Map<string, infer Entry> ? Entry : never,
  { run: unknown }
>;
const registeredCommands: WeakMap<object, CommandMap> = Cli.toCommands;

/** Project command-owned outcomes once, with optional executable-owned output. */
export const projectCliCommandResults = (
  cli: CliInstance,
  output?: CliResultOutput,
): void => {
  const commands = registeredCommands.get(cli);
  if (commands !== undefined) wrapCommands(commands, [], output);
};

const wrapCommands = (
  commands: CommandMap,
  parents: readonly string[],
  output: CliResultOutput | undefined,
): void => {
  for (const [name, entry] of commands) {
    const path = [...parents, name];
    if ("_group" in entry) {
      wrapCommands(entry.commands, path, output);
      if (entry.root !== undefined)
        wrapCommand(entry.root, path.join(" "), output);
    } else if (!("_alias" in entry) && !("_fetch" in entry))
      wrapCommand(entry, path.join(" "), output);
  }
};

const wrapCommand = (
  command: Pick<CommandDefinition, "run">,
  name: string,
  output: CliResultOutput | undefined,
): void => {
  const run = command.run;
  command.run = (context) => {
    const started = performance.now();
    const result: unknown = run(context);
    // Generator results and Incur's sentinel responses retain their own protocol.
    if (
      typeof result === "object" &&
      result !== null &&
      Symbol.asyncIterator in result
    )
      return result;
    return Promise.resolve(result).then(async (outcome: unknown) => {
      const operationFailed = outcome instanceof CliCommandFailure;
      const value = operationFailed ? outcome.value : outcome;
      if (
        typeof value === "object" &&
        value !== null &&
        Symbol.for("incur.sentinel") in value
      )
        return value;
      if (
        output === undefined ||
        !(await output.write(value, {
          command: name,
          format: context.format,
          duration: `${Math.round(performance.now() - started)}ms`,
          operationFailed,
        }))
      )
        return value;
      if (output.error !== undefined)
        return context.error({
          code: output.error.code,
          message: output.error.message,
        });
      return undefined;
    });
  };
};

/** Stream JSON and preserve command failures through the full-output formatters. */
export const createCliResultOutput = (
  arguments_: readonly string[],
  destination: Writable,
): CliResultOutput | undefined => {
  const options = parseCliOutputArguments(arguments_);
  if (
    options.parseError ||
    (options.tokenWindow &&
      (options.format === "json" ||
        options.format === "jsonl" ||
        options.format === "yaml")) ||
    (options.format !== "json" &&
      options.format !== "jsonl" &&
      (!options.fullOutput || options.tokenCount))
  )
    return undefined;
  const format = options.format;
  let handled = false;
  let failed = false;
  let error: AnalysisErrorProjection | undefined;
  return {
    get handled() {
      return handled;
    },
    get failed() {
      return failed;
    },
    get error() {
      return error;
    },
    async write(value, metadata) {
      if (metadata.format !== format) return false;
      const json = format === "json" || format === "jsonl";
      if (!json && !metadata.operationFailed) return false;
      const filtered: unknown = options.filterOutput
        ? Filter.apply(value, Filter.parse(options.filterOutput))
        : value;
      const window =
        !json && options.tokenWindow
          ? await failureTokenWindow(filtered, options)
          : undefined;
      const meta = {
        command: metadata.command,
        duration: metadata.duration,
        ...(window?.nextOffset === undefined
          ? {}
          : { nextOffset: window.nextOffset }),
      };
      if (options.tokenCount && json) {
        // Incur/tokenx materialize the formatted value. Measure its UTF-16
        // expansion before allowing that allocation, independently of UTF-8 bytes.
        let characters = 0;
        if (
          filtered !== undefined &&
          filtered !== null &&
          typeof filtered !== "function" &&
          typeof filtered !== "symbol"
        )
          for (const part of jsonOutputParts(filtered, format))
            characters += part.length;
        characters = Math.max(0, characters - 1);
        if (characters <= constants.MAX_STRING_LENGTH) return false;
        error = projectAnalysisError(
          new AnalysisResourceConstraintError(
            metadata.command,
            "memory",
            "Token counting requires a formatted string larger than the runtime permits.",
            {
              formatted_characters: characters,
              max_string_characters: constants.MAX_STRING_LENGTH,
            },
            {
              remediationAction:
                "Remove --token-count to stream the complete JSON result, or narrow it with --filter-output.",
            },
          ),
        );
      }
      const document = options.fullOutput
        ? metadata.operationFailed
          ? {
              ok: false,
              error: window?.text ?? (filtered === undefined ? {} : filtered),
              meta,
            }
          : filtered === undefined
            ? { ok: true, meta }
            : { ok: true, data: filtered, meta }
        : filtered === undefined ||
            filtered === null ||
            typeof filtered === "function" ||
            typeof filtered === "symbol"
          ? {}
          : filtered;
      // Once writing starts, a failed destination must not receive a second
      // document from Incur's error formatter.
      handled = true;
      try {
        const rendered =
          error === undefined
            ? document
            : options.fullOutput
              ? { ok: false, error, meta }
              : error;
        if (json) await writeJsonOutput(rendered, destination, format);
        else
          await writeCliOutputPart(
            destination,
            `${Formatter.format(rendered, format)}\n`,
          );
      } catch (cause: unknown) {
        failed = true;
        throw cause;
      }
      return true;
    },
  };
};

/** Match Incur's text windows while keeping the failure envelope and metadata intact. */
const failureTokenWindow = async (
  value: unknown,
  options: ReturnType<typeof parseCliOutputArguments>,
): Promise<{ text: string; nextOffset: number | undefined } | undefined> => {
  const { estimateTokenCount, sliceByTokens } = await import("tokenx");
  const formatted = Formatter.format(value, options.format);
  const total = estimateTokenCount(formatted);
  const offset = options.tokenOffset ?? 0;
  const end =
    options.tokenLimit === undefined ? total : offset + options.tokenLimit;
  if (offset === 0 && end >= total) return undefined;
  const actualEnd = Math.min(end, total);
  return {
    text: `${sliceByTokens(formatted, offset, end)}\n[truncated: showing tokens ${offset}–${actualEnd} of ${total}]`,
    nextOffset: actualEnd < total ? actualEnd : undefined,
  };
};
