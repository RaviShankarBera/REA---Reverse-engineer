import { z } from "incur";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { IosDeviceAnalysisService } from "../application/ios/IosDeviceAnalysisService.js";
import type { IosDeviceAnalysisPort } from "../application/ios/IosDeviceAnalysisPort.js";
import { createIosDeviceAnalysisProvider } from "../composition/ios.js";
import type { IosOperation } from "../domain/ios/iosDeviceAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Expose iOS USB and jailbreak SSH observations through one-shot commands. */
export const registerIosCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: IosDeviceAnalysisPort = createIosDeviceAnalysisProvider(
    environment,
  ),
): void => {
  const service = new IosDeviceAnalysisService(provider);
  const execute = (name: string, operation: IosOperation, input: unknown) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, async () => {
        const result = await service.execute(operation, input, { signal });
        try {
          await provider.close();
        } catch (cause) {
          if (cause instanceof AnalysisError)
            return projectAnalysisError(cause);
          throw cause;
        }
        return result.ok ? result.value : projectAnalysisError(result.error);
      }),
    );
  const deviceId = z
    .string()
    .min(1)
    .describe("UDID exactly as idevice_id reports it");
  const user = z
    .enum(["root", "mobile"])
    .default("root")
    .describe("SSH account on the jailbroken device");
  cli.command(CLI_COMMANDS.inspectIosToolchain, {
    description: "Inspect libimobiledevice, iproxy, and SSH tools",
    args: z.object({}),
    run: () =>
      execute(CLI_COMMANDS.inspectIosToolchain, "inspect_ios_toolchain", {}),
  });
  cli.command(CLI_COMMANDS.listIosDevices, {
    description: "List paired USB iOS devices",
    args: z.object({}),
    run: () => execute(CLI_COMMANDS.listIosDevices, "list_ios_devices", {}),
  });
  cli.command(CLI_COMMANDS.inspectIosDevice, {
    description: "Inspect one iOS device and probe jailbreak SSH",
    args: z.object({ deviceId }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.inspectIosDevice, "inspect_ios_device", {
        device_id: args.deviceId,
      }),
  });
  cli.command(CLI_COMMANDS.listIosApps, {
    description: "List installed apps and jailbreak filesystem paths",
    args: z.object({ deviceId }),
    options: z.object({
      scope: z.enum(["all", "user", "system"]).default("all"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.listIosApps, "list_ios_apps", {
        device_id: args.deviceId,
        scope: options.scope,
      }),
  });
  cli.command(CLI_COMMANDS.listIosProcesses, {
    description: "List running iOS processes",
    args: z.object({ deviceId }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.listIosProcesses, "list_ios_processes", {
        device_id: args.deviceId,
      }),
  });
  cli.command(CLI_COMMANDS.inspectIosProcess, {
    description: "Inspect one jailbreak process with ps and lsof",
    args: z.object({ deviceId, pid: z.coerce.number().int().positive(), user }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.inspectIosProcess, "inspect_ios_process", {
        device_id: args.deviceId,
        pid: args.pid,
        user: args.user,
      }),
  });
  cli.command(CLI_COMMANDS.readIosLog, {
    description: "Read a bounded live iOS syslog window",
    args: z.object({ deviceId }),
    options: z.object({
      count: z.coerce.number().int().min(1).max(20_000).default(500),
      "duration-ms": z.coerce.number().int().min(250).max(60_000).default(5000),
      match: z.string().optional(),
      process: z.string().optional(),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.readIosLog, "read_ios_log", {
        device_id: args.deviceId,
        count: options.count,
        duration_ms: options["duration-ms"],
        ...(options.match === undefined ? {} : { match: options.match }),
        ...(options.process === undefined ? {} : { process: options.process }),
      }),
  });
  cli.command(CLI_COMMANDS.pullIosFile, {
    description: "Pull a jailbroken device file and digest it",
    args: z.object({
      deviceId,
      remotePath: z.string().min(1),
      outputDirectory: z.string().min(1),
      user,
    }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.pullIosFile, "pull_ios_file", {
        device_id: args.deviceId,
        remote_path: args.remotePath,
        output_directory: args.outputDirectory,
        user: args.user,
      }),
  });
  cli.command(CLI_COMMANDS.runIosCommand, {
    description: "Run an explicitly selected jailbreak SSH command",
    args: z.object({ deviceId, command: z.string().min(1), user }),
    options: z.object({
      timeout: z.coerce.number().int().min(250).max(300_000).default(30_000),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.runIosCommand, "run_ios_command", {
        device_id: args.deviceId,
        command: args.command,
        user: args.user,
        timeout_ms: options.timeout,
      }),
  });
  cli.command(CLI_COMMANDS.inspectIosRuntime, {
    description:
      "Inspect remote debugserver/frida-server and host debugger tools",
    args: z.object({ deviceId }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.inspectIosRuntime, "inspect_ios_runtime", {
        device_id: args.deviceId,
      }),
  });
  cli.command(CLI_COMMANDS.attachIosDebugserver, {
    description: "Attach debugserver to a jailbroken process",
    args: z.object({ deviceId, pid: z.coerce.number().int().positive(), user }),
    options: z.object({
      "remote-port": z.coerce
        .number()
        .int()
        .min(1024)
        .max(65535)
        .default(12345),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.attachIosDebugserver, "attach_ios_debugserver", {
        device_id: args.deviceId,
        pid: args.pid,
        remote_port: options["remote-port"],
        user: args.user,
      }),
  });
  cli.command(CLI_COMMANDS.runIosLldbCommand, {
    description: "Run LLDB commands through debugserver",
    args: z.object({
      deviceId,
      pid: z.coerce.number().int().positive(),
      commands: z.string().min(1),
      user,
    }),
    options: z.object({
      "remote-port": z.coerce
        .number()
        .int()
        .min(1024)
        .max(65535)
        .default(12345),
      timeout: z.coerce.number().int().min(250).max(300_000).default(30_000),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.runIosLldbCommand, "run_ios_lldb_command", {
        device_id: args.deviceId,
        pid: args.pid,
        commands: args.commands.split(/\r?\n/u).filter(Boolean),
        remote_port: options["remote-port"],
        user: args.user,
        timeout_ms: options.timeout,
      }),
  });
  cli.command(CLI_COMMANDS.runIosFridaScript, {
    description: "Run a Frida JavaScript agent against a jailbroken process",
    args: z.object({
      deviceId,
      script: z.string().min(1),
      pid: z.coerce.number().int().positive().optional(),
      process: z.string().min(1).optional(),
      user,
    }),
    options: z.object({
      "remote-port": z.coerce
        .number()
        .int()
        .min(1024)
        .max(65535)
        .default(27042),
      timeout: z.coerce.number().int().min(250).max(300_000).default(30_000),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.runIosFridaScript, "run_ios_frida_script", {
        device_id: args.deviceId,
        script: args.script,
        ...(args.pid === undefined ? {} : { pid: args.pid }),
        ...(args.process === undefined ? {} : { process: args.process }),
        remote_port: options["remote-port"],
        user: args.user,
        timeout_ms: options.timeout,
      }),
  });
  cli.command(CLI_COMMANDS.dumpIosProcessMemory, {
    description: "Read a bounded process memory range through LLDB",
    args: z.object({
      deviceId,
      pid: z.coerce.number().int().positive(),
      address: z.string().regex(/^0x[0-9a-f]+$/iu),
      user,
    }),
    options: z.object({
      size: z.coerce.number().int().min(1).max(1_048_576).default(256),
      "remote-port": z.coerce
        .number()
        .int()
        .min(1024)
        .max(65535)
        .default(12345),
      timeout: z.coerce.number().int().min(250).max(300_000).default(30_000),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.dumpIosProcessMemory, "dump_ios_process_memory", {
        device_id: args.deviceId,
        pid: args.pid,
        address: args.address,
        size: options.size,
        remote_port: options["remote-port"],
        user: args.user,
        timeout_ms: options.timeout,
      }),
  });
};
