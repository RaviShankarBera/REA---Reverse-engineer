import { setImmediate } from "node:timers/promises";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type {
  Device,
  DeviceManager,
  FridaMessage,
  Script,
  Session,
} from "frida";
import { expect, it, onTestFinished } from "vitest";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { FridaInstrumentationManager } from "../../../src/frida/FridaInstrumentationManager.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const gate = () => {
  let markEntered = () => {};
  let release = () => {};
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    entered,
    release,
    async wait() {
      markEntered();
      await released;
    },
  };
};

const nativeFixture = () => {
  const created: string[] = [];
  const loaded: string[] = [];
  const unloaded: string[] = [];
  const scripts: Script[] = [];
  const controls = {
    attach: async () => {},
    create: async () => {},
    load: async () => {},
    discover: async () => {},
    unloadFailures: 0,
    detachFailures: 0,
    detachCalls: 0,
    resumes: 0,
    remoteRemovals: 0,
    removalFailures: 0,
  };
  let detached = false;
  const nativeSession: Session = {
    pid: 512,
    detached: { connect() {}, disconnect() {} },
    isDetached: () => detached,
    async detach() {
      controls.detachCalls += 1;
      if (controls.detachFailures > 0) {
        controls.detachFailures -= 1;
        throw new Error("transient detach failure");
      }
      detached = true;
    },
    async createScript(source) {
      created.push(source);
      await controls.create();
      let destroyed = false;
      let listener:
        | ((message: FridaMessage, data: Buffer | null) => void)
        | undefined;
      const script: Script = {
        get isDestroyed() {
          return destroyed;
        },
        message: {
          connect(handler) {
            listener = handler;
          },
          disconnect() {
            listener = undefined;
          },
        },
        async load() {
          await controls.load();
          loaded.push(source);
          listener?.({ type: "send", payload: source }, null);
        },
        async unload() {
          unloaded.push(source);
          if (controls.unloadFailures > 0) {
            controls.unloadFailures -= 1;
            throw new Error("transient unload failure");
          }
          destroyed = true;
        },
      };
      scripts.push(script);
      return script;
    },
  };
  const device: Device = {
    id: "local",
    name: "Local fixture",
    type: "local",
    async enumerateProcesses() {
      await controls.discover();
      return [{ pid: 512, name: "fixture" }];
    },
    async getProcessByPid() {
      return { pid: 512, name: "fixture" };
    },
    async spawn() {
      return 512;
    },
    async resume() {
      controls.resumes += 1;
    },
    async attach() {
      await controls.attach();
      return nativeSession;
    },
  };
  const deviceManager: DeviceManager = {
    async enumerateDevices() {
      return [device];
    },
    async getDeviceById() {
      return device;
    },
    async addRemoteDevice() {
      return device;
    },
    async removeRemoteDevice() {
      controls.remoteRemovals += 1;
      if (controls.removalFailures > 0) {
        controls.removalFailures -= 1;
        throw new Error("transient remote removal failure");
      }
    },
  };
  return { controls, created, loaded, unloaded, scripts, deviceManager };
};

const connectedFixture = async () => {
  const native = nativeFixture();
  const manager = new FridaInstrumentationManager({
    deviceManager: native.deviceManager,
  });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { fridaInstrumentation: manager },
  );
  const client = new Client({ name: "frida-lifecycle", version: "1" });
  onTestFinished(async () => {
    native.controls.detachFailures = 0;
    native.controls.removalFailures = 0;
    await client.close();
    await server.close();
    await manager.closeAll();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const start = async () => {
    const result = await client.callTool({
      name: "start_frida_session",
      arguments: {
        mode: "spawn",
        program: "/fixture",
        device_id: "local",
      },
    });
    return toolContract("start_frida_session").outputSchema.parse(
      result.structuredContent,
    ).session_id;
  };
  const load = (sessionId: string, source: string, signal?: AbortSignal) =>
    client.callTool(
      {
        name: "load_frida_script",
        arguments: { session_id: sessionId, source_kind: "inline", source },
      },
      signal === undefined ? undefined : { signal },
    );
  return { ...native, manager, session, server, client, start, load };
};

it.each(["load", "resume", "unload"] as const)(
  "does not dispatch a cancelled queued Frida %s through MCP",
  async (operation) => {
    const fixture = await connectedFixture();
    const id = await fixture.start();
    const original = await fixture.load(id, "original");
    const scriptId = toolContract("load_frida_script").outputSchema.parse(
      original.structuredContent,
    ).normalized_result.script_id;
    const held = gate();
    onTestFinished(held.release);
    fixture.controls.load = held.wait;
    const first = fixture.load(id, "blocking");
    await held.entered;
    const controller = new AbortController();
    const cancelled =
      operation === "load"
        ? fixture.load(id, "cancelled", controller.signal)
        : fixture.client.callTool(
            {
              name:
                operation === "resume"
                  ? "resume_frida_session"
                  : "unload_frida_script",
              arguments: {
                session_id: id,
                ...(operation === "unload" ? { script_id: scriptId } : {}),
              },
            },
            { signal: controller.signal },
          );
    const rejected = expect(cancelled).rejects.toThrow(
      "cancel queued operation",
    );
    await fixture.client.ping();
    controller.abort(new Error("cancel queued operation"));
    await fixture.client.ping();
    await rejected;
    held.release();
    await first;
    await fixture.load(id, "barrier");
    expect(fixture.created).toEqual(["original", "blocking", "barrier"]);
    expect(fixture.unloaded).toEqual([]);
    expect(fixture.controls.resumes).toBe(0);
    expect(fixture.manager.status(id)?.scripts).toHaveLength(3);
  },
);

it.each(["create", "load"] as const)(
  "releases only the new script when MCP cancellation arrives during native %s",
  async (stage) => {
    const fixture = await connectedFixture();
    const id = await fixture.start();
    await fixture.load(id, "original");
    const held = gate();
    onTestFinished(held.release);
    fixture.controls[stage] = held.wait;
    const controller = new AbortController();
    const cancelled = fixture.load(id, "cancelled-native", controller.signal);
    const rejected = expect(cancelled).rejects.toThrow(
      "cancel native operation",
    );
    await held.entered;
    controller.abort(new Error("cancel native operation"));
    await fixture.client.ping();
    await rejected;
    held.release();
    await fixture.load(id, "barrier");
    await fixture.client.ping();
    expect(fixture.unloaded).toEqual(["cancelled-native"]);
    expect(fixture.loaded).toEqual(
      stage === "create"
        ? ["original", "barrier"]
        : ["original", "cancelled-native", "barrier"],
    );
    expect(fixture.controls.detachCalls).toBe(0);
    expect(fixture.controls.resumes).toBe(0);
    expect(fixture.manager.status(id)?.scripts).toHaveLength(2);
    if (stage === "load") {
      const records = fixture.session.exportEvidenceBundle().records;
      expect(records).toContainEqual(
        expect.objectContaining({
          operation: "load_frida_script",
          normalized_result: expect.objectContaining({
            messages: [
              expect.objectContaining({ payload: "cancelled-native" }),
            ],
            script_cleanup: "released",
          }),
        }),
      );
    }
  },
);

it("awaits an admitted attach on server shutdown and retries failed native cleanup", async () => {
  const fixture = await connectedFixture();
  const held = gate();
  onTestFinished(held.release);
  fixture.controls.attach = held.wait;
  fixture.controls.detachFailures = 1;
  const starting = fixture.client
    .callTool({
      name: "start_frida_session",
      arguments: {
        mode: "attach",
        pid: 512,
        device_id: "local",
      },
    })
    .catch(() => undefined);
  await held.entered;
  let closed = false;
  const closing = fixture.server
    .close()
    .then(
      () => undefined,
      (cause: unknown) => cause,
    )
    .finally(() => {
      closed = true;
    });
  await setImmediate();
  expect(closed).toBe(false);
  expect(fixture.controls.detachCalls).toBe(0);
  held.release();
  expect(await closing).toBeInstanceOf(AggregateError);
  await starting;
  expect(fixture.controls.detachCalls).toBe(1);
  await fixture.server.close();
  expect(fixture.controls.detachCalls).toBe(2);
  await fixture.server.close();
  expect(fixture.controls.detachCalls).toBe(2);
  const afterClose = await fixture.manager.startSession({
    mode: "attach",
    pid: 512,
  });
  expect(afterClose).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
});

it("drains remote discovery before shutdown and retains failed connection cleanup", async () => {
  const fixture = await connectedFixture();
  const held = gate();
  onTestFinished(held.release);
  fixture.controls.discover = held.wait;
  fixture.controls.removalFailures = 2;
  const discovering = fixture.client
    .callTool({
      name: "list_frida_processes",
      arguments: {
        remote: { address: "127.0.0.1:27042" },
      },
    })
    .catch(() => undefined);
  await held.entered;
  let closed = false;
  const closing = fixture.server
    .close()
    .then(
      () => undefined,
      (cause: unknown) => cause,
    )
    .finally(() => {
      closed = true;
    });
  await setImmediate();
  expect(closed).toBe(false);
  held.release();
  expect(await closing).toBeInstanceOf(AggregateError);
  await discovering;
  expect(fixture.controls.remoteRemovals).toBe(2);
  await fixture.server.close();
  expect(fixture.controls.remoteRemovals).toBe(3);
});

it("retains a cancelled script whose unload fails for an explicit MCP retry", async () => {
  const fixture = await connectedFixture();
  const id = await fixture.start();
  await fixture.load(id, "original");
  const held = gate();
  onTestFinished(held.release);
  fixture.controls.load = held.wait;
  fixture.controls.unloadFailures = 1;
  const controller = new AbortController();
  const cancelled = fixture.load(id, "cancelled-native", controller.signal);
  const rejected = expect(cancelled).rejects.toThrow("cancel retained script");
  await held.entered;
  controller.abort(new Error("cancel retained script"));
  await fixture.client.ping();
  await rejected;
  held.release();
  await fixture.load(id, "barrier");
  await fixture.client.ping();
  expect(fixture.manager.status(id)?.scripts).toHaveLength(3);
  expect(fixture.session.exportEvidenceBundle().records).toContainEqual(
    expect.objectContaining({
      operation: "load_frida_script",
      normalized_result: expect.objectContaining({
        script_cleanup: "incomplete_or_unknown",
        cleanup_error: expect.stringContaining("transient unload failure"),
      }),
    }),
  );
  const scriptId = fixture.manager.status(id)?.scripts[1]?.scriptId;
  if (scriptId === undefined)
    throw new Error("Cancelled script was not retained");
  const retry = await fixture.client.callTool({
    name: "unload_frida_script",
    arguments: {
      session_id: id,
      script_id: scriptId,
    },
  });
  expect(retry.isError).not.toBe(true);
  expect(fixture.unloaded).toEqual(["cancelled-native", "cancelled-native"]);
  expect(fixture.manager.status(id)?.scripts).toHaveLength(2);
  expect(fixture.controls.detachCalls).toBe(0);
});
