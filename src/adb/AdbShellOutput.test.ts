import { describe, expect, it } from "vitest";

import { parseAmStartOutput } from "./AdbShellOutput.js";

const intent = "act=android.intent.action.MAIN cmp=com.example/.Main";
const starting = `Starting: Intent { ${intent} }`;

describe("parseAmStartOutput", () => {
  it.each(["\n", "\r\n"])(
    "preserves complete successful wait output with %j line endings",
    (newline) => {
      expect(
        parseAmStartOutput(
          [
            starting,
            "Status: ok",
            "LaunchState: COLD",
            "Activity: com.example/.Main",
            "TotalTime: 314",
            "WaitTime: 315",
            "Complete",
          ].join(newline),
        ),
      ).toEqual({
        status: "started",
        startedActivity: intent,
        activity: "com.example/.Main",
        reportedStatus: "ok",
        reason: null,
      });
    },
  );

  it("preserves the attempted intent and activity when the device times out", () => {
    expect(
      parseAmStartOutput(
        `${starting}\nStatus: timeout\nActivity: com.example/.Main\nWaitTime: 10004\nComplete\n`,
      ),
    ).toEqual({
      status: "timed_out",
      startedActivity: intent,
      activity: "com.example/.Main",
      reportedStatus: "timeout",
      reason: "am start reported status: timeout",
    });
  });

  it("does not let an earlier ok or Starting line mask later failure", () => {
    expect(
      parseAmStartOutput(`${starting}\nStatus: ok\nStatus: timeout\n`),
    ).toMatchObject({ status: "timed_out", reportedStatus: "timeout" });
    expect(parseAmStartOutput(`${starting}\nStatus: failed\n`)).toMatchObject({
      status: "refused",
      reportedStatus: "failed",
    });
  });

  it("gives hard errors precedence and reads errors from stderr", () => {
    expect(
      parseAmStartOutput(
        `${starting}\nStatus: timeout\n`,
        "Error: Activity class does not exist\n",
      ),
    ).toMatchObject({
      status: "refused",
      startedActivity: intent,
      reportedStatus: "timeout",
      reason: "Activity class does not exist",
    });
  });

  it("retains legacy Starting output and already-running success warnings", () => {
    expect(parseAmStartOutput(starting)).toMatchObject({
      status: "started",
      reportedStatus: null,
      activity: null,
    });
    expect(
      parseAmStartOutput(
        `${starting}\nWarning: Activity not started, intent has been delivered to currently running top-most instance.\nStatus: ok\nActivity: com.example/.Main\n`,
      ),
    ).toMatchObject({ status: "started", reportedStatus: "ok" });
  });

  it.each([
    "",
    "Error: unable to resolve Intent",
    "Warning: Activity not started",
  ])("refuses output without a launch observation: %j", (output) => {
    expect(parseAmStartOutput(output)).toMatchObject({
      status: "refused",
      startedActivity: null,
    });
  });
});
