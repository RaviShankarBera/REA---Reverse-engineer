import {
  inspectWebNetworkCaptureInputSchema,
  webNetworkCaptureSchema,
} from "../domain/webNetworkCapture.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Historical inspection is distinct from live browser capture and runtime authority. */
export const WEB_NETWORK_CAPTURE_TOOL_CONTRACTS = [
  {
    name: "inspect_web_network_capture",
    ...toolContractMetadata("inspect_web_network_capture"),
    description:
      "Inspect retained local HAR 1.2, native mitmproxy records or aioquic 1.5.0 JSON qlog 0.3 events without contacting recorded URLs. Returns original ordinals, pointers/byte ranges, preserved producer fields, precise numeric representations and exact exposed binary bytes inline. Excludes known transport credentials and explicitly marked values. Decodes every record before optional ordinal selection; malformed or oversized captures return no partial success. Qlog preserves event traversal ordinals, trace-scoped STREAM interval unions and observed endpoint loss declarations; it does not recover body bytes, prove network loss or correlate PCAP. Other qlog layouts are unsupported. Duplicate JSON members are invalid; prototype-named members such as __proto__ are preserved as ordinary own JSON members without prototype mutation. Uses pinned upstream parsers, owned temporary files and bounded offline processes. Native mitmproxy requires caller-supplied mitmdump 12.2.3 on Linux. Browser transaction IDs, runtime attribution and original bytes of HAR Unicode text remain unknown.",
    kind: "browser-provider",
    inputSchema: inspectWebNetworkCaptureInputSchema,
    outputSchema: evidenceResultOf(webNetworkCaptureSchema),
    examples: [
      {
        title: "Inspect retained aioquic qlog events",
        input: {
          capture_path: "/captures/origin.qlog",
          format: "qlog",
          record_ordinals: [0, 2],
        },
      },
      {
        title: "Inspect historical HAR entries",
        input: {
          capture_path: "/captures/session.har",
          format: "har",
          record_ordinals: [0, 2],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
