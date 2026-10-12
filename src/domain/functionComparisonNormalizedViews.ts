import { diffLines } from "diff";

import { digestCanonicalValue } from "./canonicalDigest.js";
import type { FunctionSnapshot } from "./functionDossierEvidence.js";
import { parseAddress } from "./functionComparisonNormalization.js";
import type {
  FunctionNormalizedViews,
  MaskingCounts,
  NormalizedTextView,
  NormalizedViewDimension,
} from "./functionComparisonSchemas.js";
import { NORMALIZED_VIEW_DIMENSIONS } from "./functionComparisonSchemas.js";

/** Masking policy identifier reported with every normalized view. */
const POLICY = "rea-address-normalized-text-v1";

/**
 * Recognized address-derived identifier forms of the supported providers.
 *
 * A label matches only when its suffix is fully hexadecimal and the whole token
 * ends there, so `sub_deallocate` and a named symbol such as `__RTC_CheckEsp`
 * never match. Matching is form-based; masking additionally requires that this
 * dossier corroborates the embedded address.
 */
const ADDRESS_DERIVED_IDENTIFIER =
  /(?<![0-9A-Za-z_])((?:thunk_|flt_)?(?:FUN|SUB|DAT|LAB|PTR|UNK|SwitchD|Join)_|(?:sub|loc|off|unk|nullsub)_|(?:fcn|sub|loc|off|data)\.)(0x)?[0-9a-f]{4,}(?![0-9A-Za-z_])/giu;

const HEXADECIMAL_ADDRESS = /(?<![0-9A-Za-z_:])0x[0-9a-f]+/giu;

/** Declared masking rules, reported verbatim so every view can be audited. */
const RULES = [
  {
    rule: "address_derived_identifier",
    description:
      "Recognized provider address-derived identifiers (FUN_, SUB_, DAT_, LAB_, PTR_, UNK_, SwitchD_, thunk_FUN_, sub_, loc_, off_, unk_, nullsub_, fcn., and peer dotted forms) whose embedded address this dossier corroborates are replaced by an ordinal placeholder in order of first appearance, keeping the provider label prefix. Named symbols, constants, and uncorroborated labels stay visible.",
  },
  {
    rule: "function_relative_address",
    description:
      "Hexadecimal addresses inside the observed function body are replaced by their offset from that function's entry, which is invariant when only the layout shifts.",
  },
  {
    rule: "corroborated_external_address",
    description:
      "Remaining hexadecimal addresses corroborated by this dossier's callees, callers, references, strings, names, comments, or thunk targets are replaced by an ordinal placeholder in order of first appearance. Addresses no dossier fact corroborates stay visible.",
  },
] as const;

const SHARED_LIMITATIONS = [
  "Normalized views compare provider text after declared address masking. Equal normalized views do not establish that both sides reference the same procedure, data, label, or layout; the exact pseudocode, assembly, calls, references, and CFG dimensions keep their own meanings and statuses.",
  "Ordinal placeholders are assigned independently by first appearance on each side. A normalized unchanged status means only that masked text is equal; it does not prove stable target identity or call order.",
] as const;

interface AddressProjection {
  /** Entry-relative offset, corroborated external address, or null when unmasked. */
  readonly maskAddress: (address: bigint) => string | null;
  readonly isCalleeAddress: (address: bigint) => boolean;
}

/**
 * Project one side's provider text into the address-normalized comparison space.
 *
 * The projection is deterministic and side-local: ordinals follow first
 * appearance, so identical code compares equal only when it uses addresses in
 * the same order. Any changed order, count, mnemonic, or constant stays visible.
 * The reported counts are masked and visible occurrence counts, not distinct
 * addresses, so a reader can audit how much of the text the policy touched.
 */
const normalizeText = (
  text: string,
  projection: AddressProjection,
): {
  readonly text: string;
  readonly counts: MaskingCounts;
  readonly maskedCalleeTarget: boolean;
} | null => {
  const identifiers = new Map<string, string>();
  const addresses = new Map<string, string>();
  let maskedIdentifiers = 0;
  let unmaskedIdentifiers = 0;
  let maskedAddresses = 0;
  let visibleAddresses = 0;
  let maskedCalleeTarget = false;
  const normalized = transformCode(text, (code) => {
    const withIdentifiers = code.replace(
      ADDRESS_DERIVED_IDENTIFIER,
      (match, label: string, prefix: string | undefined) => {
        const address = parseAddress(
          `${prefix ?? "0x"}${match.slice(label.length + (prefix?.length ?? 0))}`.toLowerCase(),
        );
        const replacement =
          address === null ? null : projection.maskAddress(address);
        if (replacement === null) {
          unmaskedIdentifiers += 1;
          return match;
        }
        if (address !== null && projection.isCalleeAddress(address))
          maskedCalleeTarget = true;
        maskedIdentifiers += 1;
        const existing = identifiers.get(replacement);
        if (existing !== undefined) return existing;
        const placeholder = `${label}<sym:${identifiers.size + 1}>`;
        identifiers.set(replacement, placeholder);
        return placeholder;
      },
    );
    return withIdentifiers.replace(HEXADECIMAL_ADDRESS, (match) => {
      const address = parseAddress(match.toLowerCase());
      const replacement =
        address === null ? null : projection.maskAddress(address);
      if (replacement === null) {
        visibleAddresses += 1;
        return match;
      }
      if (address !== null && projection.isCalleeAddress(address))
        maskedCalleeTarget = true;
      maskedAddresses += 1;
      const existing = addresses.get(replacement);
      if (existing !== undefined) return existing;
      const placeholder = `<addr:${addresses.size + 1}>`;
      addresses.set(replacement, placeholder);
      return placeholder;
    });
  });
  if (normalized === null) return null;
  return {
    text: normalized,
    maskedCalleeTarget,
    counts: {
      address_derived_identifiers: maskedIdentifiers,
      unmasked_address_derived_identifiers: unmaskedIdentifiers,
      corroborated_addresses: maskedAddresses,
      visible_addresses: visibleAddresses,
    },
  };
};

/** Normalize code tokens while preserving literals/comments byte-for-byte. */
const transformCode = (
  text: string,
  transform: (code: string) => string,
): string | null => {
  let output = "";
  let codeStart = 0;
  let index = 0;
  while (index < text.length) {
    const current = text[index];
    const next = text[index + 1];
    if (current === '"' || current === "'") {
      output += transform(text.slice(codeStart, index));
      const quote = current;
      const literalStart = index++;
      let closed = false;
      while (index < text.length) {
        if (text[index] === "\\") {
          index += 2;
          continue;
        }
        if (text[index] === quote) {
          index += 1;
          closed = true;
          break;
        }
        if ((text[index] === "\n" || text[index] === "\r") && quote === "'")
          return null;
        index += 1;
      }
      if (!closed) return null;
      output += text.slice(literalStart, index);
      codeStart = index;
      continue;
    }
    if (current === "/" && (next === "/" || next === "*")) {
      output += transform(text.slice(codeStart, index));
      const commentStart = index;
      if (next === "/") {
        index += 2;
        while (index < text.length && text[index] !== "\n") index += 1;
      } else {
        index += 2;
        const end = text.indexOf("*/", index);
        if (end < 0) return null;
        index = end + 2;
      }
      output += text.slice(commentStart, index);
      codeStart = index;
      continue;
    }
    index += 1;
  }
  output += transform(text.slice(codeStart));
  return output;
};

interface BodyExtent {
  readonly base: bigint;
  readonly ranges: readonly (readonly [bigint, bigint])[];
}

/** Read the observed body extent without expanding an address into a lookup table. */
const bodyExtent = (snapshot: FunctionSnapshot): BodyExtent | null => {
  const body = snapshot.dossier.procedure.body;
  const base = parseAddress(snapshot.dossier.procedure.address.toLowerCase());
  if (base === null || !body.available || body.ranges.length === 0) return null;
  const ranges: [bigint, bigint][] = [];
  for (const range of body.ranges) {
    const start = parseAddress(range.start.toLowerCase());
    const end = parseAddress(range.end.toLowerCase());
    if (start === null || end === null || end < start) return null;
    ranges.push([start, end]);
  }
  ranges.sort((left, right) =>
    left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0,
  );
  return { base, ranges };
};

/** Every default-space address this dossier corroborates in its own spelling. */
const corroboratedAddresses = (snapshot: FunctionSnapshot): Set<bigint> => {
  const addresses = new Set<bigint>();
  const add = (value: string | null | undefined) => {
    const parsed = parseAddress((value ?? "").toLowerCase());
    if (parsed !== null) addresses.add(parsed);
  };
  const { dossier } = snapshot;
  add(dossier.procedure.address);
  if (dossier.procedure.body.available)
    for (const range of dossier.procedure.body.ranges) {
      add(range.start);
      add(range.end);
    }
  for (const block of dossier.basic_blocks) {
    add(block.start);
    add(block.end);
    for (const successor of block.successors) add(successor);
  }
  for (const comment of dossier.comments) add(comment.address);
  for (const edge of [
    ...dossier.incoming_references,
    ...dossier.outgoing_references,
  ]) {
    add(edge.source_address);
    add(edge.target_address);
    for (const identity of [edge.source_procedure, edge.target_procedure]) {
      add(identity?.address);
      add(identity?.classification?.thunk_target);
    }
  }
  for (const identity of [...dossier.callers, ...dossier.callees]) {
    add(identity.address);
    add(identity.classification?.thunk_target);
  }
  for (const item of [
    ...dossier.referenced_strings,
    ...dossier.referenced_names,
  ]) {
    add(item.address);
    add(item.source_address);
  }
  return addresses;
};

/**
 * Project one side, using entry-relative offsets only when that extent is known.
 *
 * Both sides must agree on the projection scheme, so an unusable extent is
 * resolved once for the pair by the caller and reported as a limitation.
 */
const sideProjection = (
  snapshot: FunctionSnapshot,
  relativeOffsets: boolean,
): AddressProjection => {
  const addresses = corroboratedAddresses(snapshot);
  const calleeAddresses = new Set(
    snapshot.dossier.callees.flatMap((callee) =>
      [callee.address, callee.classification?.thunk_target]
        .map((value) => parseAddress((value ?? "").toLowerCase()))
        .filter((value): value is bigint => value !== null),
    ),
  );
  const extent = relativeOffsets ? bodyExtent(snapshot) : null;
  return {
    isCalleeAddress: (address) => calleeAddresses.has(address),
    maskAddress: (address) => {
      if (extent !== null && contains(extent.ranges, address))
        return `+0x${(address - extent.base).toString(16)}`;
      return addresses.has(address) ? `address:${address.toString(16)}` : null;
    },
  };
};

/** Binary search over sorted inclusive ranges; bodies are never expanded. */
const contains = (
  ranges: readonly (readonly [bigint, bigint])[],
  address: bigint,
): boolean => {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const range = ranges[middle];
    if (range === undefined) return false;
    if (address < range[0]) high = middle - 1;
    else if (address > range[1]) low = middle + 1;
    else return true;
  }
  return false;
};

const unknownView = (
  dimension: NormalizedViewDimension,
  links: readonly string[],
  limitations: readonly string[],
): NormalizedTextView => ({
  dimension,
  status: "unknown",
  left_digest: null,
  right_digest: null,
  left_count: null,
  right_count: null,
  text_delta: null,
  evidence_links: [...links],
  masking: null,
  limitations: [...limitations],
  conclusion_kind: "unresolved_branch",
});

/**
 * Build the opt-in normalized views for one function pair.
 *
 * Nothing here can change the eight exact dimensions, their statuses, the
 * summary counts, or the overall comparison status. Each view is labelled, cites
 * both Evidence records, and declares the masking rules it applied.
 */
export const normalizedViews = (
  left: FunctionSnapshot,
  right: FunctionSnapshot,
  options: {
    readonly links: readonly string[];
    readonly providersDiffer: boolean;
    readonly callsStatus: "unchanged" | "changed" | "unknown";
  },
): FunctionNormalizedViews => {
  const { links, providersDiffer } = options;
  const shared = [...SHARED_LIMITATIONS];
  if (providersDiffer) {
    const limitation =
      "Normalized text comparison requires one provider identity.";
    return {
      policy: POLICY,
      views: NORMALIZED_VIEW_DIMENSIONS.map((dimension) =>
        unknownView(dimension, links, [...shared, limitation]),
      ),
      limitations: [...shared, limitation],
    };
  }
  const relativeOffsets =
    bodyExtent(left) !== null && bodyExtent(right) !== null;
  const limitations = relativeOffsets
    ? shared
    : [
        ...shared,
        "One dossier did not observe its own function body extent, so corroborated addresses on both sides were masked as ordinal placeholders instead of entry-relative offsets.",
      ];
  const leftProjection = sideProjection(left, relativeOffsets);
  const rightProjection = sideProjection(right, relativeOffsets);
  return {
    policy: POLICY,
    views: NORMALIZED_VIEW_DIMENSIONS.map((dimension) => {
      const leftText = normalizeText(viewText(left, dimension), leftProjection);
      const rightText = normalizeText(
        viewText(right, dimension),
        rightProjection,
      );
      if (leftText === null || rightText === null)
        return unknownView(dimension, links, [
          ...limitations,
          "Provider text contains an unterminated string, character literal, or block comment, so normalization was skipped.",
        ]);
      const changes = diffLines(leftText.text, rightText.text, {
        timeout: 100,
        maxEditLength: 10_000,
      });
      if (changes === undefined)
        return unknownView(dimension, links, [
          ...limitations,
          "Bounded line diff exceeded its time or edit-distance limit.",
        ]);
      const delta = changes.reduce(
        (summary, change) => ({
          added_lines:
            summary.added_lines + (change.added ? (change.count ?? 0) : 0),
          removed_lines:
            summary.removed_lines + (change.removed ? (change.count ?? 0) : 0),
          hunks: summary.hunks + (change.added || change.removed ? 1 : 0),
        }),
        { added_lines: 0, removed_lines: 0, hunks: 0 },
      );
      if (
        delta.hunks === 0 &&
        options.callsStatus === "unknown" &&
        (leftText.maskedCalleeTarget || rightText.maskedCalleeTarget)
      )
        return unknownView(dimension, links, [
          ...limitations,
          "Masked text references a dossier-listed callee while the exact calls dimension is unknown; normalized equality cannot establish callee identity or call order.",
        ]);
      return {
        dimension,
        status: delta.hunks === 0 ? "unchanged" : "changed",
        left_digest: digest(leftText.text),
        right_digest: digest(rightText.text),
        left_count: [...leftText.text].length,
        right_count: [...rightText.text].length,
        text_delta: delta,
        evidence_links: [...links],
        masking: {
          policy: POLICY,
          provider_id: left.evidence.provider.id,
          rules: RULES.map((rule) => ({ ...rule })),
          left: leftText.counts,
          right: rightText.counts,
        },
        limitations: [...limitations],
        conclusion_kind: "derived_relationship",
      } satisfies NormalizedTextView;
    }),
    limitations: [...limitations],
  };
};

const viewText = (
  snapshot: FunctionSnapshot,
  dimension: NormalizedViewDimension,
): string =>
  dimension === "pseudocode_normalized"
    ? snapshot.dossier.pseudocode
    : snapshot.dossier.assembly.join("\n");

const digest = (value: string): string =>
  digestCanonicalValue(value, "Function normalized text view");
