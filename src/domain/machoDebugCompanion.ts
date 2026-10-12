import { err, ok, type Result } from "./result.js";

const LC_UUID = 0x1b;
const FAT_MAGIC_BE = 0xcafebabe;
const FAT_MAGIC_64_BE = 0xcafebabf;
const FAT_MAGIC_LE = 0xbebafeca;
const FAT_MAGIC_64_LE = 0xbfbafeca;
const THIN_LITTLE_MAGICS = new Set([0xcefaedfe, 0xcffaedfe]);
const THIN_BIG_MAGICS = new Set([0xfeedface, 0xfeedfacf]);
const UUID_BYTES = 16;

/** One LC_UUID with the cputype of the Mach-O image that declares it. */
export interface MachOUuidEntry {
  readonly cpuType: number;
  readonly uuid: string;
}

const formatUuid = (raw: Buffer): string => {
  const hex = raw.toString("hex").toUpperCase();
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
};

/**
 * The declared load-command span of a thin Mach-O image, with its byte
 * order, so a reader can fetch exactly the bytes the parser walks. The span
 * is bounded by the reader's region, not by an arbitrary ceiling.
 */
export const machoCommandSpan = (
  bytes: Buffer,
): Result<
  { readonly start: number; readonly size: number; readonly little: boolean },
  string
> => {
  if (bytes.length < 32) return err("Mach-O header is truncated");
  const magic = bytes.readUInt32BE(0);
  const little = THIN_LITTLE_MAGICS.has(magic);
  if (!little && !THIN_BIG_MAGICS.has(magic)) return err("not a Mach-O image");
  const read32 = little
    ? (position: number) => bytes.readUInt32LE(position)
    : (position: number) => bytes.readUInt32BE(position);
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const start = wide ? 32 : 28;
  const size = read32(20);
  if (size < start) return err("Mach-O declared load-command span is invalid");
  return ok({ start, size, little });
};

const readUuidsFromThin = (
  bytes: Buffer,
  offset: number,
  end: number,
): Result<MachOUuidEntry[], string> => {
  const base = offset;
  const magic = bytes.readUInt32BE(base);
  const little = THIN_LITTLE_MAGICS.has(magic);
  if (!little && !THIN_BIG_MAGICS.has(magic))
    return err(`not a Mach-O image at offset ${String(offset)}`);
  const read32 = little
    ? (position: number) => bytes.readUInt32LE(position)
    : (position: number) => bytes.readUInt32BE(position);
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const headerSize = wide ? 32 : 28;
  const commandsOffset = base + headerSize;
  // Field access requires a complete header; a short prefix is a rejection,
  // not a crash.
  if (commandsOffset > end)
    return err("Mach-O header is truncated before its load commands");
  const cpuType = read32(base + 4);
  const commandCount = read32(base + 16);
  // sizeofcmds excludes the header; its consistency is enforced by exact
  // consumption below.
  const declaredSize = read32(base + 20);
  // Commands live exactly in the declared span; anything after it is not a
  // load command no matter what the surrounding bytes look like.
  const commandsEnd = Math.min(end, commandsOffset + declaredSize);
  let cursor = commandsOffset;
  let consumed = 0;
  let observed: string | undefined;
  for (let index = 0; index < commandCount; index += 1) {
    if (cursor + 8 > commandsEnd)
      return err(`Mach-O load command ${String(index)} is truncated`);
    const command = read32(cursor);
    const size = read32(cursor + 4);
    if (size < 8 || cursor + size > commandsEnd)
      return err(`Mach-O load command ${String(index)} has an invalid size`);
    if (command === LC_UUID) {
      if (size < 8 + UUID_BYTES)
        return err("LC_UUID load command is truncated");
      // A second LC_UUID in one image is a conflicting identity, not more
      // evidence; admission must not pick whichever matches.
      if (observed !== undefined)
        return err("Mach-O image declares more than one LC_UUID");
      observed = formatUuid(
        bytes.subarray(cursor + 8, cursor + 8 + UUID_BYTES),
      );
    }
    cursor += size;
    consumed += size;
  }
  if (consumed !== declaredSize || cursor !== commandsOffset + declaredSize)
    return err(
      "Mach-O load commands do not fill the declared load-command span",
    );
  return ok(observed === undefined ? [] : [{ cpuType, uuid: observed }]);
};

/**
 * Read the LC_UUID of a Mach-O image with its declaring cputype, descending
 * into universal (FAT) containers of either byte order. Slice order is
 * preserved so a caller can attribute each UUID to its architecture; a zero
 * UUID is preserved: it is an observed value, not an unknown.
 */
export const readMachoUuidEntries = (
  bytes: Buffer,
): Result<MachOUuidEntry[], string> => {
  if (bytes.length < 8) return err("Mach-O image is truncated");
  const magic = bytes.readUInt32BE(0);
  const fat =
    magic === FAT_MAGIC_BE ||
    magic === FAT_MAGIC_64_BE ||
    magic === FAT_MAGIC_LE ||
    magic === FAT_MAGIC_64_LE;
  if (fat) {
    const wide = magic === FAT_MAGIC_64_BE || magic === FAT_MAGIC_64_LE;
    // The architecture table's byte order follows the observed magic.
    const big = magic === FAT_MAGIC_BE || magic === FAT_MAGIC_64_BE;
    const read32 = big
      ? (position: number) => bytes.readUInt32BE(position)
      : (position: number) => bytes.readUInt32LE(position);
    const count = read32(4);
    const entrySize = wide ? 32 : 20;
    if (count > 128 || 8 + count * entrySize > bytes.length)
      return err(
        "universal Mach-O container has an invalid architecture table",
      );
    const entries: MachOUuidEntry[] = [];
    for (let index = 0; index < count; index += 1) {
      const entry = 8 + index * entrySize;
      const cpuType = big ? bytes.readInt32BE(entry) : bytes.readInt32LE(entry);
      const sliceOffset = wide
        ? Number(
            big
              ? bytes.readBigUInt64BE(entry + 8)
              : bytes.readBigUInt64LE(entry + 8),
          )
        : read32(entry + 8);
      const sliceSize = wide
        ? Number(
            big
              ? bytes.readBigUInt64BE(entry + 16)
              : bytes.readBigUInt64LE(entry + 16),
          )
        : read32(entry + 12);
      if (sliceSize === 0) return err("universal Mach-O slice is empty");
      if (sliceOffset > bytes.length || sliceSize > bytes.length - sliceOffset)
        return err("universal Mach-O slice is out of bounds");
      const slice = readUuidsFromThin(
        bytes,
        sliceOffset,
        sliceOffset + sliceSize,
      );
      if (!slice.ok) return slice;
      for (const item of slice.value)
        entries.push({ cpuType, uuid: item.uuid });
    }
    return ok(entries);
  }
  return readUuidsFromThin(bytes, 0, bytes.length);
};

/** The LC_UUID values of a Mach-O image, without their architecture owner. */
export const readMachoUuids = (bytes: Buffer): Result<string[], string> => {
  const entries = readMachoUuidEntries(bytes);
  return entries.ok ? ok(entries.value.map(({ uuid }) => uuid)) : entries;
};

/**
 * A companion matches when it carries the UUID of the executable image REA
 * will analyze. Executable images without any LC_UUID cannot be matched and
 * are rejected explicitly instead of matching vacuously. An all-zero UUID is
 * an observed placeholder, not an identity, and never matches.
 */
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";

export const debugCompanionMatches = (input: {
  readonly executableUuids: readonly string[];
  readonly companionUuids: readonly string[];
}): Result<{ readonly uuid: string }, string> => {
  const executable = input.executableUuids.filter((uuid) => uuid !== ZERO_UUID);
  if (executable.length === 0)
    return err("the executable declares no LC_UUID to match against");
  const companions = new Set(
    input.companionUuids.filter((uuid) => uuid !== ZERO_UUID),
  );
  for (const uuid of executable) if (companions.has(uuid)) return ok({ uuid });
  return err(
    "the debug companion's UUID does not match the executable's LC_UUID",
  );
};
