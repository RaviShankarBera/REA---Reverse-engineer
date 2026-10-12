/**
 * Argument names agents commonly send in place of a canonical input key. An
 * agent that just received an address sends `address` to a procedure-scoped
 * tool, and `query` to a search tool. Each pair applies only to an input that
 * declares the canonical key and does not declare the alias itself.
 */
const INPUT_KEY_ALIASES: readonly (readonly [
  alias: string,
  canonical: string,
])[] = [
  ["address", "procedure"],
  ["query", "pattern"],
];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The aliases an object input schema accepts, as alias to canonical key. */
export const inputKeyAliasesFor = (
  schema: unknown,
): Readonly<Record<string, string>> => {
  const shape = isRecord(schema) ? Reflect.get(schema, "shape") : undefined;
  if (!isRecord(shape)) return {};
  return Object.fromEntries(
    INPUT_KEY_ALIASES.filter(
      ([alias, canonical]) =>
        Object.hasOwn(shape, canonical) && !Object.hasOwn(shape, alias),
    ),
  );
};

/**
 * Renames each alias to its canonical key when only the alias is present. An
 * input that carries both keys is left as sent, so strict validation rejects
 * the alias instead of choosing one value.
 */
export const renameInputKeyAliases = (
  value: unknown,
  aliases: Readonly<Record<string, string>>,
): unknown => {
  if (!isRecord(value)) return value;
  let renamed: Record<string, unknown> | undefined;
  for (const [alias, canonical] of Object.entries(aliases)) {
    if (!Object.hasOwn(value, alias) || Object.hasOwn(value, canonical))
      continue;
    renamed ??= { ...value };
    renamed[canonical] = renamed[alias];
    delete renamed[alias];
  }
  return renamed ?? value;
};

/**
 * Accept the input key aliases of a standard schema during validation. The
 * schema keeps its prototype, parser and JSON Schema projection, so clients
 * are still offered only the canonical keys, and the validated value carries
 * the canonical keys that Evidence parameters record.
 */
export const acceptInputKeyAliases = <Schema>(schema: Schema): Schema => {
  const aliases = inputKeyAliasesFor(schema);
  if (Object.keys(aliases).length === 0 || !isRecord(schema)) return schema;
  const standard = Reflect.get(schema, "~standard");
  if (!isRecord(standard)) return schema;
  const validate = Reflect.get(standard, "validate");
  if (typeof validate !== "function") return schema;
  // Registration metadata may define `~standard` as non-configurable, so the
  // wrapper copies every other own property and defines its own interface.
  const { "~standard": _replaced, ...descriptors } =
    Object.getOwnPropertyDescriptors(schema);
  const accepting = Object.create(
    Object.getPrototypeOf(schema),
    descriptors,
  ) as Record<string, unknown>;
  Object.defineProperty(accepting, "~standard", {
    value: {
      ...standard,
      validate: (value: unknown) =>
        Reflect.apply(validate, standard, [
          renameInputKeyAliases(value, aliases),
        ]) as unknown,
    },
  });
  return accepting as Schema;
};
