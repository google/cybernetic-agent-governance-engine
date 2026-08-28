const MAX_DEPTH = 64;
const MAX_NODES = 100_000;
const MAX_STRING_BYTES = 16 * 1024 * 1024;
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

interface State {
  readonly ancestors: Set<object>;
  nodes: number;
}

function enter(state: State, value: object, path: string, depth: number): void {
  if (depth > MAX_DEPTH) throw new TypeError(`Maximum canonical JSON depth exceeded at ${path}`);
  state.nodes += 1;
  if (state.nodes > MAX_NODES) throw new TypeError(`Maximum canonical JSON node count exceeded at ${path}`);
  if (state.ancestors.has(value)) throw new TypeError(`Circular reference at ${path}`);
  state.ancestors.add(value);
}

function serialize(value: unknown, path: string, depth: number, state: State): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);

  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES) {
      throw new TypeError(`Maximum canonical JSON string size exceeded at ${path}`);
    }
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite number at ${path}`);
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }

  if (Array.isArray(value)) {
    enter(state, value, path, depth);
    try {
      return `[${value.map((entry, index) => serialize(entry, `${path}[${index}]`, depth + 1, state)).join(",")}]`;
    } finally {
      state.ancestors.delete(value);
    }
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`Expected plain JSON object at ${path}`);
    }
    enter(state, value, path, depth);
    try {
      const record = value as Record<string, unknown>;
      const entries: string[] = [];
      for (const key of Object.keys(record).sort()) {
        if (DANGEROUS_KEYS.has(key)) throw new TypeError(`Dangerous object key at ${path}.${key}`);
        const descriptor = Object.getOwnPropertyDescriptor(record, key);
        if (!descriptor || !("value" in descriptor)) {
          throw new TypeError(`Accessor property is not supported at ${path}.${key}`);
        }
        if (descriptor.value === undefined) throw new TypeError(`Undefined value at ${path}.${key}`);
        entries.push(`${JSON.stringify(key)}:${serialize(descriptor.value, `${path}.${key}`, depth + 1, state)}`);
      }
      return `{${entries.join(",")}}`;
    } finally {
      state.ancestors.delete(value);
    }
  }

  if (value === undefined) throw new TypeError(`Undefined value at ${path}`);
  throw new TypeError(`Unsupported value at ${path}`);
}

export function canonicalJson(value: unknown): string {
  return serialize(value, "$", 0, { ancestors: new Set(), nodes: 0 });
}
