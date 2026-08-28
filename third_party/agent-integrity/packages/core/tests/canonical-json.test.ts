import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Canonical } from "../src/index.js";

describe("canonical JSON", () => {
  it("sorts object keys recursively while preserving array order", () => {
    expect(canonicalJson({ z: 1, nested: { b: 2, a: 1 }, list: [2, 1] })).toBe(
      '{"list":[2,1],"nested":{"a":1,"b":2},"z":1}'
    );
  });

  it("produces equal hashes for equivalent objects", () => {
    expect(sha256Canonical({ b: "✓", a: 1 })).toBe(sha256Canonical({ a: 1, b: "✓" }));
  });

  it("normalizes negative zero", () => {
    expect(canonicalJson({ value: -0 })).toBe('{"value":0}');
  });

  it.each([NaN, Infinity, -Infinity])("rejects non-finite number %s", (value) => {
    expect(() => canonicalJson({ value })).toThrow(/Non-finite number/);
  });

  it("rejects undefined rather than silently dropping it", () => {
    expect(() => canonicalJson({ value: undefined })).toThrow(/Undefined value/);
  });

  it.each(["__proto__", "constructor", "prototype"])(
    "rejects the dangerous key %s without creating a digest collision",
    (key) => {
      const hostile = JSON.parse(`{"${key}":{"admin":true}}`) as unknown;
      expect(() => canonicalJson(hostile)).toThrow(/Dangerous object key/);
      expect(() => sha256Canonical(hostile)).toThrow(/Dangerous object key/);
    }
  );

  it("rejects class instances and objects with custom prototypes", () => {
    class Hostile { value = 1; }
    expect(() => canonicalJson(new Hostile())).toThrow(/plain JSON object/);
    expect(() => canonicalJson(Object.create({ inherited: true }))).toThrow(/plain JSON object/);
  });

  it("rejects accessors without executing them", () => {
    let executed = false;
    const value = Object.defineProperty({}, "secret", {
      enumerable: true,
      get() {
        executed = true;
        return "leaked";
      },
    });
    expect(() => canonicalJson(value)).toThrow(/Accessor property/);
    expect(executed).toBe(false);
  });

  it("rejects circular and excessively deep input", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => canonicalJson(circular)).toThrow(/Circular reference/);

    let deep: unknown = null;
    for (let index = 0; index < 70; index += 1) deep = [deep];
    expect(() => canonicalJson(deep)).toThrow(/Maximum canonical JSON depth/);
  });
});
