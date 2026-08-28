import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";

export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
