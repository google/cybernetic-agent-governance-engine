#!/usr/bin/env node
import { stdin, stdout } from "node:process";
import { open } from "node:fs/promises";
import {
  FileReceiptStore,
  parsePolicy,
  recheckTrustedReceipt,
  sha256Canonical,
  verifyTrustedEnvelope,
} from "@agent-integrity/core";
import type {
  AlphaIntegrityReceipt,
  IntegrityEnvelope,
  IntegrityStatus,
} from "@agent-integrity/protocol";

type JsonRecord = Record<string, unknown>;
const MAX_STDIN_BYTES = 1024 * 1024;
const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_TRUST_CONFIG_BYTES = 1024 * 1024;
const MAX_PATH_BYTES = 4096;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exitCode(status: IntegrityStatus): number {
  if (status === "PASS") return 0;
  if (status === "REVIEW") return 2;
  return 3;
}

function emit(value: unknown, code: number): never {
  stdout.write(`${JSON.stringify(value)}\n`);
  process.exit(code);
}

function invalidInput(message: string): never {
  return emit({ error: { code: "cli.invalid_input", message } }, 1);
}

async function readRequest(): Promise<JsonRecord> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
    total += bytes.length;
    if (total > MAX_STDIN_BYTES) return invalidInput(`stdin exceeds ${MAX_STDIN_BYTES} bytes`);
    chunks.push(bytes);
  }
  const raw = Buffer.concat(chunks, total).toString("utf8");
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return invalidInput("stdin must contain one valid JSON object");
  }
  if (!isRecord(value)) return invalidInput("stdin must contain one JSON object");
  return value;
}

function optionPath(name: string): string {
  const args = process.argv.slice(3);
  const index = args.indexOf(name);
  const value = index < 0 ? undefined : args[index + 1];
  if (typeof value !== "string" || value.length === 0 || value.startsWith("--") ||
      Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES || args.filter((item) => item === name).length !== 1) {
    return invalidInput(`${name} <path> is required exactly once`);
  }
  return value;
}

async function readTrustedPolicy(): Promise<ReturnType<typeof parsePolicy>> {
  const path = optionPath("--trusted-policy");
  const handle = await open(path, "r");
  try {
    const info = await handle.stat();
    if (info.size > MAX_POLICY_BYTES) return invalidInput(`trusted policy exceeds ${MAX_POLICY_BYTES} bytes`);
    const buffer = Buffer.alloc(MAX_POLICY_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_POLICY_BYTES) return invalidInput(`trusted policy exceeds ${MAX_POLICY_BYTES} bytes`);
    return parsePolicy(buffer.subarray(0, bytesRead).toString("utf8"));
  } catch (error) {
    return invalidInput(error instanceof Error ? error.message : "trusted policy could not be loaded");
  } finally {
    await handle.close();
  }
}

async function readTrustedConfig(): Promise<JsonRecord> {
  const path = optionPath("--trusted-config");
  const handle = await open(path, "r");
  try {
    const info = await handle.stat();
    if (info.size > MAX_TRUST_CONFIG_BYTES) return invalidInput(`trusted config exceeds ${MAX_TRUST_CONFIG_BYTES} bytes`);
    const buffer = Buffer.alloc(MAX_TRUST_CONFIG_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_TRUST_CONFIG_BYTES) return invalidInput(`trusted config exceeds ${MAX_TRUST_CONFIG_BYTES} bytes`);
    const value: unknown = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
    if (!isRecord(value)) return invalidInput("trusted config must contain one JSON object");
    return value;
  } catch (error) {
    return invalidInput(error instanceof Error ? error.message : "trusted config could not be loaded");
  } finally {
    await handle.close();
  }
}

function receiptBody(receipt: AlphaIntegrityReceipt): Omit<AlphaIntegrityReceipt, "receiptDigest"> {
  const { receiptDigest: _receiptDigest, ...body } = receipt;
  return body;
}

async function main(): Promise<never> {
  const command = process.argv[2];
  if (!command || !["validate-policy", "verify", "recheck", "inspect-receipt"].includes(command)) {
    return emit({ error: { code: "cli.unknown_command", message: `Unknown command: ${command ?? ""}` } }, 1);
  }
  const request = await readRequest();

  if (command === "validate-policy") {
    if (typeof request.policy !== "string") return invalidInput("policy must be a YAML string");
    try {
      return emit({ ok: true, policy: parsePolicy(request.policy) }, 0);
    } catch (error) {
      return invalidInput(error instanceof Error ? error.message : "policy validation failed");
    }
  }

  if (command === "verify") {
    if (!("envelope" in request)) return invalidInput("envelope is required");
    const trustedPolicy = await readTrustedPolicy();
    const trustedConfig = await readTrustedConfig();
    const result = await verifyTrustedEnvelope(request.envelope as IntegrityEnvelope, { ...trustedConfig, trustedPolicy } as never);
    return emit(result, exitCode(result.status));
  }

  if (command === "recheck") {
    if (!("receipt" in request) || !("envelope" in request)) return invalidInput("receipt and envelope are required");
    const trustedPolicy = await readTrustedPolicy();
    const trustedConfig = await readTrustedConfig();
    if (!isRecord(trustedConfig.trust)) return invalidInput("trusted config must include trust settings");
    if (typeof trustedConfig.receiptStoreDirectory !== "string" || trustedConfig.receiptStoreDirectory.length === 0 || Buffer.byteLength(trustedConfig.receiptStoreDirectory, "utf8") > MAX_PATH_BYTES) return invalidInput("trusted config must include a bounded receiptStoreDirectory");
    const result = await recheckTrustedReceipt({
      receipt: request.receipt as AlphaIntegrityReceipt,
      envelope: request.envelope as IntegrityEnvelope,
      now: new Date(),
      context: { ...trustedConfig, trustedPolicy } as never,
      trust: { ...trustedConfig.trust, trustedPolicy } as never,
      receiptStore: new FileReceiptStore(trustedConfig.receiptStoreDirectory),
    });
    return emit(result, exitCode(result.status));
  }

  const receipt = request.receipt as AlphaIntegrityReceipt;
  if (!isRecord(receipt)) return invalidInput("receipt must be an object");
  try {
    const calculatedDigest = sha256Canonical(receiptBody(receipt));
    return emit({
      protocolVersion: receipt.protocolVersion,
      receiptVersion: receipt.receiptVersion,
      runId: receipt.runId,
      createdAt: receipt.createdAt,
      expiresAt: receipt.expiresAt,
      status: receipt.verification?.status,
      signatureAlgorithm: receipt.signature?.algorithm,
      keyId: receipt.signature?.keyId,
      receiptDigest: receipt.receiptDigest,
      digestMatches: calculatedDigest === receipt.receiptDigest,
    }, calculatedDigest === receipt.receiptDigest ? 0 : 3);
  } catch (error) {
    return invalidInput(error instanceof Error ? error.message : "receipt inspection failed");
  }
}

void main().catch((error: unknown) => {
  emit({
    error: {
      code: "cli.internal_error",
      message: error instanceof Error ? error.message : "internal CLI failure",
    },
  }, 1);
});
