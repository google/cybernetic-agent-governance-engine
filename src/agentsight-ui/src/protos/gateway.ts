/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export interface Message {
    /** "user" | "assistant" | "system" */
    role: string;
    content: string;
}

export function createMessage(partial?: Partial<Message>): Message {
    return {
        role:    partial?.role    ?? '',
        content: partial?.content ?? '',
    };
}

/**
 * message ChatRequest
 * Sent by the client to start a streaming chat.
 */
export interface ChatRequest {
    model: string;
    messages: Message[];
    temperature: number;
    /** Prepended system prompt */
    systemInstruction: string;
    /** "planner" (streaming) or "verifier" (blocking/deterministic) */
    mode: string;
    /** JSON Schema string for FSM-guided output */
    guidedJson: string;
    guidedRegex: string;
    /** JSON list string for guided choice */
    guidedChoice: string;
}

export function createChatRequest(partial?: Partial<ChatRequest>): ChatRequest {
    return {
        model:             partial?.model             ?? '',
        messages:          partial?.messages          ?? [],
        temperature:       partial?.temperature       ?? 0,
        systemInstruction: partial?.systemInstruction ?? '',
        mode:              partial?.mode              ?? '',
        guidedJson:        partial?.guidedJson        ?? '',
        guidedRegex:       partial?.guidedRegex       ?? '',
        guidedChoice:      partial?.guidedChoice      ?? '',
    };
}

/**
 * message ChatResponse
 * A single streaming chunk from the gateway.
 */
export interface ChatResponse {
    content: string;
    /** True on the final chunk of the response */
    isFinal: boolean;
    /** Token usage — populated on the final chunk */
    inputTokens: number;
    outputTokens: number;
}

export function createChatResponse(partial?: Partial<ChatResponse>): ChatResponse {
    return {
        content:      partial?.content      ?? '',
        isFinal:      partial?.isFinal      ?? false,
        inputTokens:  partial?.inputTokens  ?? 0,
        outputTokens: partial?.outputTokens ?? 0,
    };
}

/**
 * message ToolRequest
 * Agent requests tool execution via the gateway.
 */
export interface ToolRequest {
    toolName: string;
    /** JSON-serialised arguments */
    paramsJson: string;
}

export function createToolRequest(partial?: Partial<ToolRequest>): ToolRequest {
    return {
        toolName:   partial?.toolName   ?? '',
        paramsJson: partial?.paramsJson ?? '',
    };
}

/**
 * message ToolResponse
 * Gateway result after running the tool (with governance applied).
 */
export interface ToolResponse {
    output: string;
    /** Empty on success */
    error: string;
    /** "SUCCESS" | "ERROR" | "BLOCKED" */
    status: string;
}

export function createToolResponse(partial?: Partial<ToolResponse>): ToolResponse {
    return {
        output: partial?.output ?? '',
        error:  partial?.error  ?? '',
        status: partial?.status ?? '',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Package: governance
// Source:  gateway_protos/nemo.proto
// ─────────────────────────────────────────────────────────────────────────────

/**
 * message VerifyRequest
 * Input submitted to the NeMo Guardrails verifier.
 */
export interface VerifyRequest {
    input: string;
    /** Optional JSON-serialised context dictionary */
    contextJson: string;
}

export function createVerifyRequest(partial?: Partial<VerifyRequest>): VerifyRequest {
    return {
        input:       partial?.input       ?? '',
        contextJson: partial?.contextJson ?? '',
    };
}

/**
 * message VerifyResponse
 * Result from the NeMo Guardrails rail check.
 */
export interface VerifyResponse {
    /** The sanitised response or the original input unchanged */
    response: string;
    /** "SUCCESS" | "BLOCKED" */
    status: string;
}

export function createVerifyResponse(partial?: Partial<VerifyResponse>): VerifyResponse {
    return {
        response: partial?.response ?? '',
        status:   partial?.status   ?? '',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Service type stubs
// These describe the RPC surface; the actual gRPC transport is handled by
// the gateway_protos/gateway_pb2_grpc.py / gateway_pb2.py Python layer.
// The UI communicates via HTTP+JSON REST or WebSocket, not raw gRPC.
// These are retained for type documentation only.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * service Gateway  (gateway.proto)
 *
 *   rpc Chat (ChatRequest) returns (stream ChatResponse) {}
 *   rpc ExecuteTool (ToolRequest) returns (ToolResponse) {}
 */
export type GatewayService = {
    Chat:        (req: ChatRequest)  => AsyncIterable<ChatResponse>;
    ExecuteTool: (req: ToolRequest)  => Promise<ToolResponse>;
};

/**
 * service NeMoGuardrails  (nemo.proto)
 *
 *   rpc Verify (VerifyRequest) returns (VerifyResponse) {}
 */
export type NeMoGuardrailsService = {
    Verify: (req: VerifyRequest) => Promise<VerifyResponse>;
};
