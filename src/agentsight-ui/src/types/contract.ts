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

import { z } from 'zod';

/**
 * GOVERNANCE_VIOLATION: Zero-Trust Contract
 * When this code is received, the React frontend must trigger a 
 * High-Severity Security Alert / Modal.
 */
export const GovernanceCodeSchema = z.enum([
    "GOVERNANCE_VIOLATION",
    "BAD_REQUEST",
    "UNAUTHORIZED",
    "INTERNAL_ERROR"
]);

export type GovernanceCode = z.infer<typeof GovernanceCodeSchema>;

export const ApiResponseSchema = z.object({
    success: z.boolean(),
    data: z.any().optional(),
    error: z.string().optional(),
    code: GovernanceCodeSchema.optional(),
    timestamp: z.string().optional()
});

export type ApiResponse = z.infer<typeof ApiResponseSchema>;
