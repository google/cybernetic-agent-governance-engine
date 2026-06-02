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

import { useState, useEffect, useRef } from 'react';
import './KernelDashboard.css';
import type { GovernanceCode } from './types/contract';

// ---------------------------------------------------------------------------
// Types — mirror ComplianceMetrics from src/compliance_bridge/types.py
// ---------------------------------------------------------------------------

interface ComplianceMetrics {
    control_id: string;
    safety_rate: number;
    total_traces: number;
    blocked_traces: number;
    passed_traces: number;
    window_hours: number;
    last_event_utc: string;
    evidence_age_seconds: number;
    startup_grace_active: boolean;
    startup_grace_remaining_hours: number;
}

interface HealthResponse {
    status: string;
    service: string;
    version: string;
}

// Telemetry item shape consumed by the existing UI list
interface TelemetryItem {
    id: string;
    traceId: string;
    spanName: string;
    timestamp: string;
    safetyRate: number;
    totalTraces: number;
    blockedTraces: number;
    type?: 'AUDIT_FINDING' | 'GOVERNANCE_VIOLATION' | 'REMEDIATION_GENERATED';
    result?: 'PASS' | 'FAIL' | 'NOT_APPLICABLE' | null;
    auditId?: string;
    modelName?: string;
    textLength?: number;
}

// GovernanceEvent — shape of SSE `governance-event` payloads from the backend.
// Mirrors GovernanceEvent in src/compliance_bridge_ts/src/events.ts.
interface GovernanceEvent {
    type: 'AUDIT_FINDING' | 'GOVERNANCE_VIOLATION' | 'REMEDIATION_GENERATED';
    traceId: string;
    controlId: string;
    result: 'PASS' | 'FAIL' | 'NOT_APPLICABLE' | null;
    safetyRate: number | null;
    auditId: string;
    timestamp: string;
    modelName?: string;
    textLength?: number;
}

// SSE connection state — drives the colored status dot in the header.
type ConnectionStatus = 'connecting' | 'connected' | 'error';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// The compliance-bridge exposes these four ISO 42001 control IDs.
// Order matches SUPPORTED_CONTROLS in src/compliance_bridge/types.py.
const CONTROL_IDS = ['A.5.2', 'A.5.3', 'A.9.2', 'SC-4'] as const;

// Human-readable names matching CONTROL_META in types.py
const CONTROL_NAMES: Record<string, string> = {
    'A.5.2': 'Social Impact Assessment',
    'A.5.3': 'Logging and Monitoring',
    'A.9.2': 'Data Transfer to Suppliers',
    'SC-4':  'Fiscal Limits and RBAC',
};

// Controls that require an immediate GOVERNANCE_VIOLATION alert on low safety
// Mirrors CRITICAL_CONTROLS in src/compliance_bridge/types.py
const CRITICAL_CONTROLS = new Set(['A.9.2', 'SC-4']);

// Safety threshold below which a critical control triggers an alert
const ALERT_THRESHOLD = 0.8;

// Polling interval in milliseconds (5 seconds) — used as fallback only
const POLL_INTERVAL_MS = 5_000;

// All REST requests go through the Vite dev-server proxy (/api → http://127.0.0.1:3001)
const API_BASE = '/api';

// SSE backend URL — reads from the Vite env variable, falls back to localhost.
// The /v1/events/stream path is proxied through Vite's server.proxy config.
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:3002';

// ---------------------------------------------------------------------------
// Fetch helpers (unchanged from original — used by the polling fallback)
// ---------------------------------------------------------------------------

async function fetchHealth(): Promise<HealthResponse> {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`/health responded ${res.status}`);
    return res.json() as Promise<HealthResponse>;
}

async function fetchMetrics(controlId: string): Promise<ComplianceMetrics> {
    const res = await fetch(`${API_BASE}/v1/metrics/${encodeURIComponent(controlId)}`);
    if (!res.ok) throw new Error(`/v1/metrics/${controlId} responded ${res.status}`);
    return res.json() as Promise<ComplianceMetrics>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const KernelDashboard: React.FC = () => {
    const [telemetry, setTelemetry]               = useState<TelemetryItem[]>([]);
    const [health, setHealth]                     = useState<HealthResponse | null>(null);
    const [loading, setLoading]                   = useState<boolean>(true);
    const [fetchError, setFetchError]             = useState<string | null>(null);
    const [securityAlert, setSecurityAlert]       = useState<{ message: string; code: GovernanceCode } | null>(null);
    const [patchAdvisory, setPatchAdvisory]       = useState<{ message: string; modelName: string; size: number } | null>(null);
    const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting');
    const [selectedItem, setSelectedItem]         = useState<TelemetryItem | null>(null);

    // Pagination states
    const [page, setPage]                         = useState<number>(1);
    const [hasMore, setHasMore]                   = useState<boolean>(true);
    const [loadingMore, setLoadingMore]           = useState<boolean>(false);
    const [beforeTimestamp]                       = useState<string>(() => new Date().toISOString());

    // Track which critical-control alerts have already been shown this session
    // so we don't re-raise the same modal on every poll cycle.
    const alertedControls = useRef<Set<string>>(new Set());

    const fetchHistory = async (pageNum: number, cursor: string) => {
        if (pageNum === 1) {
            setLoading(true);
        } else {
            setLoadingMore(true);
        }

        try {
            const url = `${BACKEND_URL}/v1/telemetry/history?page=${pageNum}&limit=20&before_timestamp=${encodeURIComponent(cursor)}`;
            const res = await fetch(url);
            if (!res.ok) throw new Error(`History fetch responded ${res.status}`);
            const data = await res.json();
            
            if (data && Array.isArray(data.telemetry)) {
                setTelemetry((prev) => {
                    const existingIds = new Set(prev.map(item => item.id || item.traceId));
                    const uniqueHistory = data.telemetry.filter(
                        (item: TelemetryItem) => !existingIds.has(item.id) && !existingIds.has(item.traceId)
                    );
                    const merged = [...prev, ...uniqueHistory];
                    return merged.slice(0, 100);
                });
                
                setHasMore(data.hasMore);
                setPage(pageNum);
            }
        } catch (err) {
            console.error('[KernelDashboard] Error fetching telemetry history:', err);
            setFetchError(err instanceof Error ? err.message : 'Failed to load telemetry history');
        } finally {
            setLoading(false);
            setLoadingMore(false);
        }
    };

    const loadNextPage = () => {
        if (loadingMore || !hasMore) return;
        fetchHistory(page + 1, beforeTimestamp);
    };

    // -----------------------------------------------------------------------
    // SSE effect — primary real-time data source
    // Falls back to polling if EventSource is not supported by the browser.
    // -----------------------------------------------------------------------

    useEffect(() => {
        // ---- Fallback: polling via setInterval (legacy / non-SSE browsers) ----
        if (typeof EventSource === 'undefined') {
            console.warn('[KernelDashboard] EventSource not supported — falling back to polling');

            let cancelled = false;

            async function poll() {
                try {
                    const healthData = await fetchHealth();
                    if (!cancelled) setHealth(healthData);

                    const results = await Promise.allSettled(
                        CONTROL_IDS.map((id) => fetchMetrics(id))
                    );

                    if (cancelled) return;

                    const items: TelemetryItem[] = [];
                    for (let i = 0; i < results.length; i++) {
                        const result = results[i];
                        const controlId = CONTROL_IDS[i];
                        if (result.status === 'fulfilled') {
                            const m = result.value;
                            items.push({
                                id:            m.control_id,
                                traceId:       m.control_id,
                                spanName:      CONTROL_NAMES[m.control_id] ?? m.control_id,
                                timestamp:     m.last_event_utc,
                                safetyRate:    m.safety_rate,
                                totalTraces:   m.total_traces,
                                blockedTraces: m.blocked_traces,
                                type:          'AUDIT_FINDING',
                                result:        m.safety_rate >= 1.0 ? 'PASS' : 'FAIL',
                                auditId:       `poll-window-${m.window_hours}h`,
                            });

                            if (
                                CRITICAL_CONTROLS.has(m.control_id) &&
                                m.safety_rate < ALERT_THRESHOLD &&
                                !alertedControls.current.has(m.control_id)
                            ) {
                                alertedControls.current.add(m.control_id);
                                setSecurityAlert({
                                    message: (
                                        `Control ${m.control_id} (${CONTROL_NAMES[m.control_id] ?? m.control_id}): ` +
                                        `safety_rate=${(m.safety_rate * 100).toFixed(1)}% is below the ` +
                                        `${(ALERT_THRESHOLD * 100).toFixed(0)}% threshold. ` +
                                        `${m.blocked_traces} of ${m.total_traces} traces were blocked in the last ` +
                                        `${m.window_hours}h window. This incident has been logged by the compliance bridge.`
                                    ),
                                    code: 'GOVERNANCE_VIOLATION',
                                });
                            }

                            if (
                                CRITICAL_CONTROLS.has(m.control_id) &&
                                m.safety_rate >= ALERT_THRESHOLD
                            ) {
                                alertedControls.current.delete(m.control_id);
                            }
                        } else {
                            items.push({
                                id:            controlId,
                                traceId:       controlId,
                                spanName:      `${CONTROL_NAMES[controlId] ?? controlId} [fetch error]`,
                                timestamp:     new Date().toISOString(),
                                safetyRate:    -1,
                                totalTraces:   0,
                                blockedTraces: 0,
                            });
                        }
                    }

                    setTelemetry(items);
                    setFetchError(null);
                } catch (err) {
                    if (!cancelled) {
                        setFetchError(
                            err instanceof Error ? err.message : 'Unknown error contacting compliance-bridge'
                        );
                    }
                } finally {
                    if (!cancelled) setLoading(false);
                }
            }

            poll();
            const handle = setInterval(poll, POLL_INTERVAL_MS);

            return () => {
                cancelled = true;
                clearInterval(handle);
            };
        }

        // ---- Primary path: real SSE connection to the Hono backend ----

        fetchHistory(1, beforeTimestamp);

        setConnectionStatus('connecting');

        const eventSource = new EventSource(`${BACKEND_URL}/v1/events/stream`);

        // Once the connection opens, mark as connected and stop the loading spinner.
        eventSource.onopen = () => {
            console.info('[KernelDashboard] SSE connection established.');
            setConnectionStatus('connected');
            setLoading(false);
            setFetchError(null);
        };

        // Handle incoming governance-event messages from the backend.
        eventSource.addEventListener('governance-event', (e: MessageEvent) => {
            let event: GovernanceEvent;
            try {
                event = JSON.parse(e.data) as GovernanceEvent;
            } catch (parseErr) {
                console.warn('[KernelDashboard] Failed to parse governance-event:', parseErr, e.data);
                return;
            }

            // Map the incoming GovernanceEvent to a TelemetryItem for the list.
            const item: TelemetryItem = {
                id:            `${event.auditId}-${event.controlId}-${event.timestamp}`,
                traceId:       event.traceId,
                spanName:      CONTROL_NAMES[event.controlId] ?? event.controlId,
                timestamp:     event.timestamp,
                safetyRate:    event.safetyRate ?? -1,
                totalTraces:   0,   // not available in push events; set to 0
                blockedTraces: 0,
                type:          event.type,
                result:        event.result,
                auditId:       event.auditId,
                modelName:     event.modelName,
                textLength:    event.textLength,
            };

            setTelemetry((prev) => {
                // Prepend newest events; filter duplicates, cap list at 100 items.
                if (prev.some(p => p.id === item.id || (item.traceId && p.traceId === item.traceId))) {
                    return prev;
                }
                const updated = [item, ...prev];
                return updated.slice(0, 100);
            });

            // GOVERNANCE_VIOLATION → trigger the security alert modal.
            if (event.type === 'GOVERNANCE_VIOLATION') {
                const controlName = CONTROL_NAMES[event.controlId] ?? event.controlId;
                const alertKey    = `${event.auditId}-${event.controlId}`;

                if (!alertedControls.current.has(alertKey)) {
                    alertedControls.current.add(alertKey);
                    const safetyPct = event.safetyRate !== null
                        ? `${(event.safetyRate * 100).toFixed(1)}%`
                        : 'unknown';

                    setSecurityAlert({
                        message: (
                            `Control ${event.controlId} (${controlName}): ` +
                            `safety_rate=${safetyPct} triggered a GOVERNANCE_VIOLATION. ` +
                            `Audit ID: ${event.auditId}. ` +
                            `This incident has been logged by the compliance bridge.`
                        ),
                        code: 'GOVERNANCE_VIOLATION',
                    });
                }
            } else if (event.type === 'REMEDIATION_GENERATED') {
                const controlName = CONTROL_NAMES[event.controlId] ?? event.controlId;
                setPatchAdvisory({
                    message: `Diagnostic patch advisory generated for ${event.controlId} (${controlName}). Applied safely via automated remediation workflow.`,
                    modelName: event.modelName ?? 'local vLLM',
                    size: event.textLength ?? 0,
                });
            }

            // Heartbeat events — no UI action needed, just keep the connection alive.
        });

        // Handle heartbeat — already handled by EventSource staying open; log for debug.
        eventSource.addEventListener('heartbeat', () => {
            console.debug('[KernelDashboard] SSE heartbeat received.');
        });

        // Handle connection errors.
        eventSource.onerror = (err) => {
            console.error('[KernelDashboard] SSE connection error:', err);
            setConnectionStatus('error');
            setFetchError('SSE connection to backend lost — attempting to reconnect…');
            // EventSource automatically attempts to reconnect on error.
        };

        // Also attempt an initial health fetch so the header badge is populated.
        fetchHealth()
            .then((h) => setHealth(h))
            .catch((err) =>
                console.warn('[KernelDashboard] Initial health fetch failed:', err)
            );

        // Cleanup: close the EventSource when the component unmounts.
        return () => {
            eventSource.close();
            console.info('[KernelDashboard] SSE connection closed (component unmounted).');
        };
    }, []);

    // -----------------------------------------------------------------------
    // Render
    // -----------------------------------------------------------------------

    return (
        <div className="dashboard-layout">
            {/* ------------------------------------------------------------------ */}
            {/* SSE Connection status indicator (top-right corner)                */}
            {/* ------------------------------------------------------------------ */}
            <div className="connection-status">
                <span
                    className={`connection-dot ${connectionStatus}`}
                    title={
                        connectionStatus === 'connected'  ? 'SSE connected' :
                        connectionStatus === 'connecting' ? 'Connecting…'   :
                        'Connection error'
                    }
                />
                <span>
                    {connectionStatus === 'connected'  ? 'Live' :
                     connectionStatus === 'connecting' ? 'Connecting…' :
                     'Disconnected'}
                </span>
            </div>

            {/* ------------------------------------------------------------------ */}
            {/* Governance violation modal — same layout as original               */}
            {/* ------------------------------------------------------------------ */}
            {securityAlert && (
                <div className="security-alert-overlay">
                    <div className="security-alert-modal">
                        <div className="alert-header">
                            <span className="alert-icon">🚨</span>
                            <h2>SYSTEM GOVERNANCE VIOLATION</h2>
                        </div>
                        <div className="alert-body">
                            <p className="error-code">CODE: {securityAlert.code}</p>
                            <p className="error-message">{securityAlert.message}</p>
                            <p className="warning-text">
                                This incident has been logged and the transaction has been blocked
                                to maintain environment integrity.
                            </p>
                        </div>
                        <button
                            className="alert-close"
                            onClick={() => setSecurityAlert(null)}
                        >
                            ACKNOWLEDGE &amp; DISMISS
                        </button>
                    </div>
                </div>
            )}

            {/* ------------------------------------------------------------------ */}
            {/* Diagnostic Patch Advisory Modal                                    */}
            {/* ------------------------------------------------------------------ */}
            {patchAdvisory && (
                <div className="security-alert-overlay">
                    <div className="security-alert-modal" style={{ borderTop: '4px solid #44cc88' }}>
                        <div className="alert-header">
                            <span className="alert-icon">🛠️</span>
                            <h2 style={{ color: '#44cc88' }}>DIAGNOSTIC PATCH ADVISORY</h2>
                        </div>
                        <div className="alert-body">
                            <p className="error-code" style={{ color: '#44cc88' }}>MODEL: {patchAdvisory.modelName}</p>
                            <p className="error-message">{patchAdvisory.message}</p>
                            <p className="warning-text">
                                A {patchAdvisory.size}-byte remediation patch has been automatically generated and applied without polling.
                            </p>
                        </div>
                        <button
                            className="alert-close"
                            style={{ backgroundColor: '#44cc88' }}
                            onClick={() => setPatchAdvisory(null)}
                        >
                            ACKNOWLEDGE
                        </button>
                    </div>
                </div>
            )}

            {/* ------------------------------------------------------------------ */}
            {/* Sidebar / Left Column                                              */}
            {/* ------------------------------------------------------------------ */}
            <div className="sidebar-pane">
                <h1>CAGE Governance Dashboard</h1>
                <p className="subtitle">
                    AI Compliance & Safety Telemetry
                    {health && (
                        <span className="health-badge" title={`${health.service} v${health.version}`}>
                            {' '}— {health.service} {health.status === 'ok' ? '✅' : '⚠️'}
                        </span>
                    )}
                </p>

                {loading && (
                    <p className="loading-indicator" aria-live="polite">
                        ⏳ Connecting to compliance-bridge…
                    </p>
                )}

                {fetchError && !loading && (
                    <div className="fetch-error-banner" role="alert">
                        ⚠️ Backend unreachable: {fetchError}
                    </div>
                )}

                {!loading && (
                    <ul>
                        {telemetry.map((t) => (
                            <li 
                                key={t.id} 
                                className={`telemetry-item ${selectedItem?.id === t.id ? 'selected' : ''}`}
                                onClick={() => setSelectedItem(t)}
                            >
                                <span className="trace-id">{t.traceId || 'N/A'}</span>
                                {' — '}
                                <span className="span-name">{t.spanName}</span>
                                {t.safetyRate >= 0 && (
                                    <span
                                        className="safety-rate"
                                        title={`${t.totalTraces} total traces, ${t.blockedTraces} blocked`}
                                        style={{ color: t.safetyRate < ALERT_THRESHOLD ? '#ff4444' : '#44cc88' }}
                                    >
                                        {' '}[{(t.safetyRate * 100).toFixed(1)}% safe]
                                    </span>
                                )}
                                <span className="timestamp">{t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : ''}</span>
                            </li>
                        ))}
                        {hasMore && telemetry.length > 0 && (
                            <li className="load-more-item" style={{ listStyleType: 'none', textAlign: 'center', margin: '10px 0' }}>
                                <button className="load-more-btn" onClick={loadNextPage} disabled={loadingMore} style={{ padding: '8px 16px', background: '#333', color: '#fff', border: '1px solid #555', cursor: 'pointer', borderRadius: '4px' }}>
                                    {loadingMore ? '⏳ Loading...' : 'Load More Historical Telemetry'}
                                </button>
                            </li>
                        )}
                        {!loading && telemetry.length === 0 && !fetchError && (
                            <li className="telemetry-item">No compliance data available yet.</li>
                        )}
                    </ul>
                )}
            </div>

            {/* ------------------------------------------------------------------ */}
            {/* Drill-down details pane / Right Column                             */}
            {/* ------------------------------------------------------------------ */}
            <div className="details-pane">
                {selectedItem ? (
                    <div className="details-card">
                        <div className="details-header">
                            <h2>Trace Inspection</h2>
                            <span className={`event-type-badge ${selectedItem.type || 'AUDIT_FINDING'}`}>
                                {selectedItem.type || 'AUDIT_FINDING'}
                            </span>
                        </div>

                        <div className="section">
                            <h3>Identity &amp; Origin</h3>
                            <div className="meta-grid">
                                <div className="meta-label">Control ID:</div>
                                <div className="meta-value control-id-value">
                                    <code>{selectedItem.id.split('-')[1] || selectedItem.id}</code>
                                    <span className="control-desc">— {selectedItem.spanName}</span>
                                </div>

                                <div className="meta-label">Audit ID:</div>
                                <div className="meta-value font-mono">{selectedItem.auditId || 'N/A'}</div>

                                <div className="meta-label">Trace ID:</div>
                                <div className="meta-value font-mono trace-link-wrapper">
                                    <code>{selectedItem.traceId || 'N/A'}</code>
                                    {selectedItem.traceId && (
                                        <a 
                                            href={`http://localhost:3001/project/cage-compliance/traces/${selectedItem.traceId}`}
                                            target="_blank"
                                            rel="noreferrer"
                                            className="langfuse-trace-btn"
                                            title="Inspect details and CoT traces inside Langfuse UI"
                                        >
                                            🔍 Open in Langfuse
                                        </a>
                                    )}
                                </div>

                                <div className="meta-label">Timestamp:</div>
                                <div className="meta-value">
                                    {selectedItem.timestamp ? new Date(selectedItem.timestamp).toLocaleString() : 'N/A'}
                                </div>
                            </div>
                        </div>

                        <div className="section">
                            <h3>Assertion Result</h3>
                            <div className="result-display">
                                <div className="metric-box">
                                    <span className="metric-label">Postured State</span>
                                    <span className={`result-badge ${selectedItem.result || (selectedItem.safetyRate >= ALERT_THRESHOLD ? 'PASS' : 'FAIL')}`}>
                                        {selectedItem.result || (selectedItem.safetyRate >= ALERT_THRESHOLD ? 'PASS' : 'FAIL')}
                                    </span>
                                </div>

                                <div className="metric-box">
                                    <span className="metric-label">Safety Rate</span>
                                    <span 
                                        className="metric-value"
                                        style={{ color: selectedItem.safetyRate < ALERT_THRESHOLD ? '#ff4444' : '#44cc88' }}
                                    >
                                        {selectedItem.safetyRate >= 0 ? `${(selectedItem.safetyRate * 100).toFixed(1)}%` : 'N/A'}
                                    </span>
                                </div>
                            </div>

                            {selectedItem.safetyRate >= 0 && (
                                <div className="progress-bar-container">
                                    <div 
                                        className="progress-bar-fill"
                                        style={{ 
                                            width: `${selectedItem.safetyRate * 100}%`,
                                            backgroundColor: selectedItem.safetyRate < ALERT_THRESHOLD ? '#ff4444' : '#44cc88'
                                        }}
                                    />
                                </div>
                            )}
                        </div>

                        {selectedItem.modelName && (
                            <div className="section">
                                <h3>Remediation Context</h3>
                                <div className="meta-grid">
                                    <div className="meta-label">Generator Model:</div>
                                    <div className="meta-value font-mono">{selectedItem.modelName}</div>

                                    <div className="meta-label">Patch Size:</div>
                                    <div className="meta-value">{selectedItem.textLength || 0} bytes</div>
                                </div>
                            </div>
                        )}

                        <div className="section">
                            <h3>Symbolic Policy Rules (Rego &amp; OPA)</h3>
                            <p className="policy-intro">
                                This trace was dynamically validated against the following compiled CAGE symbolic guardrails:
                            </p>
                            <pre className="policy-code">
{selectedItem.id.includes('SC-4') ? 
`# ISO 42001 SC-4: Fiscal Limits & RBAC Enforcer
package cage.policy.fiscal_limits

default allow = false

# Allow if trade is within bounds and user is authorized advisor
allow {
    input.role == "governed-financial-advisor"
    input.amount <= 10000
    input.currency == "USD"
}

# Audit trail logging for non-compliant intents
audit_finding[msg] {
    not allow
    msg := sprintf("CRITICAL LIMIT EXCEEDED: Transaction of %d %s proposed by %s blocked.", [input.amount, input.currency, input.role])
}`
: selectedItem.id.includes('A.9.2') ?
`# ISO 42001 A.9.2: Data Transfer to Suppliers / PII Redaction
package cage.policy.data_privacy

default safe_transfer = true

# Block if raw SSN or Credit Card structures are leaked in supplier payload
safe_transfer = false {
    re_match("[0-9]{3}-[0-9]{2}-[0-9]{4}", input.payload)
}

safe_transfer = false {
    re_match("[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}", input.payload)
}

audit_finding[msg] {
    not safe_transfer
    msg := "PRIVACY VIOLATION: Trace contains unredacted supplier PII; data block active."
}`
: selectedItem.id.includes('A.5.3') ?
`# ISO 42001 A.5.3: Logging & Monitoring Observability Guard
package cage.policy.observability

default logging_active = true

# Require that trace telemetry contains active spans & Langfuse project key
logging_active = false {
    not input.has_active_spans
}

logging_active = false {
    not input.has_langfuse_project_secret
}`
: 
`# General CAGE Compliance Policy Guard
package cage.policy.general

default compliant = true

# Asserts world-model integrity using DoWhy causal inference
compliant = false {
    input.causal_refutation_failed == true
}`}
                            </pre>
                        </div>
                    </div>
                ) : (
                    <div className="empty-details-card">
                        <div className="empty-icon">🔍</div>
                        <h3>Select a Telemetry Trace</h3>
                        <p>
                            Click any event from the real-time feed on the left to drill down into 
                            trace assertions, safety scores, policy rules, and deep observability links.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default KernelDashboard;
