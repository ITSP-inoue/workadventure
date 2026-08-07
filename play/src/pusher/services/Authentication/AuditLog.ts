/**
 * Audit logging for Google Workspace authentication attempts (spec-kit-practice#1, FR-009).
 *
 * Deliberately typed so a raw ID token / access token cannot be passed in: the event
 * shape only carries the fields spec.md allows in the audit trail (subject, domain,
 * result, timestamp).
 */

export type AuthenticationAttemptResult = "allowed" | "denied";

export interface AuthenticationAttemptEvent {
    readonly result: AuthenticationAttemptResult;
    /** hd claim presented by the identity token, or null if absent (e.g. personal Gmail). */
    readonly domain: string | null;
    /** Stable user identifier (the token's `sub` claim), not the raw token. */
    readonly subject: string | null;
    readonly timestamp?: Date;
}

export interface AuthenticationAttemptLogRecord {
    readonly event: "google_workspace_auth_attempt";
    readonly result: AuthenticationAttemptResult;
    readonly domain: string | null;
    readonly subject: string | null;
    readonly timestamp: string;
}

export function toAuditLogRecord(attempt: AuthenticationAttemptEvent): AuthenticationAttemptLogRecord {
    return {
        event: "google_workspace_auth_attempt",
        result: attempt.result,
        domain: attempt.domain,
        subject: attempt.subject,
        timestamp: (attempt.timestamp ?? new Date()).toISOString(),
    };
}

/**
 * Writes one structured audit line to stdout, matching the pusher service's existing
 * console-based logging (no new persistent storage required for this feature).
 */
export function logAuthenticationAttempt(attempt: AuthenticationAttemptEvent): void {
    console.log(JSON.stringify(toAuditLogRecord(attempt)));
}
