/**
 * Extracts the claims AllowedDomainValidator needs from a Google ID token payload.
 *
 * Technical constraint found while investigating this feature (spec-kit-practice#1,
 * T003 / PR #37): Google's UserInfo endpoint — what OpenIDClient.getUserInfo() calls
 * today — does not return the `hd` (hosted domain) claim; only the ID token itself
 * carries it. Callers must therefore pass this function the object returned by the
 * openid-client TokenSet's own `claims()` method (already signature- and
 * expiry-verified by openid-client), not the result of getUserInfo().
 *
 * `hd` is the only claim treated as authoritative for domain matching (FR-004) — the
 * email suffix is never used as a substitute, since it can diverge from `hd` for
 * spoofed or non-Workspace accounts.
 */

export interface GoogleWorkspaceClaims {
    readonly sub: string | null;
    readonly email: string | null;
    /** Present only for Google Workspace accounts; absent for personal Gmail. */
    readonly hostedDomain: string | null;
}

function readOptionalString(payload: Record<string, unknown>, key: string): string | null {
    const value = payload[key];
    return typeof value === "string" && value.trim() !== "" ? value : null;
}

export function extractGoogleWorkspaceClaims(payload: Record<string, unknown>): GoogleWorkspaceClaims {
    return {
        sub: readOptionalString(payload, "sub"),
        email: readOptionalString(payload, "email"),
        hostedDomain: readOptionalString(payload, "hd"),
    };
}
