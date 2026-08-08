/**
 * Decides whether a Google Workspace account may authenticate, based on its `hd`
 * (hosted domain) claim (spec-kit-practice#1, FR-002, FR-003, FR-004, FR-011).
 *
 * When ALLOWED_GOOGLE_WORKSPACE_DOMAINS is empty (the default), the feature is
 * disabled and every account is allowed through unchanged — this must stay a strict
 * opt-in so existing anonymous/ADMIN_API_URL login flows are unaffected.
 */

import { ALLOWED_GOOGLE_WORKSPACE_DOMAINS } from "../../enums/EnvironmentVariable";

export interface AllowedDomainCheckResult {
    readonly allowed: boolean;
    /** The hd claim as presented by the token; not re-normalized, for audit logging. */
    readonly domain: string | null;
}

/**
 * A genuine Google-issued token for a Workspace account always has the email's domain
 * suffix equal to `hd`. A mismatch indicates either a non-Google/misconfigured IdP
 * response or client-side tampering, so it is treated as suspicious regardless of
 * what the (possibly forged) `hd` value itself says (spec.md Edge Cases: "なりすまし・
 * 表記ゆれ").
 */
function emailMatchesHostedDomain(email: string, hostedDomain: string): boolean {
    const atIndex = email.lastIndexOf("@");
    if (atIndex === -1) {
        return false;
    }
    const emailDomain = email.slice(atIndex + 1).toLowerCase();
    return emailDomain === hostedDomain.toLowerCase();
}

export class AllowedDomainValidator {
    constructor(private readonly allowedDomains: readonly string[] = ALLOWED_GOOGLE_WORKSPACE_DOMAINS) {}

    get isEnabled(): boolean {
        return this.allowedDomains.length > 0;
    }

    /**
     * @param email Optional; when provided and the feature is enabled, a mismatch
     * between the email's domain suffix and `hostedDomain` denies the attempt even if
     * `hostedDomain` itself is on the allow-list (T019). Only enforced while the
     * feature is enabled, so a disabled allow-list never rejects logins (FR-011).
     */
    check(hostedDomain: string | null, email: string | null = null): AllowedDomainCheckResult {
        if (!this.isEnabled) {
            return { allowed: true, domain: hostedDomain };
        }
        if (hostedDomain === null || !this.allowedDomains.includes(hostedDomain.toLowerCase())) {
            return { allowed: false, domain: hostedDomain };
        }
        if (email !== null && !emailMatchesHostedDomain(email, hostedDomain)) {
            return { allowed: false, domain: hostedDomain };
        }
        return { allowed: true, domain: hostedDomain };
    }
}

export const allowedDomainValidator = new AllowedDomainValidator();
