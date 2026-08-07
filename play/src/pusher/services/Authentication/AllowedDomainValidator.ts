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

export class AllowedDomainValidator {
    constructor(private readonly allowedDomains: readonly string[] = ALLOWED_GOOGLE_WORKSPACE_DOMAINS) {}

    get isEnabled(): boolean {
        return this.allowedDomains.length > 0;
    }

    check(hostedDomain: string | null): AllowedDomainCheckResult {
        if (!this.isEnabled) {
            return { allowed: true, domain: hostedDomain };
        }
        const allowed = hostedDomain !== null && this.allowedDomains.includes(hostedDomain.toLowerCase());
        return { allowed, domain: hostedDomain };
    }
}

export const allowedDomainValidator = new AllowedDomainValidator();
