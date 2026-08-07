/**
 * Domain allow-list for the opt-in Google Workspace authentication feature
 * (spec-kit-practice#1, FR-005, FR-006, FR-011). Backs the
 * ALLOWED_GOOGLE_WORKSPACE_DOMAINS zod schema entry in EnvironmentVariableValidator.
 */

const DOMAIN_PATTERN = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export function isValidWorkspaceDomain(domain: string): boolean {
    const trimmed = domain.trim();
    return trimmed.length > 0 && !trimmed.includes("@") && DOMAIN_PATTERN.test(trimmed);
}

/** Lowercases, trims and de-duplicates a list of already-validated domains. */
export function normalizeAllowedDomains(domains: string[]): string[] {
    const seen = new Set<string>();
    const normalized: string[] = [];
    for (const domain of domains) {
        const lower = domain.trim().toLowerCase();
        if (!seen.has(lower)) {
            seen.add(lower);
            normalized.push(lower);
        }
    }
    return normalized;
}
