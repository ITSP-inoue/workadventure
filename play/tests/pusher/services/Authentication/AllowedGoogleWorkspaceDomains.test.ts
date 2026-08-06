import { describe, expect, it } from "vitest";
import {
    isValidWorkspaceDomain,
    normalizeAllowedDomains,
} from "../../../../src/pusher/services/Authentication/AllowedGoogleWorkspaceDomains";

describe("isValidWorkspaceDomain", () => {
    it("accepts a plain domain", () => {
        expect(isValidWorkspaceDomain("example-corp.com")).toBe(true);
    });

    it("accepts a multi-label domain", () => {
        expect(isValidWorkspaceDomain("example-corp.co.jp")).toBe(true);
    });

    it("rejects an empty string", () => {
        expect(isValidWorkspaceDomain("")).toBe(false);
    });

    it("rejects a wildcard-only entry", () => {
        expect(isValidWorkspaceDomain("*")).toBe(false);
    });

    it("rejects an email address", () => {
        expect(isValidWorkspaceDomain("user@example-corp.com")).toBe(false);
    });

    it("rejects a bare label with no dot", () => {
        expect(isValidWorkspaceDomain("localhost")).toBe(false);
    });
});

describe("normalizeAllowedDomains", () => {
    it("lowercases and trims entries", () => {
        expect(normalizeAllowedDomains([" Example-Corp.COM "])).toEqual(["example-corp.com"]);
    });

    it("de-duplicates case-insensitively", () => {
        expect(normalizeAllowedDomains(["Example-Corp.com", "example-corp.com"])).toEqual(["example-corp.com"]);
    });

    it("returns an empty array unchanged", () => {
        expect(normalizeAllowedDomains([])).toEqual([]);
    });
});
