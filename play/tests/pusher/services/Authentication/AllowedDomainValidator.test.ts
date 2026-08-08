import { describe, expect, it, vi } from "vitest";

// AllowedDomainValidator.ts imports EnvironmentVariable.ts for its default constructor
// parameter; that module runs real env validation (and can process.exit) at import
// time, so it must be stubbed here even though every test below passes an explicit
// domain list and never touches the default.
vi.mock("../../../../src/pusher/enums/EnvironmentVariable", () => import("../../mocks/pusherEnvironmentVariableMock"));

import { AllowedDomainValidator } from "../../../../src/pusher/services/Authentication/AllowedDomainValidator";

describe("AllowedDomainValidator", () => {
    describe("when disabled (no allowed domains configured)", () => {
        const validator = new AllowedDomainValidator([]);

        it("allows an account with no hd claim (existing anonymous/OIDC flows unaffected, FR-011)", () => {
            expect(validator.check(null)).toEqual({ allowed: true, domain: null });
        });

        it("allows an account with an hd claim outside any configured list", () => {
            expect(validator.check("example-corp.com")).toEqual({ allowed: true, domain: "example-corp.com" });
        });
    });

    describe("when enabled with a single allowed domain", () => {
        const validator = new AllowedDomainValidator(["example-corp.com"]);

        it("allows an account whose hd claim matches the allowed domain", () => {
            expect(validator.check("example-corp.com")).toEqual({ allowed: true, domain: "example-corp.com" });
        });

        it("matches case-insensitively", () => {
            expect(validator.check("Example-Corp.COM")).toEqual({ allowed: true, domain: "Example-Corp.COM" });
        });

        it("denies an account whose hd claim is a different domain", () => {
            expect(validator.check("other-company.com")).toEqual({ allowed: false, domain: "other-company.com" });
        });

        it("denies an account with no hd claim (e.g. a personal Gmail account)", () => {
            expect(validator.check(null)).toEqual({ allowed: false, domain: null });
        });
    });

    describe("when enabled with multiple allowed domains (T012)", () => {
        const validator = new AllowedDomainValidator(["example-corp.com", "example-corp.co.jp"]);

        it("allows an account matching the first configured domain", () => {
            expect(validator.check("example-corp.com").allowed).toBe(true);
        });

        it("allows an account matching the second configured domain", () => {
            expect(validator.check("example-corp.co.jp").allowed).toBe(true);
        });

        it("denies an account matching neither configured domain", () => {
            expect(validator.check("unrelated-company.com").allowed).toBe(false);
        });
    });

    describe("email / hd mismatch detection (T019)", () => {
        const validator = new AllowedDomainValidator(["example-corp.com"]);

        it("allows when the email domain matches the allowed hd claim", () => {
            expect(validator.check("example-corp.com", "user@example-corp.com")).toEqual({
                allowed: true,
                domain: "example-corp.com",
            });
        });

        it("matches the email domain case-insensitively", () => {
            expect(validator.check("example-corp.com", "user@Example-Corp.COM").allowed).toBe(true);
        });

        it("denies when the email domain does not match an otherwise-allowed hd claim", () => {
            expect(validator.check("example-corp.com", "user@other-company.com")).toEqual({
                allowed: false,
                domain: "example-corp.com",
            });
        });

        it("denies when the email has no domain part at all", () => {
            expect(validator.check("example-corp.com", "not-an-email").allowed).toBe(false);
        });

        it("does not run the mismatch check when the feature is disabled", () => {
            const disabledValidator = new AllowedDomainValidator([]);
            expect(disabledValidator.check("example-corp.com", "user@other-company.com")).toEqual({
                allowed: true,
                domain: "example-corp.com",
            });
        });

        it("still denies an out-of-allow-list hd claim even when no email is provided", () => {
            expect(validator.check("other-company.com", null).allowed).toBe(false);
        });

        it("does not enforce the mismatch check when email is omitted", () => {
            expect(validator.check("example-corp.com").allowed).toBe(true);
        });
    });
});
