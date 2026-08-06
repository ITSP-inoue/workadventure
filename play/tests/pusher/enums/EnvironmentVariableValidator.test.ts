import { describe, expect, it } from "vitest";
import { EnvironmentVariables } from "../../../src/pusher/enums/EnvironmentVariableValidator";

const schema = EnvironmentVariables.shape.ALLOWED_GOOGLE_WORKSPACE_DOMAINS;

describe("ALLOWED_GOOGLE_WORKSPACE_DOMAINS schema", () => {
    it("disables the feature (empty array) when unset", () => {
        const result = schema.safeParse(undefined);
        expect(result.success).toBe(true);
        if (result.success) {
            expect(result.data).toEqual([]);
        }
    });

    it("parses and normalizes a comma-separated list", () => {
        const result = schema.safeParse(" Example-Corp.com , example-corp.co.jp ");
        expect(result.success).toBe(true);
        if (result.success) {
            expect(result.data).toEqual(["example-corp.com", "example-corp.co.jp"]);
        }
    });

    it("rejects a trailing comma (empty entry)", () => {
        expect(schema.safeParse("example-corp.com,").success).toBe(false);
    });

    it("rejects a wildcard-only entry", () => {
        expect(schema.safeParse("*").success).toBe(false);
    });

    it("rejects an email address in place of a domain", () => {
        expect(schema.safeParse("user@example-corp.com").success).toBe(false);
    });
});
