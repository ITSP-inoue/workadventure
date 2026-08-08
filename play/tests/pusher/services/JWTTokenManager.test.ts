import { describe, expect, it, vi } from "vitest";

vi.mock("../../../src/pusher/enums/EnvironmentVariable", () => import("../mocks/pusherEnvironmentVariableMock"));

import { jwtTokenManager } from "../../../src/pusher/services/JWTTokenManager";

describe("JWTTokenManager hostedDomain (T027)", () => {
    it("round-trips a hostedDomain claim through create/verify", async () => {
        const token = await jwtTokenManager.createAuthToken(
            "user@example-corp.com",
            "google-access-token",
            "user",
            "en",
            [],
            undefined,
            "example-corp.com",
        );

        const data = await jwtTokenManager.verifyJWTToken(token);

        expect(data.hostedDomain).toBe("example-corp.com");
    });

    it("round-trips a null hostedDomain (feature disabled, or no hd claim) as null, not undefined", async () => {
        const token = await jwtTokenManager.createAuthToken(
            "someone@gmail.com",
            "google-access-token",
            "someone",
            "en",
            [],
            undefined,
            null,
        );

        const data = await jwtTokenManager.verifyJWTToken(token);

        expect(data.hostedDomain).toBeNull();
    });

    it("still verifies a token created without a hostedDomain argument at all (pre-T027 anonymous tokens)", async () => {
        const token = await jwtTokenManager.createAuthToken("some-anonymous-uuid");

        const data = await jwtTokenManager.verifyJWTToken(token);

        expect(data.hostedDomain).toBeUndefined();
        expect(data.identifier).toBe("some-anonymous-uuid");
    });
});
