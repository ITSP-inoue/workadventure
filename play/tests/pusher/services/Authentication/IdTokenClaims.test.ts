import { describe, expect, it } from "vitest";
import { extractGoogleWorkspaceClaims } from "../../../../src/pusher/services/Authentication/IdTokenClaims";

describe("extractGoogleWorkspaceClaims", () => {
    it("extracts hd, email and sub from a Workspace account payload", () => {
        const claims = extractGoogleWorkspaceClaims({
            sub: "1234567890",
            email: "user@example-corp.com",
            hd: "example-corp.com",
            iss: "https://accounts.google.com",
        });

        expect(claims).toEqual({
            sub: "1234567890",
            email: "user@example-corp.com",
            hostedDomain: "example-corp.com",
        });
    });

    it("returns a null hostedDomain for a personal Gmail account (no hd claim)", () => {
        const claims = extractGoogleWorkspaceClaims({
            sub: "9876543210",
            email: "someone@gmail.com",
        });

        expect(claims.hostedDomain).toBeNull();
    });

    it("ignores a non-string hd claim instead of throwing", () => {
        const claims = extractGoogleWorkspaceClaims({ hd: 12345 });
        expect(claims.hostedDomain).toBeNull();
    });

    it("treats a blank hd claim as absent", () => {
        const claims = extractGoogleWorkspaceClaims({ hd: "   " });
        expect(claims.hostedDomain).toBeNull();
    });
});
