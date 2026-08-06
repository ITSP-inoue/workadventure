import { afterEach, describe, expect, it, vi } from "vitest";
import {
    logAuthenticationAttempt,
    toAuditLogRecord,
} from "../../../../src/pusher/services/Authentication/AuditLog";

describe("toAuditLogRecord", () => {
    it("builds a record for an allowed attempt", () => {
        const record = toAuditLogRecord({
            result: "allowed",
            domain: "example-corp.com",
            subject: "user-123",
            timestamp: new Date("2026-08-06T00:00:00.000Z"),
        });

        expect(record).toEqual({
            event: "google_workspace_auth_attempt",
            result: "allowed",
            domain: "example-corp.com",
            subject: "user-123",
            timestamp: "2026-08-06T00:00:00.000Z",
        });
    });

    it("builds a record for a denied attempt with no domain claim", () => {
        const record = toAuditLogRecord({
            result: "denied",
            domain: null,
            subject: null,
            timestamp: new Date("2026-08-06T00:00:00.000Z"),
        });

        expect(record.result).toBe("denied");
        expect(record.domain).toBeNull();
    });

    it("defaults the timestamp to now when omitted", () => {
        const before = Date.now();
        const record = toAuditLogRecord({ result: "allowed", domain: "example-corp.com", subject: "user-123" });
        const after = Date.now();

        const recordedTime = new Date(record.timestamp).getTime();
        expect(recordedTime).toBeGreaterThanOrEqual(before);
        expect(recordedTime).toBeLessThanOrEqual(after);
    });
});

describe("logAuthenticationAttempt", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("writes a single structured JSON line without leaking extra fields", () => {
        const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);

        logAuthenticationAttempt({
            result: "denied",
            domain: "other-company.com",
            subject: null,
            timestamp: new Date("2026-08-06T00:00:00.000Z"),
        });

        expect(consoleSpy).toHaveBeenCalledTimes(1);
        const [firstCall] = consoleSpy.mock.calls;
        const logged = JSON.parse(firstCall?.[0] as string);
        expect(logged).toEqual({
            event: "google_workspace_auth_attempt",
            result: "denied",
            domain: "other-company.com",
            subject: null,
            timestamp: "2026-08-06T00:00:00.000Z",
        });
    });
});
