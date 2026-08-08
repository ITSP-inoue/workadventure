import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Application, Request, Response } from "express";

vi.mock("../../src/pusher/enums/EnvironmentVariable", () => import("./mocks/pusherEnvironmentVariableMock"));

const getUserInfo = vi.fn();
const checkTokenAuth = vi.fn();
vi.mock("../../src/pusher/services/OpenIDClient", () => ({
    openIDClient: {
        getUserInfo,
        authorizationUrl: vi.fn(),
        logoutUser: vi.fn(),
        checkTokenAuth,
    },
}));

const createAuthToken = vi.fn();
const verifyJWTToken = vi.fn();
vi.mock("../../src/pusher/services/JWTTokenManager", () => ({
    jwtTokenManager: {
        createAuthToken,
        verifyJWTToken,
    },
}));

vi.mock("../../src/pusher/services/MatrixProvider", () => ({
    matrixProvider: {
        getBareMatrixIdFromEmail: vi.fn().mockReturnValue("@user:matrix.test"),
    },
}));

const fetchMemberDataByUuid = vi.fn();
vi.mock("../../src/pusher/services/AdminService", () => ({
    adminService: { fetchMemberDataByUuid },
}));

const checkDomain = vi.fn();
vi.mock("../../src/pusher/services/Authentication/AllowedDomainValidator", () => ({
    allowedDomainValidator: { check: checkDomain },
}));

const logAuthenticationAttempt = vi.fn();
vi.mock("../../src/pusher/services/Authentication/AuditLog", () => ({
    logAuthenticationAttempt,
}));

const { AuthenticateController } = await import("../../src/pusher/controllers/AuthenticateController");

type RouteHandler = (req: Request, res: Response) => Promise<void> | void;

class MockApp {
    private readonly getRoutes = new Map<string, RouteHandler>();
    private readonly postRoutes = new Map<string, RouteHandler>();

    get(endpoint: string, callback: RouteHandler) {
        this.getRoutes.set(endpoint, callback);
        return this;
    }

    post(endpoint: string, callback: RouteHandler) {
        this.postRoutes.set(endpoint, callback);
        return this;
    }

    options(_endpoint: string, _callback: unknown) {
        return this;
    }

    async simulateGet(endpoint: string, req: Request, res: Response) {
        const handler = this.getRoutes.get(endpoint);
        if (!handler) {
            throw new Error(`No handler registered for GET ${endpoint}`);
        }
        await handler(req, res);
    }

    async simulatePost(endpoint: string, req: Request, res: Response) {
        const handler = this.postRoutes.get(endpoint);
        if (!handler) {
            throw new Error(`No handler registered for POST ${endpoint}`);
        }
        await handler(req, res);
    }
}

class FakeResponse {
    statusCode = 200;
    body: string | undefined;
    redirectedTo: string | undefined;
    clearedCookies: string[] = [];

    status(code: number) {
        this.statusCode = code;
        return this;
    }

    send(body?: string) {
        this.body = body;
        return this;
    }

    json(body: unknown) {
        this.body = JSON.stringify(body);
        return this;
    }

    redirect(url: string) {
        this.redirectedTo = url;
        return this;
    }

    clearCookie(name: string) {
        this.clearedCookies.push(name);
        return this;
    }

    cookie() {
        return this;
    }

    type() {
        return this;
    }

    setHeader() {
        return this;
    }
}

function makeUserInfo(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        email: "user@example-corp.com",
        sub: "1234567890",
        access_token: "google-access-token",
        username: "user",
        locale: "en",
        tags: [],
        matrix_url: undefined,
        matrix_identity_provider: undefined,
        hostedDomain: "example-corp.com",
        ...overrides,
    };
}

describe("AuthenticateController /openid-callback — Google Workspace domain restriction (US1)", () => {
    let app: MockApp;

    beforeEach(() => {
        vi.clearAllMocks();
        createAuthToken.mockResolvedValue("fake-jwt-token");
        app = new MockApp();
        new AuthenticateController(app as unknown as Application);
    });

    it("issues a JWT and redirects with the token for an allowed Workspace domain (T008)", async () => {
        checkDomain.mockReturnValue({ allowed: true, domain: "example-corp.com" });
        getUserInfo.mockResolvedValue(makeUserInfo());

        const req = { cookies: { playUri: "https://play.example.com/room" } } as unknown as Request;
        const res = new FakeResponse();

        await app.simulateGet("/openid-callback", req, res as unknown as Response);

        expect(checkDomain).toHaveBeenCalledWith("example-corp.com", "user@example-corp.com");
        expect(createAuthToken).toHaveBeenCalledTimes(1);
        expect(res.redirectedTo).toBe("https://play.example.com/room?token=fake-jwt-token");
        expect(res.statusCode).not.toBe(403);
    });

    it("logs the allowed attempt with domain and subject (T011)", async () => {
        checkDomain.mockReturnValue({ allowed: true, domain: "example-corp.com" });
        getUserInfo.mockResolvedValue(makeUserInfo());

        const req = { cookies: { playUri: "https://play.example.com/room" } } as unknown as Request;
        await app.simulateGet("/openid-callback", req, new FakeResponse() as unknown as Response);

        expect(logAuthenticationAttempt).toHaveBeenCalledWith({
            result: "allowed",
            domain: "example-corp.com",
            subject: "1234567890",
        });
    });

    it("rejects a personal Gmail account and does not issue a JWT when the domain is denied", async () => {
        checkDomain.mockReturnValue({ allowed: false, domain: null });
        getUserInfo.mockResolvedValue(makeUserInfo({ email: "someone@gmail.com", hostedDomain: null }));

        const req = { cookies: { playUri: "https://play.example.com/room" } } as unknown as Request;
        const res = new FakeResponse();

        await app.simulateGet("/openid-callback", req, res as unknown as Response);

        expect(createAuthToken).not.toHaveBeenCalled();
        expect(res.redirectedTo).toBeUndefined();
        expect(res.statusCode).toBe(403);
        expect(logAuthenticationAttempt).toHaveBeenCalledWith({
            result: "denied",
            domain: null,
            subject: "1234567890",
        });
    });

    it("rejects an email/hd mismatch (T019) and does not issue a JWT", async () => {
        // AllowedDomainValidator itself denies mismatches; here we only confirm the
        // controller forwards the raw email and honors whatever the validator decides.
        checkDomain.mockReturnValue({ allowed: false, domain: "example-corp.com" });
        getUserInfo.mockResolvedValue(
            makeUserInfo({ email: "user@other-company.com", hostedDomain: "example-corp.com" }),
        );

        const req = { cookies: { playUri: "https://play.example.com/room" } } as unknown as Request;
        const res = new FakeResponse();

        await app.simulateGet("/openid-callback", req, res as unknown as Response);

        expect(checkDomain).toHaveBeenCalledWith("example-corp.com", "user@other-company.com");
        expect(createAuthToken).not.toHaveBeenCalled();
        expect(res.statusCode).toBe(403);
    });

    it("does not restrict logins when the domain allow-list is disabled (FR-011)", async () => {
        checkDomain.mockReturnValue({ allowed: true, domain: null });
        getUserInfo.mockResolvedValue(makeUserInfo({ email: "someone@gmail.com", hostedDomain: null }));

        const req = { cookies: { playUri: "https://play.example.com/room" } } as unknown as Request;
        const res = new FakeResponse();

        await app.simulateGet("/openid-callback", req, res as unknown as Response);

        expect(createAuthToken).toHaveBeenCalledTimes(1);
        expect(res.statusCode).not.toBe(403);
    });
});

describe("AuthenticateController /anonymLogin — unaffected by Google Workspace domain restriction (T021)", () => {
    let app: MockApp;

    beforeEach(() => {
        vi.clearAllMocks();
        createAuthToken.mockResolvedValue("fake-anonymous-jwt-token");
        app = new MockApp();
        new AuthenticateController(app as unknown as Application);
    });

    it("issues an anonymous token without consulting AllowedDomainValidator, even if it would deny", async () => {
        // ALLOWED_GOOGLE_WORKSPACE_DOMAINS being set (or the validator denying) must never
        // affect anonymous login: it's a separate, unrelated route (FR-011).
        checkDomain.mockReturnValue({ allowed: false, domain: null });

        const req = {} as Request;
        const res = new FakeResponse();

        await app.simulatePost("/anonymLogin", req, res as unknown as Response);

        expect(checkDomain).not.toHaveBeenCalled();
        expect(logAuthenticationAttempt).not.toHaveBeenCalled();
        expect(createAuthToken).toHaveBeenCalledTimes(1);
        expect(res.statusCode).not.toBe(403);
        expect(res.body).toContain("fake-anonymous-jwt-token");
    });
});

function makeMeRequest(token = "fake-jwt-token"): Request {
    return {
        query: {
            token,
            playUri: "https://play.example.com/room",
        },
        header: () => undefined,
    } as unknown as Request;
}

describe("AuthenticateController /me — re-validates the Workspace domain on reconnect (T025, T027)", () => {
    let app: MockApp;

    beforeEach(() => {
        vi.clearAllMocks();
        fetchMemberDataByUuid.mockResolvedValue({ status: "ok" });
        checkTokenAuth.mockResolvedValue({});
        app = new MockApp();
        new AuthenticateController(app as unknown as Application);
    });

    it("re-checks the stored hd claim against the current allow-list and proceeds when still allowed", async () => {
        verifyJWTToken.mockResolvedValue({
            identifier: "user@example-corp.com",
            accessToken: "google-access-token",
            hostedDomain: "example-corp.com",
        });
        checkDomain.mockReturnValue({ allowed: true, domain: "example-corp.com" });

        const res = new FakeResponse();
        await app.simulateGet("/me", makeMeRequest(), res as unknown as Response);

        expect(checkDomain).toHaveBeenCalledWith("example-corp.com");
        expect(checkTokenAuth).toHaveBeenCalledTimes(1);
        expect(logAuthenticationAttempt).not.toHaveBeenCalled();
        const body = JSON.parse(res.body ?? "{}");
        expect(body.type).not.toBe("unauthorized");
    });

    it("denies reconnection and does not call checkTokenAuth when the domain is no longer allowed", async () => {
        // Simulates an admin having narrowed ALLOWED_GOOGLE_WORKSPACE_DOMAINS after this
        // session's original login: the JWT still carries the old hd claim, but the
        // validator (reflecting the *current* config) now denies it.
        verifyJWTToken.mockResolvedValue({
            identifier: "user@example-corp.com",
            accessToken: "google-access-token",
            hostedDomain: "example-corp.com",
        });
        checkDomain.mockReturnValue({ allowed: false, domain: "example-corp.com" });

        const res = new FakeResponse();
        await app.simulateGet("/me", makeMeRequest(), res as unknown as Response);

        expect(checkTokenAuth).not.toHaveBeenCalled();
        expect(logAuthenticationAttempt).toHaveBeenCalledWith({
            result: "denied",
            domain: "example-corp.com",
            subject: "user@example-corp.com",
        });
        const body = JSON.parse(res.body ?? "{}");
        expect(body).toMatchObject({
            status: "error",
            type: "unauthorized",
            code: "GOOGLE_WORKSPACE_DOMAIN_NOT_ALLOWED",
        });
    });

    it("does not consult AllowedDomainValidator for an anonymous session (no accessToken)", async () => {
        verifyJWTToken.mockResolvedValue({
            identifier: "some-anonymous-uuid",
            accessToken: undefined,
        });

        const res = new FakeResponse();
        await app.simulateGet("/me", makeMeRequest(), res as unknown as Response);

        expect(checkDomain).not.toHaveBeenCalled();
        expect(checkTokenAuth).not.toHaveBeenCalled();
    });
});
