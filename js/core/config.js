/* ==========================================================================
   config.js
   Single source of truth for the API origin plus an authenticated fetch
   wrapper.

   The base URL used to be hardcoded in eight different files, so pointing
   the app at a local backend meant editing all of them.
   Override at runtime from the console with:
        localStorage.setItem("fintack_api_base", "http://localhost:5000");
========================================================================== */

const DEFAULT_ORIGIN = "https://fintack.getvoroa.com";

function resolveOrigin() {
    const override = localStorage.getItem("fintack_api_base");

    if (override) return override.replace(/\/$/, "");

    const host = window.location.hostname;

    /* If running locally, allow local development overrides or fallback */
    if (host === "localhost" || host === "127.0.0.1") {
        return localStorage.getItem("fintack_api_local") || "http://localhost:5000";
    }

    /* For production environments like Netlify, force the live backend origin */
    return DEFAULT_ORIGIN;
}

export const API_ORIGIN = resolveOrigin();
export const API_BASE_URL = `${API_ORIGIN}/api`;

/* ==========================================================================
                        SESSION
========================================================================== */

export function getToken() {
    return localStorage.getItem("token");
}

export function getCurrentUser() {
    try {
        return JSON.parse(localStorage.getItem("user"));
    } catch (err) {
        return null;
    }
}

export function clearSession() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    localStorage.removeItem("currentChatId");
}

/* ==========================================================================
                        AUTHENTICATED FETCH

   Returns a normalised { ok, status, data } instead of throwing on
   non-2xx, so callers can surface the server's message rather than a
   generic "something went wrong".
========================================================================== */

export async function apiFetch(path, options = {}) {
    const url = path.startsWith("http")
        ? path
        : `${API_ORIGIN}${path.startsWith("/") ? "" : "/"}${path}`;

    const headers = {
        Accept: "application/json",
        ...(options.headers || {})
    };

    if (options.body && !headers["Content-Type"]) {
        headers["Content-Type"] = "application/json";
    }

    if (!options.skipAuth) {
        const token = getToken();
        if (token) headers.Authorization = `Bearer ${token}`;
    }

    let response;

    try {
        response = await fetch(url, {
            ...options,
            headers,
            body:
                options.body && typeof options.body !== "string"
                    ? JSON.stringify(options.body)
                    : options.body
        });
    } catch (networkError) {
        console.error("[FinTack API] Network error:", url, networkError);

        return {
            ok: false,
            status: 0,
            data: {
                success: false,
                message:
                    "Can't reach the FinTack server. Check your connection and try again."
            }
        };
    }

    let data = null;

    try {
        const text = await response.text();
        data = text ? JSON.parse(text) : {};
    } catch (parseError) {
        data = {
            success: false,
            message: "The server returned an unexpected response."
        };
    }

    /* An expired token should log the user out rather than fail silently. */
    if (response.status === 401 && data?.code === "TOKEN_EXPIRED") {
        clearSession();
        window.dispatchEvent(new CustomEvent("fintack:session-expired"));
    }

    return {
        ok: response.ok && data?.success !== false,
        status: response.status,
        data: data || {}
    };
}

/* ==========================================================================
                GLOBAL FETCH AUTHORISATION

   The app grew several modules that call fetch() directly (calendar, AI
   storage, goal actions). Now that every API route requires a bearer
   token, each of those would have started returning 401.

   Rather than rewriting each call site - and risking one being missed -
   this wraps the global fetch once and attaches the token to any request
   aimed at the FinTack API. Requests to third-party origins are untouched,
   so the token never leaks off-origin.
========================================================================== */

function installFetchAuth() {
    /*
        Guarded rather than assumed: this module is also loaded by the test
        harness and by any environment without fetch, where reaching into
        window.fetch would throw at import time and take the whole app down.
    */
    if (
        typeof window === "undefined" ||
        typeof window.fetch !== "function" ||
        window.__fintackFetchPatched
    ) {
        return;
    }

    const originalFetch = window.fetch.bind(window);

    window.fetch = async (input, init = {}) => {
        const url =
            typeof input === "string"
                ? input
                : input instanceof Request
                    ? input.url
                    : String(input);

        const isOwnApi = url.startsWith(API_ORIGIN);

        if (!isOwnApi) return originalFetch(input, init);

        const token = getToken();

        if (!token) return originalFetch(input, init);

        const headers = new Headers(
            init.headers || (input instanceof Request ? input.headers : undefined)
        );

        if (!headers.has("Authorization")) {
            headers.set("Authorization", `Bearer ${token}`);
        }

        const response = await originalFetch(input, { ...init, headers });

        /* Surface expired sessions from legacy call sites too. */
        if (response.status === 401) {
            window.dispatchEvent(new CustomEvent("fintack:session-expired"));
        }

        return response;
    };

    window.__fintackFetchPatched = true;
}

installFetchAuth();

export default {
    API_ORIGIN,
    API_BASE_URL,
    apiFetch,
    getToken,
    getCurrentUser,
    clearSession
};