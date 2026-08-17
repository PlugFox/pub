import { ApiError, NetworkError, parseRetryAfter } from "./errors";

/*
 * Interceptor-chain fetch client (foxic-style, decision 14).
 *
 * Interceptors compose around a terminal fetch via reduceRight, so the FIRST
 * interceptor in the array is the OUTERMOST wrapper (sees the request first,
 * the response last). The concrete chain — mutation headers, bearer injection,
 * proactive/reactive refresh, step-up detection — lives in `interceptors.ts`
 * and is assembled by `createPubApi` in `pub-api.ts`.
 *
 * NOTE: request/response payload types are hand-written in `types.ts` for now;
 * regenerate them from the server's utoipa OpenAPI 3.1 document via
 * openapi-typescript once the app API stabilizes.
 */

/** Per-request instructions for the interceptor chain (never sent on the wire). */
export type RequestMeta = {
  /** Skip bearer injection and the refresh dance (login, refresh, providers). */
  readonly skipAuth?: boolean;
  /** Marks the refresh call itself, so a 401 on it can never recurse. */
  readonly isRefresh?: boolean;
};

export type RequestContext = {
  request: Request;
  /** Free-form bag for interceptors to pass state along the chain. */
  state: Record<string, unknown>;
};

export type NextFn = (ctx: RequestContext) => Promise<Response>;
export type Interceptor = (ctx: RequestContext, next: NextFn) => Promise<Response>;

/** Uniform JSON envelope produced by the server (decision 16). */
export type Envelope<T> =
  | { status: "ok"; data: T }
  | { status: "error"; error: { code: string; message: string } };

/** Minimal fetch shape the client needs — keeps test doubles trivial. */
export type FetchLike = (request: Request) => Promise<Response>;

export type ClientOptions = {
  /** Prefix for relative paths, e.g. "/api/v1". Defaults to same-origin "". */
  baseUrl?: string;
  /** Outermost-first interceptor chain. */
  interceptors?: readonly Interceptor[];
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: FetchLike;
};

export type ApiClient = {
  request<T>(path: string, init?: RequestInit, meta?: RequestMeta): Promise<T>;
  /**
   * Runs the same interceptor chain and hands back the raw `Response`.
   *
   * For the routes whose body is deliberately not the JSON envelope — the S-29.b
   * account export and the S-23 audit export are NDJSON streams — where
   * unwrapping would try to `JSON.parse` a whole file and fail on the second
   * line. An error status still carries the envelope, so callers turn it into
   * an `ApiError` with `throwIfError` rather than reading a failed download.
   */
  requestRaw(path: string, init?: RequestInit, meta?: RequestMeta): Promise<Response>;
};

const META_KEY = "pub.meta";

/** Reads the per-request meta an interceptor was handed (never mutate it). */
export function requestMeta(ctx: RequestContext): RequestMeta {
  const meta = ctx.state[META_KEY];
  return typeof meta === "object" && meta !== null ? (meta as RequestMeta) : {};
}

/** Composes interceptors around `terminal`; index 0 becomes the outermost layer. */
export function composeInterceptors(
  interceptors: readonly Interceptor[],
  terminal: NextFn,
): NextFn {
  return interceptors.reduceRight<NextFn>(
    (next, interceptor) => (ctx) => interceptor(ctx, next),
    terminal,
  );
}

export function createClient(options: ClientOptions = {}): ApiClient {
  const fetchImpl = options.fetchImpl ?? fetch;

  const terminal: NextFn = async (ctx) => {
    try {
      return await fetchImpl(ctx.request);
    } catch (cause) {
      // fetch rejects only on transport problems — never on HTTP error statuses.
      throw new NetworkError("network request failed", { cause });
    }
  };

  const run = composeInterceptors(options.interceptors ?? [], terminal);

  const send = (path: string, init?: RequestInit, meta?: RequestMeta): Promise<Response> => {
    const request = new Request(`${options.baseUrl ?? ""}${path}`, init);
    return run({ request, state: { [META_KEY]: meta ?? {} } });
  };

  return {
    async request<T>(path: string, init?: RequestInit, meta?: RequestMeta): Promise<T> {
      return unwrapEnvelope<T>(await send(path, init, meta));
    },
    requestRaw: send,
  };
}

/**
 * JSON body + method, the shape every mutation in the API modules uses.
 *
 * The content type is declared HERE and not left to the interceptor, because
 * `new Request(url, { body: "…" })` is not neutral: per Fetch ("extract a
 * body"), a string body makes the constructor append
 * `Content-Type: text/plain;charset=UTF-8` when the header is absent. The S-12
 * guard answers 415 to anything that is not `application/json`, so a mutation
 * built without an explicit type would be refused by the server in every real
 * browser. Bun's `Request` does NOT add the implicit type, which is exactly why
 * an offline test suite cannot see the failure — the interceptor keeps a second
 * guard for bodies built elsewhere.
 */
export function jsonBody(method: string, body: unknown): RequestInit {
  return { method, body: JSON.stringify(body), headers: { "content-type": "application/json" } };
}

/** Unwraps the server envelope: ok → data, error → ApiError, 204 → undefined. */
export async function unwrapEnvelope<T>(response: Response): Promise<T> {
  // 429/503 carry Retry-After (S-24); the countdown UI needs it on the error.
  const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
  if (response.status === 204) {
    return undefined as T;
  }
  let envelope: Envelope<T>;
  try {
    envelope = (await response.json()) as Envelope<T>;
  } catch {
    throw new ApiError(
      "invalid_response",
      "response body is not a JSON envelope",
      response.status,
      {
        retryAfter,
      },
    );
  }
  if (envelope.status === "ok") {
    return envelope.data;
  }
  if (envelope.status === "error") {
    throw new ApiError(envelope.error.code, envelope.error.message, response.status, {
      retryAfter,
    });
  }
  throw new ApiError(
    "invalid_response",
    "envelope status is neither ok nor error",
    response.status,
    {
      retryAfter,
    },
  );
}

/**
 * Turns a failed response into an `ApiError`, leaving a successful one alone.
 *
 * The half of [`unwrapEnvelope`] that a non-envelope body still needs: an NDJSON
 * export answers the ordinary error envelope when it is refused (401, 403
 * `step_up_required`, 429), and a caller that skipped the check would save a
 * file containing the refusal.
 */
export async function throwIfError(response: Response): Promise<Response> {
  if (response.ok) return response;
  const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
  const code = await peekErrorCode(response);
  throw new ApiError(
    code ?? "invalid_response",
    `request failed with ${response.status}`,
    response.status,
    {
      retryAfter,
    },
  );
}

/**
 * Reads the error code out of a response without consuming it.
 *
 * Interceptors that need to branch on the code (step-up, refresh reuse) run
 * before the envelope is unwrapped, so they must clone: a body read twice
 * throws, and the caller still needs the original.
 */
export async function peekErrorCode(response: Response): Promise<string | null> {
  try {
    const parsed: unknown = await response.clone().json();
    if (typeof parsed !== "object" || parsed === null) return null;
    const envelope = parsed as { status?: string; error?: { code?: unknown } };
    if (envelope.status !== "error") return null;
    const code = envelope.error?.code;
    return typeof code === "string" ? code : null;
  } catch {
    return null;
  }
}
