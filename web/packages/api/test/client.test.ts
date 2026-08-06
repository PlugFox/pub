import { describe, expect, test } from "bun:test";
import { composeInterceptors, createClient, type Interceptor } from "@pub/api/client";
import { ApiError, NetworkError } from "@pub/api/errors";

// Outside the browser Request() has no document base URL, so tests always
// pass an absolute baseUrl (in the app it defaults to same-origin "").
const BASE = "https://pub.test";

function okJson(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ status: "ok", data }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("interceptor chain", () => {
  test("index 0 is outermost: before in order, after in reverse", async () => {
    const calls: string[] = [];
    const make = (name: string): Interceptor => {
      return async (ctx, next) => {
        calls.push(`${name}:before`);
        const response = await next(ctx);
        calls.push(`${name}:after`);
        return response;
      };
    };
    const client = createClient({
      baseUrl: BASE,
      interceptors: [make("a"), make("b")],
      fetchImpl: async () => {
        calls.push("terminal");
        return okJson(null);
      },
    });

    await client.request("/x");
    expect(calls).toEqual(["a:before", "b:before", "terminal", "b:after", "a:after"]);
  });

  test("composeInterceptors with an empty chain is just the terminal", async () => {
    const terminal = async (): Promise<Response> => okJson("bare");
    const run = composeInterceptors([], terminal);
    const response = await run({ request: new Request("http://local/x"), state: {} });
    expect(((await response.json()) as { data: string }).data).toBe("bare");
  });
});

describe("envelope unwrapping", () => {
  test("ok envelope resolves to data", async () => {
    const client = createClient({
      baseUrl: BASE,
      fetchImpl: async () => okJson({ name: "pub_api", version: 1 }),
    });
    const data = await client.request<{ name: string; version: number }>("/info");
    expect(data).toEqual({ name: "pub_api", version: 1 });
  });

  test("error envelope rejects with ApiError carrying code and HTTP status", async () => {
    const client = createClient({
      baseUrl: BASE,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({ status: "error", error: { code: "forbidden", message: "no access" } }),
          { status: 403, headers: { "content-type": "application/json" } },
        ),
    });

    const failure = await client.request("/private").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    const apiError = failure as ApiError;
    expect(apiError.code).toBe("forbidden");
    expect(apiError.message).toBe("no access");
    expect(apiError.status).toBe(403);
  });

  test("204 No Content resolves to undefined", async () => {
    const client = createClient({
      baseUrl: BASE,
      fetchImpl: async () => new Response(null, { status: 204 }),
    });
    await expect(client.request<undefined>("/deleted")).resolves.toBeUndefined();
  });

  test("non-JSON body rejects with ApiError, not a parse crash", async () => {
    const client = createClient({
      baseUrl: BASE,
      fetchImpl: async () => new Response("<html>gateway</html>", { status: 502 }),
    });
    const failure = await client.request("/broken").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("invalid_response");
    expect((failure as ApiError).status).toBe(502);
  });
});

describe("network failures", () => {
  test("fetch rejection maps to NetworkError, never ApiError", async () => {
    const client = createClient({
      baseUrl: BASE,
      fetchImpl: async () => {
        throw new TypeError("fetch failed");
      },
    });
    const failure = await client.request("/anything").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(NetworkError);
    expect(failure).not.toBeInstanceOf(ApiError);
    expect((failure as NetworkError).cause).toBeInstanceOf(TypeError);
  });
});
