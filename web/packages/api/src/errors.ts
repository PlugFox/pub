/*
 * The two failure classes are deliberately distinct (docs/rules/web.md):
 * an ApiError means the server received the request and said no; a
 * NetworkError means the request never completed. Interceptors and stores
 * must discriminate — a network failure must never log the user out.
 */

/** The server answered with an error envelope: `{ status: "error", error: { code, message } }`. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

/** Transport-level failure (offline, DNS, aborted, CORS). Not a denial. */
export class NetworkError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "NetworkError";
  }
}
