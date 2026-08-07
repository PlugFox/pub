import { beforeEach, describe, expect, test } from "bun:test";
import type { StreamEventDto } from "@pub/api/types";
import { resetUnread, setUnreadCount, unreadCount } from "../src/app/state/notification-store";
import { dispatchStreamEvent } from "../src/app/state/sse";
import { clearToasts, toasts } from "../src/app/state/toast-store";

/*
 * What the app DOES with a stream frame.
 *
 * The transport is tested in `packages/api/test/events.test.ts`; this covers
 * the mapping from an event to the badge and the toast queue, which is where
 * the product decisions live: which events are loud, and where the unread
 * count comes from.
 */

function event(type: string, data: Record<string, unknown> = {}): StreamEventDto {
  return {
    id: "01JABC",
    type,
    at: "2026-08-07T10:00:00Z",
    data: data as StreamEventDto["data"],
  };
}

beforeEach(() => {
  resetUnread();
  clearToasts();
});

describe("notification.new", () => {
  test("adopts the authoritative unread count the event carries", () => {
    setUnreadCount(1);
    dispatchStreamEvent(event("notification.new", { unread: 7, title: "acme_ui 2.0.0 published" }));
    expect(unreadCount()).toBe(7);
  });

  test("a count that went DOWN is still adopted — the server's number wins", () => {
    setUnreadCount(9);
    dispatchStreamEvent(event("notification.new", { unread: 2 }));
    expect(unreadCount()).toBe(2);
  });

  test("falls back to an increment when the frame omits the count", () => {
    setUnreadCount(3);
    dispatchStreamEvent(event("notification.new", {}));
    expect(unreadCount()).toBe(4);
  });

  test("a non-numeric count is treated as absent rather than rendered", () => {
    setUnreadCount(3);
    dispatchStreamEvent(event("notification.new", { unread: "many" }));
    expect(unreadCount()).toBe(4);
  });

  test("raises a toast carrying the server-rendered title", () => {
    dispatchStreamEvent(event("notification.new", { unread: 1, title: "http 1.5.0 published" }));
    expect(toasts().map((toast) => toast.message)).toEqual(["http 1.5.0 published"]);
  });

  test("no title means no toast — an empty toast is worse than none", () => {
    dispatchStreamEvent(event("notification.new", { unread: 1 }));
    expect(toasts()).toHaveLength(0);
    expect(unreadCount()).toBe(1);
  });
});

describe("alarm events", () => {
  test("a shadowing alarm is a warning toast naming the package", () => {
    dispatchStreamEvent({ ...event("upstream.shadowing"), package: "acme_ui" });
    expect(toasts()).toHaveLength(1);
    expect(toasts()[0]?.intent).toBe("warning");
    expect(toasts()[0]?.message).toContain("acme_ui");
  });

  test("a quarantined upstream archive is a danger toast", () => {
    dispatchStreamEvent({ ...event("upstream.quarantine"), package: "http" });
    expect(toasts()[0]?.intent).toBe("danger");
    expect(toasts()[0]?.message).toContain("http");
  });

  test("a membership change is announced", () => {
    dispatchStreamEvent(event("org.member"));
    expect(toasts()).toHaveLength(1);
  });
});

describe("everything else is silent", () => {
  test.each([
    "package.publish",
    "package.retract",
    "package.options",
    "package.hard_delete",
    "package.transfer",
    "org.updated",
    "org.deleted",
    "admin.settings",
    "upstream.drift",
    "some.future.event",
  ])("%s updates no badge and raises no toast", (type) => {
    // A stream that toasts everything is a stream users mute — and then the
    // alarm-shaped events above get missed too.
    dispatchStreamEvent(event(type));
    expect(toasts()).toHaveLength(0);
    expect(unreadCount()).toBe(0);
  });
});
