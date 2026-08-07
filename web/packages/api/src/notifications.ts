import { type ApiClient, jsonBody } from "./client";
import type {
  NotificationFeedDto,
  NotificationPreferenceDto,
  NotificationPreferencesDto,
  NotificationsReadDto,
} from "./types";

/*
 * The notification center (`/api/v1/notifications`, decision 20).
 *
 * Every route is scoped to the caller — there is no `user_id` parameter
 * anywhere in the surface, so another account's notifications are not
 * addressable, let alone readable.
 *
 * `unread` in the feed is the TOTAL, not the count on this page: it is the
 * badge, and a badge that changed with the page size would be worse than none.
 * Both mutations return the recomputed badge so the header updates without a
 * second request.
 */

export type FeedOptions = {
  readonly unread?: boolean;
  readonly cursor?: string;
  readonly limit?: number;
};

export type NotificationsApi = ReturnType<typeof createNotificationsApi>;

export function createNotificationsApi(client: ApiClient) {
  return {
    list(options: FeedOptions = {}): Promise<NotificationFeedDto> {
      const search = new URLSearchParams();
      if (options.unread === true) search.set("unread", "true");
      if (options.cursor !== undefined && options.cursor !== "") {
        search.set("cursor", options.cursor);
      }
      if (options.limit !== undefined) search.set("limit", String(options.limit));
      const encoded = search.toString();
      return client.request<NotificationFeedDto>(
        `/notifications${encoded === "" ? "" : `?${encoded}`}`,
      );
    },

    /** Marks the listed ids read. Already-read and foreign ids count for nothing. */
    markRead(ids: readonly string[]): Promise<NotificationsReadDto> {
      return client.request<NotificationsReadDto>("/notifications/read", jsonBody("POST", { ids }));
    },

    /** Marks every unread notification read. */
    markAllRead(): Promise<NotificationsReadDto> {
      return client.request<NotificationsReadDto>(
        "/notifications/read",
        jsonBody("POST", { all: true }),
      );
    },

    /** Every category with defaults filled in — never a partial list. */
    preferences(): Promise<NotificationPreferencesDto> {
      return client.request<NotificationPreferencesDto>("/notifications/preferences");
    },

    /** Categories left out keep their stored value. */
    updatePreferences(
      preferences: readonly NotificationPreferenceDto[],
    ): Promise<NotificationPreferencesDto> {
      return client.request<NotificationPreferencesDto>(
        "/notifications/preferences",
        jsonBody("PATCH", { preferences }),
      );
    },
  };
}
