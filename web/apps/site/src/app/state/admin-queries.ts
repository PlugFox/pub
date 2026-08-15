import { query } from "@solidjs/router";
import { api } from "./api";

/*
 * Admin-plane queries shared by more than one panel.
 *
 * `GET /api/v1/admin/settings` has two readers now: the settings form edits it,
 * and the organizations table's quota editor needs `registry.storage_quota_bytes`
 * to label its "follow the instance default" choice with the number that
 * default currently is (S-20.b). Declaring the query twice would give
 * solid-router two cache entries under one key and two round trips for one
 * document, so it is declared once here and imported.
 *
 * The table itself no longer needs it: `effective_quota_bytes` arrives resolved
 * on every org row, because the three-state rule belongs to one server function
 * and not to two implementations of it.
 *
 * The key is unchanged (`admin-settings`) — the settings form still
 * revalidates it by name after a save.
 */

export const ADMIN_SETTINGS_KEY = "admin-settings";

export const adminSettingsQuery = query(() => api.admin.settings(), ADMIN_SETTINGS_KEY);
