import type { Me } from "../types/api";
import { request } from "./apiClient";

function isMe(value: unknown): value is Me {
  return (
    typeof value === "object" &&
    value !== null &&
    "subject" in value &&
    typeof value.subject === "string" &&
    "name" in value &&
    (value.name === null || typeof value.name === "string") &&
    "roles" in value &&
    Array.isArray(value.roles) &&
    value.roles.every((role) => typeof role === "string") &&
    "auth_mode" in value &&
    (value.auth_mode === "dev" || value.auth_mode === "entra")
  );
}

/** Who the API thinks the caller is. Shown as a role badge; the subject id is never displayed. */
export function fetchMe(signal?: AbortSignal): Promise<Me> {
  return request("/api/v1/me", { signal, guard: isMe });
}
