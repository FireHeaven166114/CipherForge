/** Shapes returned by the CipherForge API. Keep in sync with backend/app/schemas. */

export interface HealthResponse {
  status: "ok";
  service: string;
  version: string;
}

export interface ReadinessResponse {
  status: "ready" | "not_ready";
  checks: Record<string, "ok" | "unavailable">;
}

/** The signed-in caller, from `GET /api/v1/me`. Keep in sync with backend/app/schemas/identity.py. */
export interface Me {
  subject: string;
  name: string | null;
  roles: string[];
  auth_mode: "dev" | "entra";
}

/** Every API error uses this envelope; see backend/app/core/errors.py. */
export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
    correlation_id?: string;
  };
}
