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

/** Every API error uses this envelope; see backend/app/core/errors.py. */
export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
    correlation_id?: string;
  };
}
