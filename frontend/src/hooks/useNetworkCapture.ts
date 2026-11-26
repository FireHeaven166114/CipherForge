import { useCallback } from "react";

import type { ApiError } from "../services/apiClient";
import { startCapture, stopCapture } from "../services/networkService";
import type { NetworkStatus } from "../types/network";
import { useNetworkAction } from "./useNetworkAction";

type CaptureCommand = { kind: "start"; interfaceId: string } | { kind: "stop" };

function execute(command: CaptureCommand): Promise<NetworkStatus> {
  return command.kind === "start" ? startCapture(command.interfaceId) : stopCapture();
}

export interface CaptureControls {
  /** Which command is waiting for the API, if any. */
  busy: "start" | "stop" | null;
  /** Why the last command failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /** Resolves to the status the API reports afterwards, or null when it failed or another command is running. */
  start: (interfaceId: string) => Promise<NetworkStatus | null>;
  stop: () => Promise<NetworkStatus | null>;
  reset: () => void;
}

/** Starts and stops the live capture, one command at a time. */
export function useNetworkCapture(): CaptureControls {
  const { pending, error, run, reset } = useNetworkAction(execute);

  const start = useCallback((interfaceId: string) => run({ kind: "start", interfaceId }), [run]);
  const stop = useCallback(() => run({ kind: "stop" }), [run]);

  return { busy: pending?.[0].kind ?? null, error, start, stop, reset };
}
