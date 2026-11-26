import { useCallback, useRef } from "react";

import { listInterfaces } from "../services/networkService";
import type { InterfaceList } from "../types/network";
import { type LiveResource, useLiveResource } from "./useLiveResource";

/**
 * The interfaces capture can start on. They are read once; `refresh` asks the server to look at the
 * machine's interfaces again (a plugged-in adapter, a connected VPN) and keeps the old list on
 * screen until the new one arrives.
 */
export function useNetworkInterfaces(): LiveResource<InterfaceList> {
  const rescan = useRef(false);

  const load = useCallback((signal: AbortSignal) => {
    const fresh = rescan.current;
    rescan.current = false;
    return listInterfaces(fresh, signal);
  }, []);

  const { state, refresh } = useLiveResource(load, 0);

  const rescanNow = useCallback(() => {
    rescan.current = true;
    refresh();
  }, [refresh]);

  return { state, refresh: rescanNow };
}
