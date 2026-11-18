import type { DeleteResult } from "../../types/intel";
import { plural } from "./format";

/** What a deletion did, in a sentence, for the notice shown afterwards. */
export function describeDeletion({ deleted, not_found, observations_removed }: DeleteResult): string {
  const gone =
    not_found.length === 0
      ? ""
      : ` ${plural(not_found.length, "indicator")} ${not_found.length === 1 ? "was" : "were"} already gone.`;
  if (deleted.length === 0) return `Nothing was deleted.${gone}`;
  return `Deleted ${plural(deleted.length, "indicator")} and ${plural(observations_removed, "stored provider answer")}.${gone}`;
}
