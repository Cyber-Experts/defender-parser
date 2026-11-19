// Receives files handed over by sister tools ("Open in Defender Parser"), browser
// to browser, with tab-handoff (https://github.com/Cyber-Experts/tab-handoff).
//
// A sender opens this page with `#handoff=<sender id>` and posts the files as
// Blobs with postMessage, addressed to this exact origin; nothing is uploaded
// and the URL carries nothing about them. The package accepts one message,
// only from the window that opened this tab and only from that sender's
// origins below, checks the count, sizes, Blob types and paths, then drops
// the reference to the opener and removes the flag. The files then go through
// the same intake as a dropped folder.

import { receiveHandoff as receive, type ReceivedFile } from "tab-handoff";

const dev = process.env.NODE_ENV === "development";

/** Sender id → its name and the exact origins it may hand files over from. */
export const HANDOFF_SENDERS: Record<string, { name: string; origins: readonly string[] }> = {
  "disk-image-parser": {
    name: "Disk Image Parser",
    origins: dev ? ["http://localhost:3000"] : ["https://www.diskimageparser.com", "https://diskimageparser.com"],
  },
};

/**
 * One handoff: the Defender folders (quarantine, DetectionHistory, support
 * logs), the Defender event logs, MpCmdRun.log and the SOFTWARE hive of one or
 * more Windows volumes. A SOFTWARE hive reaches a few hundred MB on real
 * machines.
 */
export const HANDOFF_LIMITS = {
  maxFiles: 20000,
  maxFileBytes: 1024 * 1024 * 1024,
  maxTotalBytes: 2 * 1024 * 1024 * 1024,
} as const;

export interface HandoffHandlers {
  /** The page is waiting for the files from `tool`. */
  onWait: (tool: string) => void;
  onFiles: (files: ReceivedFile[]) => void;
  /** No files arrived from `tool` in time. */
  onTimeout: (tool: string) => void;
}

/** Starts receiving when this page was opened for a handoff; returns a cleanup. */
export function receiveHandoff(h: HandoffHandlers): () => void {
  const name = (id: string) => HANDOFF_SENDERS[id]?.name ?? id;
  return receive({
    senders: Object.fromEntries(Object.entries(HANDOFF_SENDERS).map(([id, s]) => [id, s.origins])),
    ...HANDOFF_LIMITS,
    onWait: (id) => h.onWait(name(id)),
    onFiles: (files) => h.onFiles(files),
    onTimeout: (id) => h.onTimeout(name(id)),
  });
}
