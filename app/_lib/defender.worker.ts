/// <reference lib="webworker" />
// Runs the Defender engine off the main thread. Receives the collected files
// (File objects travel by reference), reads them, reads each Defender event
// log with EVTX Parser's WebAssembly reader (vendor/evtx), analyses, replies.
// Recovered quarantine content is not part of the reply: the analysis only
// describes it.

import init, { EvtxHandle } from "@/vendor/evtx/evtx_wasm.js";
import { analyze } from "@/lib/defender/engine";
import { readEvtx, type EvtxFileRaw } from "@/lib/defender/evtx";
import type { InputFile } from "@/lib/defender/types";

export interface WorkerRequest {
  files: { path: string; file: File; mtimeApprox?: boolean }[];
}

export type WorkerMessage =
  | { type: "progress"; done: number; total: number }
  | { type: "done"; analysis: ReturnType<typeof analyze> }
  | { type: "error"; message: string };

const post = (m: WorkerMessage) => (self as unknown as DedicatedWorkerGlobalScope).postMessage(m);

let wasm: Promise<unknown> | null = null;

/** EVTX files, by their signature or their name, through the WebAssembly reader (which reports what is not one). */
async function readLogs(inputs: InputFile[]): Promise<EvtxFileRaw[]> {
  const logs = inputs.filter((i) => /\.evtx$/i.test(i.path) || (i.bytes.length >= 8 && String.fromCharCode(...i.bytes.subarray(0, 7)) === "ElfFile"));
  if (!logs.length) return [];
  wasm ??= init({ module_or_path: new URL("/evtx_wasm_bg.wasm", self.location.origin) });
  try {
    await wasm;
  } catch (err) {
    return logs.map((l) => ({ path: l.path, records: [], total: 0, error: `the EVTX reader could not load: ${err instanceof Error ? err.message : String(err)}` }));
  }
  return logs.map((l) => readEvtx(l.path, l.bytes, (b) => new EvtxHandle(b)));
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  try {
    const inputs: InputFile[] = [];
    const total = e.data.files.length;
    let done = 0;
    for (const f of e.data.files) {
      inputs.push({
        path: f.path,
        mtime: f.file.lastModified > 0 ? f.file.lastModified : null,
        ...(f.mtimeApprox && f.file.lastModified > 0 ? { mtimeApprox: true } : {}),
        bytes: new Uint8Array(await f.file.arrayBuffer()),
      });
      if (++done % 200 === 0) post({ type: "progress", done, total });
    }
    const logs = await readLogs(inputs);
    post({ type: "done", analysis: analyze(inputs, logs) });
  } catch (err) {
    post({ type: "error", message: err instanceof Error ? err.message : String(err) });
  }
};
