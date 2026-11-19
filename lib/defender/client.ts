// Main-thread side of the worker: one worker per analysis, terminated after.

import type { Artifact } from "@/lib/intake/collect";
import type { Analysis } from "./types";
import type { WorkerMessage, WorkerRequest } from "@/app/_lib/defender.worker";

export function analyzeInWorker(artifacts: Artifact[], onProgress?: (done: number, total: number) => void): Promise<Analysis> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("../../app/_lib/defender.worker.ts", import.meta.url), { type: "module" });
    const finish = () => worker.terminate();
    worker.onmessage = (e: MessageEvent<WorkerMessage>) => {
      const m = e.data;
      if (m.type === "progress") onProgress?.(m.done, m.total);
      else if (m.type === "done") {
        finish();
        resolve(m.analysis);
      } else {
        finish();
        reject(new Error(m.message));
      }
    };
    worker.onerror = (e) => {
      finish();
      reject(new Error(e.message || "worker failed"));
    };
    const req: WorkerRequest = { files: artifacts.map((a) => ({ path: a.path, file: a.file, ...(a.mtimeApprox ? { mtimeApprox: true } : {}) })) };
    worker.postMessage(req);
  });
}
