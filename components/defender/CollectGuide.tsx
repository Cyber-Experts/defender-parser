"use client";

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { Check, Copy, FolderInput, Lock, TerminalSquare } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ToolDict } from "@/lib/defender/dict";

type CollectDict = ToolDict["collect"];

/*
 * The commands keep the Windows layout under a folder named after the host
 * (<host>\C\ProgramData\Microsoft\Windows Defender\…, <host>\C\Windows\…),
 * which the intake (lib/intake/collect.ts) and the engine use to place each
 * file. Run them as an administrator: the Defender folders are readable by
 * administrators and SYSTEM only.
 */

/** Elevated Command Prompt: the Defender folders, the event log, MpCmdRun.log, SOFTWARE. */
const COPY = String.raw`set CASE=E:\case\%COMPUTERNAME%\C
robocopy "C:\ProgramData\Microsoft\Windows Defender" "%CASE%\ProgramData\Microsoft\Windows Defender" /E /B /COPY:DAT /DCOPY:T /XD "Definition Updates"
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "%CASE%\Defender-Operational.evtx"
robocopy C:\Windows\Temp "%CASE%\Windows\Temp" MpCmdRun.log* /COPY:DAT
rem Each user's own MpCmdRun.log, if they ran MpCmdRun.exe:
for /d %u in (C:\Users\*) do robocopy "%u\AppData\Local\Temp" "%CASE%\Users\%~nxu\AppData\Local\Temp" MpCmdRun.log* /COPY:DAT
reg save HKLM\SOFTWARE "%CASE%\Windows\System32\config\SOFTWARE"`;

const KAPE = String.raw`kape.exe --tsource C: --tdest E:\case\%COMPUTERNAME% --target WindowsDefender,RegistryHivesSystem --zip defender`;

const VELOCIRAPTOR = String.raw`Artifact:  Windows.KapeFiles.Targets   (Windows.Triage.Targets in recent releases)
Targets:   WindowsDefender, RegistryHivesSystem
Result:    the collection's zip (uploads/auto/C%3A/ProgramData/Microsoft/Windows Defender/…)`;

const POWERSHELL = String.raw`Get-MpThreatDetection | Format-List
Get-MpPreference | Select-Object Exclusion*, DisableRealtimeMonitoring
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5013)]]" |
  Format-List TimeCreated, Id, Message`;

const WHERE = String.raw`C:\ProgramData\Microsoft\Windows Defender\Quarantine\Entries\{GUID}                 quarantine entries (RC4)
C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\<xx>\<SHA-1>      quarantined content (RC4): live malware
C:\ProgramData\Microsoft\Windows Defender\Quarantine\Resources\<xx>\<SHA-1>         content records (RC4)
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<nn>\<GUID>
C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log, MPDetection-*.log
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx
C:\Windows\Temp\MpCmdRun.log, and %TEMP%\MpCmdRun.log of a user who ran MpCmdRun.exe
SOFTWARE  Microsoft\Windows Defender\Exclusions, Real-Time Protection, Spynet, Features
SOFTWARE  Policies\Microsoft\Windows Defender (the same keys set by policy)`;

type TabKey = "copy" | "kape" | "velociraptor" | "powershell" | "where";
const TABS: TabKey[] = ["copy", "kape", "velociraptor", "powershell", "where"];

export function CollectGuide({ dict, id, className }: { dict: CollectDict; id?: string; className?: string }) {
  const base = useId();
  const [active, setActive] = useState<TabKey>("copy");
  const tabRefs = useRef<Record<TabKey, HTMLButtonElement | null>>({ copy: null, kape: null, velociraptor: null, powershell: null, where: null });

  const label: Record<TabKey, string> = { copy: dict.tabCopy, kape: dict.tabKape, velociraptor: dict.tabVelociraptor, powershell: dict.tabPowershell, where: dict.tabWhere };

  const onTabKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = TABS.indexOf(active);
    const next =
      e.key === "ArrowRight" ? TABS[(i + 1) % TABS.length]
      : e.key === "ArrowLeft" ? TABS[(i - 1 + TABS.length) % TABS.length]
      : e.key === "Home" ? TABS[0]
      : e.key === "End" ? TABS[TABS.length - 1]
      : null;
    if (!next) return;
    e.preventDefault();
    setActive(next);
    tabRefs.current[next]?.focus();
  };

  const steps = [
    { icon: TerminalSquare, text: dict.step1 },
    { icon: FolderInput, text: dict.step2 },
    { icon: Lock, text: dict.step3 },
  ];

  return (
    <section id={id} aria-labelledby={`${base}-title`} className={cn("min-w-0 scroll-mt-20 rounded-2xl border bg-card px-4 py-5 shadow-[var(--shadow-soft)] sm:px-6", className)}>
      <h2 id={`${base}-title`} className="font-heading text-base font-bold">
        {dict.title}
      </h2>
      <p className="mt-1 max-w-3xl text-sm leading-relaxed [overflow-wrap:anywhere] text-muted-foreground">{dict.intro}</p>

      <ol className="mt-4 grid gap-2 sm:grid-cols-3">
        {steps.map(({ icon: Icon, text }, i) => (
          <li key={text} className="flex min-w-0 items-center gap-2.5 rounded-lg border bg-surface/70 px-3 py-2 text-sm">
            <span aria-hidden className="grid size-6 shrink-0 place-items-center rounded-full bg-primary font-mono text-xs font-semibold text-primary-foreground">
              {i + 1}
            </span>
            <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="min-w-0 leading-snug">{text}</span>
          </li>
        ))}
      </ol>

      <div className="mt-5 min-w-0 overflow-hidden rounded-xl border bg-card">
        <div role="tablist" aria-label={dict.tabsLabel} className="flex flex-wrap gap-1 border-b bg-muted/40 p-1.5">
          {TABS.map((key) => {
            const selected = key === active;
            return (
              <button
                key={key}
                ref={(el) => {
                  tabRefs.current[key] = el;
                }}
                type="button"
                role="tab"
                id={`${base}-tab-${key}`}
                aria-selected={selected}
                aria-controls={`${base}-panel-${key}`}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActive(key)}
                onKeyDown={onTabKey}
                className={cn(
                  "inline-flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium whitespace-nowrap transition-colors motion-reduce:transition-none",
                  selected ? "bg-card text-foreground shadow-[var(--shadow-soft)]" : "text-muted-foreground hover:bg-card/60 hover:text-foreground",
                )}
              >
                {label[key]}
                {key === "copy" && <span className="rounded-full bg-accent px-1.5 py-px text-[0.65rem] font-semibold text-accent-foreground">{dict.recommended}</span>}
              </button>
            );
          })}
        </div>

        {TABS.map((key) => (
          <div
            key={key}
            role="tabpanel"
            id={`${base}-panel-${key}`}
            aria-labelledby={`${base}-tab-${key}`}
            hidden={key !== active}
            tabIndex={0}
            className="min-w-0 space-y-3 p-3 text-sm leading-relaxed [overflow-wrap:anywhere] outline-none sm:p-4"
          >
            {key === "copy" && (
              <>
                <CodeBlock code={COPY} lang="Command Prompt · administrator" dict={dict} />
                <p className="text-muted-foreground">{dict.copyNote}</p>
              </>
            )}
            {key === "kape" && (
              <>
                <CodeBlock code={KAPE} lang="Command Prompt · administrator" dict={dict} />
                <p className="text-muted-foreground">{dict.kapeNote}</p>
              </>
            )}
            {key === "velociraptor" && (
              <>
                <CodeBlock code={VELOCIRAPTOR} lang="Velociraptor collection" dict={dict} />
                <p className="text-muted-foreground">{dict.velociraptorNote}</p>
              </>
            )}
            {key === "powershell" && (
              <>
                <CodeBlock code={POWERSHELL} lang="PowerShell · administrator" dict={dict} />
                <p className="text-muted-foreground">{dict.powershellNote}</p>
              </>
            )}
            {key === "where" && (
              <>
                <CodeBlock code={WHERE} lang="paths and keys" dict={dict} />
                <p className="text-muted-foreground">{dict.whereNote}</p>
              </>
            )}
          </div>
        ))}
      </div>

      <div className="mt-4 rounded-xl border border-sev-medium/30 bg-sev-medium-bg/60 px-4 py-3 text-sm">
        <h3 className="font-semibold text-sev-medium">{dict.gotchasTitle}</h3>
        <ul className="mt-1.5 list-disc space-y-1 pl-5 leading-relaxed marker:text-sev-medium">
          {dict.gotchas.map((g) => (
            <li key={g}>{g}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy path
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

function CodeBlock({ code, lang, dict }: { code: string; lang: string; dict: CollectDict }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const pre = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 2000);
    return () => clearTimeout(timer);
  }, [state]);

  const onCopy = async () => {
    if (await writeClipboard(code)) {
      setState("copied");
      return;
    }
    // Last resort: select the command so Ctrl+C / long-press works.
    const el = pre.current;
    const sel = window.getSelection();
    if (el && sel) {
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);
    }
    setState("failed");
  };

  return (
    <div className="min-w-0 overflow-hidden rounded-lg bg-[var(--code-bg)] text-[var(--code-fg)] shadow-[var(--shadow-soft)] ring-1 ring-black/10 dark:ring-white/10">
      <div className="flex items-center justify-between gap-2 border-b border-white/10 px-3 py-1">
        <span className="inline-flex min-w-0 items-center gap-2 truncate font-mono text-[0.68rem] text-white/60">
          <span aria-hidden className="text-brand-300">$</span>
          {lang}
        </span>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-white/70 transition-colors hover:bg-white/10 hover:text-white motion-reduce:transition-none"
        >
          {state === "copied" ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
          {state === "copied" ? dict.copied : dict.copy}
        </button>
        <span aria-live="polite" className="sr-only">
          {state === "copied" ? dict.copied : state === "failed" ? dict.copyFailed : ""}
        </span>
      </div>
      <pre ref={pre} tabIndex={0} className="overflow-x-auto p-3 font-mono text-xs leading-relaxed whitespace-pre outline-none">
        <code>{code}</code>
      </pre>
      {state === "failed" && <p className="border-t border-white/10 px-3 py-1.5 text-xs text-white/80">{dict.copyFailed}</p>}
    </div>
  );
}
