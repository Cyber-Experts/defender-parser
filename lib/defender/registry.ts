// The Defender settings in the SOFTWARE hive. Only these keys are read:
//
//   Microsoft\Windows Defender                      (and the same under Policies\Microsoft\Windows Defender)
//     \Exclusions\Paths, Extensions, Processes, IpAddresses, TemporaryPaths
//     \Real-Time Protection
//     \Spynet                                        (MAPS: cloud protection)
//     \Features                                      (TamperProtection)
//
// Exclusions: one value per excluded item, its name the item (Dissect's
// exclusions reader, Windows Persistence). A key's LastWrite time is shared
// by all its values: it dates the latest change to the key, not each value.
//
// Meanings, only where a source states them: the Disable* switches (1 = off)
// from Microsoft's Defender policy documentation; SpynetReporting (0 off,
// 1 basic, 2 advanced) and SubmitSamplesConsent (0 always prompt, 1 send safe
// samples, 2 never send, 3 send all) from Set-MpPreference's MAPSReporting
// and SubmitSamplesConsent; TamperProtection 5 = on and 4 or 0 = off from
// community write-ups and Elastic's "Microsoft Windows Defender Tampering"
// rule (Microsoft does not document the value). Other values are shown as
// written, not interpreted.

import { REG_DWORD, REG_QWORD, valueNumber, valueText, type Hive, type Key } from "./regf";

export type RegGroup = "defender" | "exclusion" | "rtp" | "spynet" | "features";
export type ExclusionKind = "Paths" | "Extensions" | "Processes" | "IpAddresses" | "TemporaryPaths";
export const EXCLUSION_KINDS: ExclusionKind[] = ["Paths", "Extensions", "Processes", "IpAddresses", "TemporaryPaths"];

export interface RegValueRaw {
  name: string;
  type: number;
  typeName: string;
  /** Strings as stored, numbers in decimal, binary as hex. */
  text: string;
  num?: number;
  /** A sourced meaning code (dictionary: meaning_<code>), when there is one. */
  meaning?: string;
}

export interface RegKeyRaw {
  keyPath: string;
  group: RegGroup;
  policy: boolean;
  exclusionKind?: ExclusionKind;
  lastWrite: number | null;
  values: RegValueRaw[];
}

const TYPE_NAMES: Record<number, string> = { 0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 11: "REG_QWORD" };
const MAX_VALUES = 20_000;

/** The meaning of a setting's value, by its name and number, where a source states it. */
export function meaningOf(group: RegGroup, name: string, n: number | undefined): string | undefined {
  if (n === undefined) return undefined;
  const v = name.toLowerCase();
  if ((group === "rtp" || group === "defender") && /^disable/.test(v)) return n === 1 ? "switched_off" : n === 0 ? "switched_on" : undefined;
  if (group === "spynet" && v === "spynetreporting") return ({ 0: "maps_off", 1: "maps_basic", 2: "maps_advanced" } as Record<number, string>)[n];
  if (group === "spynet" && v === "submitsamplesconsent") return ({ 0: "samples_prompt", 1: "samples_safe", 2: "samples_never", 3: "samples_all" } as Record<number, string>)[n];
  if (group === "features" && v === "tamperprotection") return n === 5 ? "tamper_on" : n === 4 || n === 0 ? "tamper_off" : undefined;
  return undefined;
}

function read(k: Key, group: RegGroup, policy: boolean, exclusionKind?: ExclusionKind): RegKeyRaw {
  const values = k
    .values()
    .slice(0, MAX_VALUES)
    .map((v): RegValueRaw => {
      const num = v.type === REG_DWORD || v.type === REG_QWORD || group !== "exclusion" ? valueNumber(v) : undefined;
      const meaning = group === "exclusion" ? undefined : meaningOf(group, v.name, num);
      return { name: v.name, type: v.type, typeName: TYPE_NAMES[v.type] ?? `type ${v.type}`, text: valueText(v) ?? "", ...(num !== undefined ? { num } : {}), ...(meaning ? { meaning } : {}) };
    });
  return { keyPath: k.path, group, policy, ...(exclusionKind ? { exclusionKind } : {}), lastWrite: k.lastWrite, values };
}

export interface DefenderRegistry {
  keys: RegKeyRaw[];
  /** Keys that could not be read (damaged). */
  damaged: string[];
  /** Neither Microsoft\Windows Defender nor its policy key is in the hive. */
  absent: boolean;
}

/** The Defender keys of a SOFTWARE hive (and their policy copies). */
export function readDefenderKeys(hive: Hive): DefenderRegistry {
  const out: DefenderRegistry = { keys: [], damaged: [], absent: true };
  const sub = (path: string): Key | undefined => {
    try {
      return hive.root.subkey(path);
    } catch {
      out.damaged.push(path);
      return undefined;
    }
  };
  for (const [base, policy] of [
    ["Microsoft\\Windows Defender", false],
    ["Policies\\Microsoft\\Windows Defender", true],
  ] as const) {
    const root = sub(base);
    if (!root) continue;
    out.absent = false;
    const tryRead = (k: Key | undefined, group: RegGroup, kind?: ExclusionKind) => {
      if (!k) return;
      try {
        out.keys.push(read(k, group, policy, kind));
      } catch {
        out.damaged.push(k.path);
      }
    };
    tryRead(root, "defender");
    tryRead(sub(`${base}\\Exclusions`), "exclusion");
    for (const kind of EXCLUSION_KINDS) tryRead(sub(`${base}\\Exclusions\\${kind}`), "exclusion", kind);
    tryRead(sub(`${base}\\Real-Time Protection`), "rtp");
    tryRead(sub(`${base}\\Spynet`), "spynet");
    tryRead(sub(`${base}\\Features`), "features");
  }
  return out;
}
