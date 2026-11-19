# Sample sources

`scripts/make-samples.ts` builds the FIN-WKS-07 sample with this SOFTWARE
hive, copied unchanged from the Windows Persistence sample so that every site
shows the same Defender keys and key times: `Exclusions\Paths` =
`C:\ProgramData\Intel` and `Exclusions\Processes` = `m64.exe`, both keys
written at 2026-09-14 10:08:12 UTC, and `Features\TamperProtection` = 5. The
script writes it into the sample as it is (its modification time,
2026-09-14 10:55:12 UTC, is Windows Persistence's).

- Repository: windows-persistence (github.com/Cyber-Experts/windows-persistence)
- Commit: `1aade7f86866de2afb56533bb769dbcc48ed0ec3` (the hive last changed in `9de1b70dfe826316ee8b1b91b2fc54ae1ef917fa`)
- Source file: `public/samples/FIN-WKS-07/C/Windows/System32/config/SOFTWARE`

The quarantined m64.exe is the same benign placeholder Disk Image Parser's
sample disk holds (`disk-image-parser/scripts/make-samples.py`,
`placeholder("m64.exe", 9_216)`, commit `910b429`): readable text that says it
is a synthetic placeholder, not an executable, so its hashes match across the
two sites. Everything is synthetic: no real program, hash, threat family or
person.

| File | SHA-256 |
|---|---|
| `windows-persistence/C/Windows/System32/config/SOFTWARE` | `f3023606953e3b886061ead3d50b24d00cf63e51d56d565057dea40f74239c6e` |
