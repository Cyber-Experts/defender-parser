# EVTX reader (vendored)

`evtx_wasm.js`, `evtx_wasm.d.ts` and `public/evtx_wasm_bg.wasm` are the
WebAssembly build of EVTX Parser's Rust reader (`crates/evtx-wasm`, built on
the `evtx` crate 0.8.5), copied from Cyber-Experts/evtx-parser:

- Repository: github.com/Cyber-Experts/evtx-parser
- Commit: `3f91f7d63e8e4dfd9703bcd768c3a4e91f336e18` (the build files last
  changed in `88f2d706159e353276e20d56b30d2ac2b77c4c47`)
- Source folder: `lib/evtx-wasm/`

| File | SHA-256 |
|---|---|
| `vendor/evtx/evtx_wasm.js` | `ef39f62f5a54d1106e7f64521f529362a25a0a10e8ed0b3030f9e65b99e4edda` |
| `vendor/evtx/evtx_wasm.d.ts` | `e349cf695864044fd700b87f27132551e8fe179fe90c724c17979bf6ebca0e8a` |
| `public/evtx_wasm_bg.wasm` | `74d618d696073fa231432c5ceec4096065416d3b57a02845de5633423a0b7289` |

One change, as Windows Persistence made to its vendored WMI glue: when
`init` gets no `module_or_path`, the glue throws instead of building
`new URL('evtx_wasm_bg.wasm', import.meta.url)`, which the bundler would try to
resolve next to the script (the module is served from `public/`). The file as
copied had SHA-256 `cf898c0fa723683aaeff0e8f8ddea798f1def0b28281edd60693678f618e047f`.

Only `EvtxHandle` is used (`lib/defender/evtx.ts`): its constructor reads every
record of the file, `count`, `get_chunk` (record ID, time, event ID, level,
provider, channel, computer), `get_event_data` (the `<EventData>` /
`<UserData>` pairs) and `get_xml` (the record's XML, kept as the raw source).
The worker loads it with `init({ module_or_path: new URL("/evtx_wasm_bg.wasm", origin) })`;
the tests with `initSync`. The page's CSP allows `'wasm-unsafe-eval'` for it.

To update: rebuild in evtx-parser, copy the three files here and record the
new commit and hashes above (`tests/decoders.test.ts` checks them).
