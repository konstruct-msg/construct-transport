# AGENTS.md — construct-transport

QUIC / HTTP-3 gRPC transport in Rust (quinn + h3), exposed to Swift through UniFFI as
`ConstructTransport.xcframework`, plus the `gateway` binary (h3 → h2c reverse proxy) and
diagnostic binaries (`probe`, `udpcheck`, `smoke`). Transport only: it moves bytes and reports
what it saw; it holds no crypto state and decides nothing about sessions. If a rule here and your
plan disagree, the rule wins until a `decisions/` note says otherwise.

| Area | Read first |
|---|---|
| Why these rules exist; checklist before any new protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Why a dedicated Rust stack | `~/Code/construct-docs/decisions/quic-h3-transport-dedicated-rust-stack.md` |
| Plain vs obfuscated QUIC, what the network blocks | `decisions/quic-plain-vs-obfuscated.md` · `decisions/quic-suppression-ladder.md` · `decisions/udp-stealth-tier-evaluation.md` |
| Connection health, escalation | `decisions/transport-connection-health-and-escalation.md` |
| UDP receive errors | `decisions/udp-receive-errors-terminate-endpoints.md` |
| Salamander | `decisions/salamander-psk-shared-per-gateway.md` · `decisions/quic-moderate-dpi-udp-obfuscation.md` |
| Route per platform, shared vectors | `decisions/transport-route-per-platform-shared-vectors.md` (vectors in `construct-protos/conformance/transport_route.json`) |
| Reachability probe | `testing/UDP_QUIC_REACHABILITY_TESTER_RUNBOOK.md` |
| One meaning, two carriers | `decisions/one-meaning-two-carriers.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) — paths above are relative to it |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md`. Change it there first.

## Rules

1. **Prior art first.** Transport behaviour (handover, keepalive, congestion, retries) starts from what QUIC RFCs, quinn and h3 already do; a custom mechanism needs a note saying why they do not suffice.
2. **Transport only.** Sessions, ratchets and message meaning stay in `construct-core`. This crate carries opaque bytes and reports connection facts; it never reads a payload.
3. **Time is not an address.** A retry budget, cooldown or timer that papers over an unknown state means the state should be reported to the caller. Fix the report, not the timer.
4. **Reproduce before fixing.** A transport bug gets a failing test in `tests/` (or a `probe` / `udpcheck` run on the real path) before the fix; the fix counts when it turns green.
5. **One meaning, one carrier.** Route choice, endpoint state and error class are each decided in one place; the client's route-per-platform vectors live in `construct-protos`. Do not add a second copy of a classification here.
6. **Bytes stay bytes.** The FFI passes `bytes` (Swift `Data`), never `sequence<u8>` or base64/String.
7. **Measure, then build.** Obfuscation, relay or fronting changes start from a measurement on the real network path, not a hypothesis. The measured fact that closed the question: Russia drops UDP by destination — not by name, port or content — and Salamander measured worse than plain.
8. **The effect is the proof.** A transport fix is verified by `udpcheck` / `probe` against the real endpoint and by the counters, not by a build exit code. Heat or battery claims are read from the runtime line (`udperr`), not inferred.
9. **A test must be able to fail.** Break the behaviour on purpose and watch the test go red before trusting it; `cargo test` must show `Compiling` (see Toolchain).
10. **Depth before breadth.** No new transport (MASQUE, P2P, new obfuscation) while plain QUIC with H2 fallback is not boring on devices.
11. **A temporary exception has an end date and a check.** Experimental flags and the Salamander debug path name what removes them.
12. **Branch and PR, always;** see Git.

**Three questions before a change to the delivery path lands**, answered in the commit message: (1) what does the network, the server or a relay learn that it did not before (SNI, packet sizes, timing, endpoint addresses); (2) what can a party withhold or substitute that it could not before; (3) which trust boundary moves, and which way. An honest "something" is a `decisions/` note, not a merge.

**A producer with no consumer is a defect.** A new counter, event or FFI export lands with its reader (app, `udpcheck`, metrics) in the same change, or is removed. A handler no producer reaches is wired up or deleted.

## Invariants of this repo

- **Toolchain is pinned** in `rust-toolchain.toml` (1.96.0) and equals `rust-version` in `Cargo.toml`; raise both together. With a toolchain older than `rust-version`, `cargo test` re-ran a stale binary and reported green for source never compiled.
- **UDP receive errors terminate the endpoint**; `spin_free_socket` stops the spin on an error but does not ask why the socket is still polled. An abandoned endpoint heats the device — a `QuicChannel` must be closed by its owner (`close()` once had no caller).
- **Plain QUIC is the production default**; Salamander is DEBUG-only and release forces the flags, ignoring `UserDefaults`.
- **Native h3 server, no Traefik bridge**: bidirectional gRPC over h3 silent-fails through a QUIC↔h2c bridge. The `gateway` is the h3 → h2c proxy; H2 is the fallback.
- **Pure-ring crypto** (no `aws-lc-rs`), so the Docker builder needs no cmake/clang. Keep it that way.
- **`bindings/` is generated** by `uniffi-bindgen` 0.30 (`./build_ios.sh --bindings`); never hand-edit. A new FFI export updates the bindings and the app in the same change.
- **Build for the app**: `./build_ios.sh` (`--ios`, `--sim`, `--mac`, `--bindings`; default iOS + simulator) here, or `./build_transport_lib.sh --all` from `construct-messenger`. Use `--all` unless one platform is intended; a bare run omits the `macos-arm64` slice and the Desktop target then fails to link against a well-formed-looking xcframework.
- **Checks**: `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` (CI and `.githooks/pre-push`; install once per clone with `scripts/install-hooks.sh`), then `cargo test --all`. `SKIP_CHECKS=1` is for emergencies only.
- The Docker image ships three binaries: `gateway` (default), `construct-transport` (echo server), `probe`.

## Git

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from up-to-date `main`, PR into `main`. The owner merges. `main` is what a release is built from.
- Check `git branch --show-current` and `git status` before every commit; other sessions share the tree. Never `checkout -- .`, `restore .`, `reset --hard` or `stash`; name files. Never rewrite pushed history. A commit made on `main` by mistake and not pushed moves with `git branch <topic> && git reset --keep origin/main && git switch <topic>`.
- Docs: the vault's `AGENTS.md` is authoritative; a decision that constrains future work goes to `decisions/`, one line to `log.md`.
