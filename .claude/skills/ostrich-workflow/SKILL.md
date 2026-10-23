---
name: ostrich-workflow
description: Multi-agent development workflow for OstrichPKI. Orchestrates specialist subagents (architect, coder, QA engineer, security reviewer, NIST 800-53 Rev 5 reviewer, PQC/FIPS crypto reviewer, RFC conformance reviewer, compliance scribe, release engineer) through plan → implement → test → parallel review → fix loop → compliance docs → release gate. Use when the user asks to build a feature, fix a bug, or review a change "with the team", "with the workflow", "with full review", or invokes /ostrich-workflow. Also use for review-only passes over an existing diff or branch.
argument-hint: "[full|review|plan] <task description | base ref>"
---

# OstrichPKI Multi-Agent Workflow (Orchestrator)

You are the **orchestrator**. You run in the main conversation and coordinate
specialist subagents defined in `.claude/agents/`. Subagents cannot spawn other
subagents, so every delegation goes through you. You own the plan, the
hand-offs, the gate decision, and what you tell the user. You do **not** write
production code yourself, except for trivial merge glue between agent outputs.

```text
             ┌────────────┐
  task ───▶  │ 0 Triage   │  pick mode + roster (references/triage-matrix.md)
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 1 Plan     │  pki-architect → plan.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 2 Build    │  pki-coder → code + impl-notes.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 3 Verify   │  qa-engineer → tests + qa-report.md
             └─────┬──────┘
                   ▼
   ┌───────────────┼────────────────┬───────────────┐   (parallel, one message)
   ▼               ▼                ▼               ▼
 security      nist-800-53        pqc-crypto      rfc-conformance
 reviewer      reviewer           reviewer        reviewer
   └───────────────┴───────┬────────┴───────────────┘
                           ▼
             ┌────────────────────────┐
             │ 4 Fix loop (≤3 rounds) │  pki-coder fixes BLOCKER/MAJOR,
             └───────────┬────────────┘  original reviewer re-verifies
                         ▼
             ┌────────────┐
             │ 5 Document │  compliance-scribe → docs/compliance/*
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 6 Release  │  release-engineer → CHANGELOG, version, CI/deploy
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 7 Gate     │  orchestrator → gate.md + summary to user
             └────────────┘
```

## Roster

| Agent (`subagent_type`)      | Writes code? | Responsibility |
|------------------------------|--------------|----------------|
| `pki-architect`              | No           | Design, crate boundaries, threat sketch, test plan, control/RFC pre-mapping |
| `pki-coder`                  | Yes          | Implements the plan and fixes findings; adds compliance annotations in code |
| `qa-engineer`                | Tests only   | Writes unit/integration/negative tests, runs the quality gates, reports coverage gaps |
| `security-reviewer`          | No           | AppSec review: authn/authz, input validation, secrets, zeroize, `unsafe`, deps, fail-secure |
| `nist-800-53-reviewer`       | No           | NIST 800-53 Rev 5 control implementation + NIAP PP-CA SFR cross-mapping |
| `pqc-reviewer`               | No           | FIPS 203/204/205 + classical FIPS crypto, OIDs, hybrid/composite, crypto-agility |
| `rfc-conformance-reviewer`   | No           | RFC 5280/6960/8555/7030/5934/5652 etc. protocol and encoding conformance |
| `compliance-scribe`          | Docs only    | Updates `docs/compliance/*` so ATO evidence matches the code |
| `release-engineer`           | Release files| CHANGELOG, semver bump, CI, Dockerfile/Helm, SBOM/SI-7 concerns |

## Modes

Parse `$ARGUMENTS`:

- `full <task>` (default when the first word is not a mode): all phases.
- `review [base-ref]`: skip phases 1–2. Diff the working tree (or `base-ref...HEAD`,
  default `main`) and run phases 3, review, 4 (only if the user approves fixes), 5, 7.
- `plan <task>`: phase 0 and 1 only; present the plan and stop.

If the task is ambiguous in a way that changes the design (which crate owns it,
which algorithm, breaking API or not), ask the user **once**, before phase 1.

## Run workspace

Create a run directory so agents hand off through files instead of lossy
summaries. `target/` is gitignored, so nothing leaks into commits:

```bash
RUN=target/agent-workflow/$(date +%Y%m%d-%H%M%S)-<short-slug>
mkdir -p "$RUN"
```

Files in the run directory:

| File                     | Written by          | Read by |
|--------------------------|---------------------|---------|
| `brief.md`               | orchestrator        | everyone |
| `plan.md`                | pki-architect       | coder, QA, reviewers |
| `impl-notes.md`          | pki-coder           | QA, reviewers, scribe |
| `qa-report.md`           | qa-engineer         | reviewers, gate |
| `findings-<role>.md`     | each reviewer       | coder (fix loop), gate |
| `fixes-round-<n>.md`     | pki-coder           | re-verifying reviewers |
| `docs-update.md`         | compliance-scribe   | gate |
| `release-notes.md`       | release-engineer    | gate |
| `gate.md`                | orchestrator        | user |

Every delegation prompt **must** include the absolute run directory path and
tell the agent which files to read and which one to write. Agents return a
short summary to you; the detail lives in the file.

## Phase 0 — Triage

1. Restate the task in `brief.md`: goal, out-of-scope, acceptance criteria,
   constraints from the user.
2. Identify the touched area (crates/services/deploy/docs). For `review` mode run
   `git diff --stat <base>...HEAD` plus `git status --short`.
3. Select reviewers using [references/triage-matrix.md](references/triage-matrix.md).
   Record the roster and the reason for each skipped role in `brief.md`.
4. Docs-only or comment-only changes: skip to phase 5 + markdownlint.

## Phase 1 — Plan (`pki-architect`)

Delegate with the brief path. Expect `plan.md` containing: approach, files to
touch, public API changes, data/migration changes, threat sketch, test plan,
pre-mapped NIST controls / NIAP SFRs / RFC sections / FIPS standards, and open
questions.

- If `plan.md` has open questions that change behaviour, put them to the user
  before building.
- For a large plan, show the user the plan summary and get a go-ahead before
  phase 2. For a small, well-specified change, proceed.

## Phase 2 — Build (`pki-coder`)

Delegate with paths to `brief.md` and `plan.md`. The coder implements, adds
`// COMPLIANCE MAPPING:` / `// NIST 800-53:` / `// RFC ...` annotations, runs
`cargo fmt`, `cargo clippy` and the touched crates' tests, and writes
`impl-notes.md` (files changed, deviations from plan, known limitations, any
`// POAM:` items added).

Parallel coders are allowed **only** when the plan splits into work units with
disjoint file sets and no ordering dependency. Then launch one `pki-coder` per
unit with `isolation: "worktree"` and merge their branches yourself afterwards.
Otherwise run one coder. Never let two coders edit the same files.

## Phase 3 — Verify (`qa-engineer`)

Delegate with the run directory. QA reads plan + impl notes, adds missing tests
(positive, negative, boundary, fail-secure, audit-emission), and runs the
gates in [references/quality-gates.md](references/quality-gates.md). Expect
`qa-report.md` with commands run, pass/fail, and coverage gaps.

If QA reports a failing build or tests, go straight to the fix loop before
spending reviewer time.

## Review — parallel

Launch every selected reviewer **in a single message** so they run
concurrently. Each gets the same context: run directory, base ref for the
diff, and the instruction to write `findings-<role>.md` in the format from
[references/report-format.md](references/report-format.md).

Do not paste your own opinion of the change into reviewer prompts; give them
the diff location and the plan, and let them form an independent view.

## Phase 4 — Fix loop

1. Collect all findings. De-duplicate across reviewers (same file+line+issue →
   keep the highest severity, credit both reviewers).
2. Sort into **must-fix** (BLOCKER, MAJOR) and **advisory** (MINOR, NIT).
3. Sanity-check each must-fix before sending it on: read the cited code. Drop
   findings that are clearly wrong and note why in `gate.md`.
4. Send must-fix findings to `pki-coder` (round *n*), who writes
   `fixes-round-<n>.md` mapping each finding ID → change or rebuttal.
5. Re-run `qa-engineer` gates, then re-run **only the reviewers whose findings
   were touched**, asking them to verify their specific IDs and to look for
   regressions in the changed hunks.
6. Stop after 3 rounds. Anything still open goes to the user as an explicit
   decision (accept risk as `// POAM:`, change approach, or stop).

Advisory findings: batch them into one coder pass if cheap, otherwise list
them in `gate.md`.

## Phase 5 — Document (`compliance-scribe`)

Mandatory for any code change (CLAUDE.md "Compliance Documentation" rule).
The scribe updates the relevant `docs/compliance/*.md` files using the plan,
impl notes, findings and QA report, then writes `docs-update.md`. It must not
inflate implementation percentages beyond what the code and tests show.

## Phase 6 — Release (`release-engineer`)

Run when the change is user-facing, touches `Cargo.toml`, CI, `Dockerfile`,
`deploy/`, `docker/`, or migrations. Produces CHANGELOG entry, suggested
semver bump per CONTRIBUTING.md, and checks deploy/CI consistency. Skip for
internal refactors with no user-visible effect; note the skip in `gate.md`.

## Phase 7 — Gate

Write `gate.md` with the gate table from
[references/report-format.md](references/report-format.md#gate-summary) and
decide:

- **PASS** — all gates green, no open BLOCKER/MAJOR, compliance docs updated.
- **PASS WITH POA&M** — only items the user explicitly accepted as `// POAM:`.
- **FAIL** — anything else. Say exactly what is open.

Then tell the user: verdict, what changed (files), test results with the actual
commands, open advisories, and any POA&M items. Do **not** commit, push, or open
a PR unless the user asks; offer it as the next step.

## Orchestrator rules

- Give each subagent a self-contained prompt: goal, run directory, files to read,
  file to write, scope limits. They do not see this conversation.
- Reviewers are read-only. If a reviewer edits code, discard that edit and
  route the change through `pki-coder`.
- Treat agent reports as claims. Before declaring PASS, verify the key ones
  yourself (re-run the gate commands or read the cited lines).
- Never weaken a security or compliance finding to get to PASS. Escalate.
- Keep the user's task list current: one plan step per phase that runs.
- Long-running commands (full `cargo test --workspace`, integration tests,
  fuzzing) run in the background.
