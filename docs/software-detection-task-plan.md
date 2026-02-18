# Task Plan: Software Install Detection Accuracy + Performance

## Goal
Improve Inspect software detection so it is:
1. **Accurate first**: minimize false positives and false negatives.
2. **Fast second**: reduce total inspect runtime by avoiding repeated expensive probes.
3. **Robust across installers**: apps installed via winget, MSI/EXE, portable tools, per-user installs, and custom enterprise deployments.

---

## Problem Summary
Current detection relies heavily on per-app `winget list --id ...` plus per-app registry fallback.
This creates two classes of issues:

- **False positives** from broad matching (for example publisher-only matches).
- **False negatives** when apps are not represented in winget, or installed per-user / portable / custom paths.
- **Slow inspect** because command + registry scans repeat for each app.

Also, app footprints vary:
- Some add uninstall registry entries.
- Some create Start Menu shortcuts under `C:\ProgramData\Microsoft\Windows\Start Menu\Programs` (not universal).
- Some expose executable names on `%PATH%`.
- Some run services/scheduled tasks only.

---

## Detection Strategy (Accuracy-First)
Use a **multi-signal evidence model** with strict matching rules and explainable output.

### A) Evidence sources (ordered by trust)
1. **Registry uninstall entries** (HKLM + WOW6432Node + HKCU)
2. **Winget installed package inventory** (single bulk query)
3. **Executable discovery on `%PATH%`** (exact expected exe names only)
4. **Start Menu shortcuts** (`ProgramData` + per-user Start Menu)
5. **Known install paths / app-specific probes** (optional per app)
6. **Service/process signatures** (only where app naturally installs a service)

### B) Matching rules to prevent false positives
- Never mark installed from **publisher-only** match.
- Prefer **exact winget ID** or strict normalized ID equality.
- Registry requires:
  - exact/canonical product-name match; or
  - app-specific regex with word boundaries.
- Shortcut and PATH evidence alone should be **weak evidence** unless app config explicitly allows it.
- Require **minimum confidence threshold** before PASS.

### C) False negative defenses
- Include HKCU uninstall keys and per-user Start Menu paths.
- Add optional app-specific aliases (DisplayName variants, exe aliases).
- Use multiple sources so non-winget installs can still pass.

### D) Result model
Each app detection returns:
- `status`: `PASS | FAIL | PENDING`
- `confidence`: `high | medium | low`
- `evidence`: machine-readable list (source + matched value)
- `detail`: human-readable reason shown in UI/report

PASS criteria (recommended):
- High confidence evidence from one strong source (registry exact/winget exact), OR
- Combined medium evidence from at least two independent sources.

---

## Priority-Ranked Implementation Sequence

## Priority 0 — Acceptance gates (must define first)
1. Define measurable quality targets:
   - False positive rate target (e.g. 0 known FPs in curated test matrix).
   - False negative rate target (e.g. <= 1 known FN in curated matrix).
   - Inspect software stage runtime target.
2. Build a baseline matrix of apps × install styles:
   - winget, MSI, EXE, portable, per-user, custom path, not-installed control.

**Deliverable**: `detection_test_matrix.json` + expected outcomes.

## Priority 1 — Stop false positives first
1. Replace OR-based broad matching in registry detection with strict name-first logic.
2. Disallow publisher-only PASS decisions.
3. Harden winget parsing (JSON authoritative; strict fallback parser).
4. Improve details to include exact matched field and source.

**Why first**: false positives damage trust more than false negatives.

## Priority 2 — Stop false negatives (multi-source detection)
1. Add HKCU registry coverage consistently for all app probes.
2. Add optional app metadata fields:
   - `detect_executables`
   - `detect_shortcuts`
   - `detect_path_tokens`
   - `detect_install_paths`
3. Implement PATH + Start Menu probes as supplemental evidence.
4. Add app-specific aliases for known DisplayName variants.

**Why second**: expands coverage for non-winget/non-standard installs.

## Priority 3 — Performance refactor (bulk snapshot)
1. One-time snapshot at inspect start:
   - winget inventory (single query)
   - uninstall registry rows (single query)
   - PATH executable map (single query)
   - Start Menu shortcut inventory (single query)
2. Evaluate all apps against in-memory snapshot.
3. Keep cancellable behavior and concise logging.

**Expected impact**: major runtime reduction by eliminating repeated subprocess calls.

## Priority 4 — Confidence scoring + explainability
1. Introduce weighted evidence scoring per source.
2. Emit per-app decision trace in debug log/report.
3. Mark low-confidence cases as `PENDING` instead of forced FAIL/PASS.

## Priority 5 — Regression safety
1. Add unit tests for matchers/parsers.
2. Add fixtures for winget JSON/text and registry samples.
3. Add integration-style tests for decision engine over canned snapshots.

---

## Proposed App Metadata Extensions
Extend install app catalog metadata with optional detection hints:

- `detect_display_names: tuple[str, ...]`
- `detect_publishers: tuple[str, ...]` (supporting evidence only)
- `detect_executables: tuple[str, ...]`
- `detect_shortcuts: tuple[str, ...]`
- `detect_install_paths: tuple[str, ...]`
- `allow_weak_evidence_only: bool` (default `False`)

This supports apps that:
- are not in winget,
- install only shortcuts,
- are only discoverable via executable presence.

---

## Task Breakdown (Ready to implement)
1. **Design**: define evidence schema + confidence rules.
2. **Core**: implement snapshot collector and decision engine.
3. **Migration**: move current per-app detection to snapshot-driven evaluation.
4. **Catalog**: enrich top-priority apps with executable/shortcut aliases.
5. **UI/Report**: show evidence source + confidence for each software item.
6. **Validation**: run matrix and tune thresholds until FP/FN targets are met.

---

## Definition of Done
- No known false positives in baseline matrix.
- False negatives reduced to agreed target threshold.
- Inspect software stage runtime meets target after snapshot refactor.
- Every PASS/FAIL decision includes explainable evidence in report/log.
- Existing checklist sync behavior remains correct.
