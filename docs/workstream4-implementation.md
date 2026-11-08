# Workstream 4 implementation and verification

## Baseline

Started on main at a1d9368, clean; git diff --check passed. No development
migrations, application-data edits, dependency installation, staging, commits,
pushes or credential changes were performed.

## 4A: immutable evidence

SigningVisualSnapshot is one-to-one with Attendance (PROTECT), with unique opaque
storage identifier, SHA-256, byte length, dimensions, capture timestamp, historical
display name and provenance. Migration: meetings/0008_signingvisualsnapshot.py.
There is no historical backfill. Ordinary save/update/bulk-update/conflict-create
paths cannot overwrite existing snapshots; pre_delete rejects snapshot deletion.
Parent Attendance deletion is protected even with inconsistent signed flags.
Admin also treats a snapshot as protected evidence. These are application guards,
not protection against privileged raw SQL or direct filesystem administration.

## 4B: transactional signing

The existing sign_meeting path now locks Meeting, User, optional QRSession, then
Attendance. It reloads account activity/authority and meeting lifecycle, rechecks
token state and the exact assignment, and uses the existing conditional update.
ECDSA generation now occurs with the fresh locked User and Meeting. The winning
conditional update precedes snapshot creation within the same uncommitted atomic
block; this avoids creating evidence for the losing conditional request. A failed
copy/readback/insert marks the transaction for rollback. QR usage and required
signature.created audit follow successful capture. Existing audit exceptions
continue to abort the transaction and propagate through Django error handling.

The capture service validates current bounded PNG bytes under the User lock,
copies without normalization, reads back and compares exact bytes/hash/length/
dimensions, and records the frozen display name or Name unavailable.
Database rollback cannot undo a file write: failed private objects remain held
for reconciliation, with no automatic deletion. The canonical/legacy payloads
and ECDSA algorithms were not changed; the PNG digest is not added to a payload.

## 4C and 4D: PDF evidence and attribution

capture_document joins the snapshot data in the existing joined SELECT and never
uses a current profile image for historical rendering. Legacy signing records
have Name unavailable, not an invented current historical name. Missing, damaged,
oversized or hash-mismatched images show Visual signature unavailable while
retaining independent ECDSA verification labels. Intact images remain visible
with prominently styled invalid-signature warnings when ECDSA is invalid.

An opaque export-local resource map allows only validated bytes, through the
installed WeasyPrint 70 URLFetcher/URLFetcherResponse API. Explicit fatal denial
replaces the prior incidental attribute-error denial. Network, filesystem, data,
and unknown URLs remain denied. Images have fixed CSS dimensions and bounded
reads; exports include at most 100 attendance-position images, 16 MiB image
bytes and 12 million decoded pixels. HTML metadata supplies a bounded control-stripped title, safe description,
VeriMeet generator and export creation timestamp. No bearer QR is added. No
meeting-date field is introduced. Record timestamps retain their factual labels.
Required export auditing still happens only after successful rendering and before
returning PDF bytes. Dynamic PDFs are not cryptographically signed artifacts.

## 4E: historical compatibility

Tests demonstrate A on Meeting 1, replacement with B, then B on Meeting 2, while
Meeting 1 keeps A and the original name after renaming and archival. Multiple
Officers receive separate snapshot associations. Account activity cycles do not
change snapshots. Snapshot storage is independent of the superseded-profile
retention ledger and has no expiry. Missing legacy evidence is never guessed.

## 4F: checkpoints

- First 19-test image/PDF checkpoint exposed an installed-renderer response-type
  mismatch; corrected rerun: 19 passed in 5.285s.
- Expanded signing/deletion checkpoint exposed rollback-response handling and a
  test-thread SQLite read-contention issue. Both were corrected; 45 passed in
  30.656s, including the original conditional-update winner assertions.
- Latest evidence/PDF checkpoint: 28 passed in 5.966s, no failures/errors/skips.
- Insert-only primary-key race regression: 18 evidence tests passed in 3.322s.
- Final image-budget/resource checkpoint: 28 passed in 7.781s, no failures/errors/skips.
- manage.py check: no issues; makemigrations --check --dry-run: no changes.
- Final full regression against all safeguards: **588 discovered, 588 passed,
  0 failures, 0 errors, 0 skipped, 826.975 seconds, process exit code 0**.
  The isolated test database was destroyed. Baseline 570 tests plus 18 new tests.
- First complete regression before the final two safeguards: 588 discovered,
  588 passed, zero failures/errors/skips, 854.258 seconds.
- Second complete regression with insert-only guard: 588 passed, zero failures/
  errors/skips, 856.167 seconds.

Coverage includes exact bytes/hash/length/dimensions, readback/storage/insert/audit
failures, legacy placeholders, independent invalid ECDSA, neutral/frozen names,
parent and direct deletion, bulk mutation denial, actual renderer map fetching,
metadata, multiple Officers, archival, account state cycles, post-lock deactivation
and QR revocation, duplicate signing, and threaded replacement during signing.
Existing authorization, CSRF, lifecycle, QR, canonical/legacy crypto and retention
tests remain part of the full regression.

## Files and migration

Modified: accounts/test_fixtures.py (explicit temporary snapshot storage isolation);
core/settings.py; docs/private-signatures.md; meetings/PDF_DEPLOYMENT.md;
meetings/admin.py; meetings/deletion_guards.py; meetings/models.py; meetings/pdf.py;
meetings/templates/pdf/final_minutes.html; meetings/tests.py; meetings/views.py.
New: meetings/visual_evidence.py; meetings/test_visual_evidence.py;
meetings/migrations/0008_signingvisualsnapshot.py; this report.

## Deployment and limitations

PRIVATE_SNAPSHOT_ROOT optionally overrides the default dynamic
PRIVATE_SIGNATURE_ROOT/signing-evidence location. Keep private roots outside all
public aliases; use restrictive permissions. Back up and recover database rows
and private objects together; validate hashes after restore. Apply migration via
the normal deployment process before enabling the new code. It has only been
executed in isolated test databases during this workstream.

The threaded test accepts SQLite's explicit contention failure for the competing
replacement and proves captured bytes remain unchanged. Production-database
lock/deadlock behavior still requires deployment-platform testing. File storage
and SQL are not a distributed transaction. Raw database/filesystem operations are
trusted boundaries. PDF byte identity across exports is not guaranteed. Validate
fonts/native libraries, memory/time limits and private-origin denial before release.
Existing profile-retention cleanup must never delete snapshot objects.
Verification continues to use the User's existing public key. This workstream
does not add key-version history, legal identity proof, trusted timestamps or
cryptographic binding of visual bytes; those are separate architectural concerns.

No tests were skipped or removed. Two existing PDF expectations were updated for
approved policies: legacy signing names become neutral, and forbidden resources
raise an intentional fatal renderer error while retaining opener-denial checks.

## Final Git state

Final inspection: main / a1d9368. Eleven tracked files modified (190 insertions,
35 deletions), four untracked new files: this report, the migration, snapshot
service, and evidence tests. Ordinary git diff --stat excludes untracked files.
git diff --check passed. Staged diff is empty. Nothing was staged, committed,
or pushed. All Workstream 4 phases are complete for independent review.

Raw execution evidence is retained outside the working tree at
C:/Users/seah/AppData/Local/Temp/verimeet-workstream4-a1d9368-20261108/.
