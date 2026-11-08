# PDF export deployment

## Workstream 4 signing evidence

Apply `meetings.0008_signingvisualsnapshot` through the deployment migration
process before enabling this code. This workstream does not migrate the existing
development database. Legacy signed rows have no inferred snapshot or historical
name: exports show `Name unavailable` and `Visual signature unavailable`.

SigningVisualSnapshot has a one-to-one protected Attendance association, immutable
historical display name, opaque file identifier, SHA-256, byte length, dimensions,
capture time and provenance. Snapshot files default to the `signing-evidence`
subdirectory of PRIVATE_SIGNATURE_ROOT. Deployments may configure
PRIVATE_SNAPSHOT_ROOT separately. Keep both roots outside every public media,
static, proxy, bucket and CDN alias. No public storage URL is provided.

Signing serializes Meeting, User, optional QRSession, then Attendance. It reloads
account authority and lifecycle and conditionally persists ECDSA state, captures
the locked user's validated PNG bytes without normalization, verifies readback,
and commits the snapshot, QR usage and audit in the same transaction. Failure
rolls back database evidence. Filesystem writes cannot roll back: private orphan
objects may remain after failures. Do not automatically remove them. Reconcile
against committed snapshot references and preservation holds using a separately
reviewed operational procedure. Retry SQLite contention; validate concurrency on
the production database before deployment.

Snapshots are retained for the lifetime of evidence, with no expiry or 90-day
cleanup rule. Profile replacement and account status changes do not change them.
ORM update/bulk update, ordinary model saves and snapshot deletion are blocked;
Attendance parent deletion is protected. Raw SQL, explicit base QuerySet calls,
and direct filesystem writes remain trusted administrative boundaries.

Exports validate bounded snapshot bytes, hash, length, PNG format and dimensions.
Missing or damaged images display `Visual signature unavailable`, independently
of cryptographic status. Intact PNGs remain visible alongside prominent invalid
ECDSA warnings. ECDSA payloads and legacy verification are unchanged; neither
images nor names are added to the signed payload. PDFs are not signed artifacts.

At most 100 attendance-position images and 16 MiB of image bytes are included per
export, with an aggregate 12-million-pixel budget to bound decoded image memory;
additional images receive the unavailable notice. Each image is bounded
by the existing 2 MiB/4096-pixel validation limits and fixed CSS dimensions.
An export-local opaque resource map serves only validated bytes through WeasyPrint
70's URLFetcherResponse API. Network, file, unknown and data URLs fail closed.
No public verification bearer QR is embedded. Title metadata is bounded and
control-stripped; generator, description and export creation time use HTML metadata.

Back up database evidence and private snapshot objects together. Restore both,
verify hashes and references, and investigate missing objects without substituting
current profile images. Protect filesystem credentials and backup access. Bound
synchronous rendering memory/time and smoke-test native libraries and fonts.

The application declares WeasyPrint 70.0 (Python >= 3.10, Pango >= 1.44).
The inspected development environment uses Python 3.15, WeasyPrint 70.0 and
pydyf 0.13.0. No packages were installed for this batch.

Deploy Pango, HarfBuzz/fontconfig and their platform dependencies, plus fonts
covering the languages used in minutes. On Windows the upstream instructions
use MSYS2 UCRT64 Pango; configure WEASYPRINT_DLL_DIRECTORIES for its DLL folder
if it cannot be discovered. On Linux use the distribution's native packages.
See https://doc.courtbouillon.org/weasyprint/stable/first_steps.html.

Smoke-test real rendering on the deployment OS. Missing fonts can produce
missing glyphs even when PDF generation succeeds. Renderer import/native-library
failures return an unavailable response without a successful export event.

Exports use one joined database query to capture current finalized records.
They do not persist artifacts, archive meetings or change signatures. They are
not byte-identical historical snapshots or cryptographically signed PDFs.
No current profile images or external assets are used; only captured private
signing images in the export-local map are permitted. Audit records indicate generation/offering, not confirmed delivery.
Large documents consume synchronous rendering resources; configure request
timeouts and deployment resource limits for expected document sizes.
