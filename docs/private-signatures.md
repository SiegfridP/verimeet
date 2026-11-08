# Private signature deployment

## Owner replacement and retention

Completed non-admin accounts replace PNGs through Settings with explicit confirmation
and a signed, owner-bound current-version token. Global Admins receive no PNG
management interface; Admin signatures are status-only. Supported User.save,
FieldFile and QuerySet/bulk replacement paths reject untracked changes. The
replacement service uses a private raw QuerySet update after its transaction guard,
retention insert and stale-version checks. Raw SQL, private ORM internals and direct
filesystem access remain trusted-code boundaries, not security sandboxes.
QuerySet filename assignment is not an initial-upload API: only conditional no-op
signature reference updates are allowed. Initial uploads use FieldFile/model file
assignment and storage validation. Private/base managers, raw SQL and explicit
base QuerySet method calls can bypass application guards and must not be exposed
to untrusted input. Recovery independently locks/reloads the account, compares
the caller's version, and validates the new stored bytes before committing its
ledger, active reference and audit event. When invoked by onboarding, all of this
also rolls back if subsequent onboarding persistence fails. Neither rollback
path physically removes files.

Superseded files remain untouched. Retention starts at supersession, defaults to
90 days and SIGNATURE_RETENTION_DAYS must never be less than 90. Ledger owners
use SET_NULL plus a stable numeric identifier. Historical associations remain
unknown and preservation holds remain enabled. No physical deletion is available,
including via SignatureStorage.delete. Database rollback cannot roll back a new
filesystem write: failed new files remain private orphans. Reconciliation must
compare ledger and active references without deleting files. Legacy identifiers
retain their original namespace; missing/corrupt onboarding assets are recorded
as unresolved when recovered.

Run `python manage.py inspect_signature_retention --limit 100` for bounded,
metadata-only inspection. Continue with `--after RECORD_UUID`. Output includes
safe ledger IDs, holds and age eligibility, never private paths. It does not
inspect file existence and age eligibility does not authorize deletion.

PNG replacement does not modify ECDSA payloads, attendance, annotations or PDFs.
Workstream 4 may reference stable retained asset IDs from signing-time snapshots;
it must not infer historical image associations from current profile PNGs. Future
cleanup must check active references, protected snapshot references and holds.

New signature files live in `PRIVATE_SIGNATURE_ROOT`, outside `MEDIA_ROOT` by
default. Keep that directory outside every web server alias, static root, public
bucket, and CDN origin. Grant filesystem access only to the application identity.
Do not publish generic storage URLs. The authenticated signature preview endpoint
returns only the current account's validated image with `private, no-store`.

All new signature uploads through `SignatureStorage.save()` are validated and
normalized to 600 x 200 PNGs with generated filenames. This includes onboarding,
Django Admin, model file assignment followed by save, and `FieldFile.save()`.
Forms also validate inputs to show field-level errors, but formatting occurs at
the storage boundary. Ordinary saves of committed file references do not rewrite
existing assets. Raw filesystem writes and database filename assignment are not
upload APIs; persisted-reference/content validation still applies on access.

Legacy `signatures/` names remain readable through the application storage adapter
under `MEDIA_ROOT`; onboarding does not move, rewrite, or delete those files.
Django denies requests to `/media/signatures/`, including when DEBUG static serving
is enabled and when no matching URL exists. This cannot protect files served
directly by a reverse proxy, object store, CDN, or another application.

Before deployment, independently deny the entire legacy signature directory in
the production media server, including directory indexes, alternate aliases, and
case variants on case-insensitive filesystems. Remove any existing public CDN
copies. Do not expose `PRIVATE_SIGNATURE_ROOT` through an alternate URL. Check
anonymous and authenticated requests at the public origin, not just Django.

Validation hashes bounded file contents on each check to detect external edits;
unchanged data is not decoded again or written to the database. Changed validation
results use compare-and-swap updates; a losing validator fails closed for that
request. Do not replace this with mtime-only or filename-only trust. Preview serves
the validated byte snapshot, avoiding a second open and a file-change race.

Apply migration `0007_secure_onboarding` as an explicit deployment step. It has not
been applied to the development database by this workstream.
