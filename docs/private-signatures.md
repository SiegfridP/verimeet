# Private signature deployment

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
