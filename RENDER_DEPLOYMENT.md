# VeriMeet Render deployment

## Fast full-feature Render + Neon setup (database evidence)

Use `EVIDENCE_BACKEND=database` to store private profile PNGs and immutable signing
snapshots in the same PostgreSQL database as attendance. No R2/B2 account or
credentials are required in this mode. The existing R2 mode remains available by
selecting `EVIDENCE_BACKEND=r2`; the R2 instructions below apply only to that mode.
Do not switch backends on a populated deployment without a separately verified
byte-preserving import: changing modes does not copy existing evidence.

1. Use a fresh Neon database. Set `DATABASE_URL` to its supplied PostgreSQL URL,
   retaining `sslmode=require` and any other supplied TLS parameters. Do not copy
   development records. Select the Neon region nearest the Render service.
2. Render: Docker runtime, repository root `.`, Dockerfile `./Dockerfile`, Free
   instance, health path `/healthz/`, no build/start override. The Docker command
   applies migrations including `meetings.0010_privateevidenceobject` before serving;
   failure prevents startup. Never run concurrent migration starts.
3. Set `DJANGO_ENV=production`, `DJANGO_DEBUG=False`,
   `DJANGO_ALLOWED_HOSTS=<service>.onrender.com`,
   `APPLICATION_ORIGIN=https://<service>.onrender.com`, `EVIDENCE_BACKEND=database`.
   Set a securely generated `DJANGO_SECRET_KEY` (50+ characters, 5+ distinct), and
   a stable Fernet `SIGNING_KEY_ENCRYPTION_KEY`. Back up both outside Render.
4. Configure real `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and register
   `https://<service>.onrender.com/accounts/auth/google/login/callback/` with Google.
5. Set `EMAIL_BACKEND=core.resend_backend.EmailBackend`, `RESEND_API_KEY`,
   `DEFAULT_FROM_EMAIL` to a verified sender, `EMAIL_FROM_NAME=VeriMeet`,
   `EMAIL_TIMEOUT=20`. No authentication or email validation is bypassed.
6. Configure the external runner described below with the same code, database
   backend selection and secrets. It must execute both finite outbox commands;
   deploying Gunicorn alone does not deliver queued messages.
7. Before real use, verify password/Google login, invitation and verification mail,
   meeting lifecycle, attendance/QR signing, individual verification, PDF exports,
   audit history and evidence persistence across restart using synthetic records.

Database evidence uses INSERT with a primary-key constraint, never UPSERT or
HEAD-then-PUT. Duplicate keys fail atomically. Snapshot bytes, signing state and
audit records share the default database transaction and roll back together.
Private previews, namespace checks, PNG bounds, snapshot hashes and retention
guards remain in force. There is no public object URL or local fallback. Ordinary
model/queryset updates and deletion are blocked. Raw SQL, schema changes and
database administrators remain trusted boundaries, as with existing audit models.
Use restricted database credentials and independently protected backups.

Each object is at most 2 MiB; historical snapshots are retained indefinitely, so
monitor total database size and upgrade before the Neon quota is exhausted.
PNG bytes may be stored twice (profile and historical snapshot), plus database
overhead. Back up the database including binary evidence and test restores with
the preserved encryption keys. Neon replaces Render Postgres in this setup;
Render's free Postgres expiration does not apply to Neon. Neon has its own quota,
compute, restore-window and availability limits; verify them in your account.
No production migrations or external resources were created by this implementation.

This foundation preserves the application workflows. External services are not
provisioned and scheduling is not operational until configured. Review changes
and complete the validation below before deploying real evidence.

## Runtime and commands

Docker uses Python 3.14 on Debian Bookworm, WeasyPrint 70, Pango, HarfBuzz and
DejaVu/Noto fonts. Gunicorn runs one synchronous worker to limit memory.
Build: `docker build -t verimeet .`
Static collection runs during image build using non-production configuration and
a disposable build-only secret. No production credentials are required in layers.
Start command (already in Dockerfile):

```sh
python manage.py migrate --noinput && exec gunicorn core.wsgi:application --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 1 --timeout 120 --access-logfile -
```

Migrations run before Gunicorn; failure prevents startup. Never run two deployment
starts simultaneously. The additive evidence-table migration is required for the
database backend; existing migrations are unchanged. Local development defaults to
SQLite; do not upload or migrate the local database. Production requires a
PostgreSQL URL. Existing transaction/locking code and outbox claims are unchanged.

## Alternative R2 + Render PostgreSQL setup

1. Create a free Render PostgreSQL database in the same region as the web service.
   Use a fresh database, with no development records. Copy its internal URL into
   the web service secret `DATABASE_URL` (`postgresql://user:password@host/db`).
   The Blueprint deliberately does not provision a database.
2. Create a private Cloudflare R2 bucket. Disable r2.dev and public/custom domain
   access. Do not set lifecycle expiration rules. Configure a bucket retention
   lock appropriate to evidence retention. Separate backup credentials from app
   credentials. R2 credentials are a trusted administrative boundary: the app
   refuses deletion, but credential holders may otherwise delete objects.
3. Set `EVIDENCE_ENDPOINT=https://<32-character-account-id>.r2.cloudflarestorage.com`,
   `EVIDENCE_BUCKET`, `EVIDENCE_ACCESS_KEY_ID`, `EVIDENCE_SECRET_ACCESS_KEY`.
   Reads and conditional PUTs are signed server-side. No public/presigned URLs
   are exposed. Profiles use `profiles/normalized/<uuid>.png`; snapshots use
   `snapshots/<uuid>.png`. Legacy names read `profiles/signatures/<filename>.png`.
   A separately reviewed historical import must preserve exact names and bytes;
   this implementation performs no automatic import or cleanup.
4. Create a Resend account, verify your sender domain and its DNS records, and set
   `RESEND_API_KEY`, `DEFAULT_FROM_EMAIL`, `EMAIL_FROM_NAME=VeriMeet`,
   `EMAIL_BACKEND=core.resend_backend.EmailBackend`, `EMAIL_TIMEOUT=20`.
   Testing-tier recipient/domain limits must be checked in the provider account.
   This uses HTTPS, avoiding Render's blocked SMTP ports. Local console/SMTP
   behavior remains available. Acceptance requires an HTTP success and message ID;
   acceptance is not inbox delivery. Existing leases and retries are unchanged;
   uncertain acceptance can still cause duplicate submission. No provider
   idempotency key is invented from changing verification-message contents.
5. Create the Docker web service from `render.yaml`, or manually choose Docker,
   Free instance, root directory `.`, Dockerfile `./Dockerfile`, health path
   `/healthz/`, and no command override. No persistent disk is required.
6. Set `DJANGO_ENV=production`, `DJANGO_DEBUG=False`,
   `DJANGO_ALLOWED_HOSTS=<service>.onrender.com` (comma-separated explicit hosts),
   `APPLICATION_ORIGIN=https://<service>.onrender.com` (no path).
   Set independent strong `DJANGO_SECRET_KEY` and a generated Fernet
   `SIGNING_KEY_ENCRYPTION_KEY`. Preserve and back up both securely. Loss of the
   Fernet key prevents decryption of private signing keys and QR tokens. Never
   regenerate keys on restart. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and
   register `https://<service>.onrender.com/accounts/auth/google/login/callback/`.
7. Configure an external trusted scheduled runner every minute, with this same
   image, canonical origin and secrets. Give it the database's external TLS URL
   and allowlist its egress address in Render. Execute these finite commands:

```sh
python manage.py process_invitation_deliveries --base-url "$APPLICATION_ORIGIN" --limit 10
python manage.py process_verification_deliveries --base-url "$APPLICATION_ORIGIN" --limit 10
```

   Use scheduler concurrency 1, a runtime limit, encrypted secrets and redacted
   logs. Never run the image's default CMD in the scheduled runner: override it
   with the commands above. It must not run migrations. Smaller batches and
   provider rate limits may require cadence adjustments. Existing conditional
   claims and expiring leases allow interrupted runs to recover; monitor pending
   age and submitted/retried/failed counts, not only exit status. No HTTP job
   endpoint or Gunicorn background loop is introduced. Scheduler authentication
   is provided by the external runner's secret/account controls.

## Validation and operations

Before deployment, run `python manage.py check`, focused deployment/authentication,
outbox, signature and visual evidence tests, and
`python manage.py makemigrations --check --dry-run` in an isolated environment.
Build the Docker image; verify `collectstatic`, native PDF rendering and required
language glyphs. Validate PostgreSQL concurrency separately. Mock all external
provider calls during automated tests.

After approved deployment, verify health, password/Google login, roles, invitations,
verification, meeting lifecycle, QR attendance/signing, private previews, historical
snapshot hashes, verification QR, PDF export and audit logs using synthetic data.
Restart the service and confirm evidence survives. Confirm anonymous object access
is denied and both processors actually drain their queues.

Render Free sleeps after 15 idle minutes and cold starts delay requests. Its
filesystem is ephemeral, so only collected static assets belong in the image.
Free PostgreSQL expires after 30 days; plan export or upgrade before expiration.
External runner and storage/email providers have independent quotas/costs. Large
PDFs can exceed free memory or request timeouts. Health checks show process health,
not database, storage, scheduler or mail availability.

Back up database and evidence objects together, retain immutable snapshot objects
for the evidence lifetime, and back up encryption secrets separately. Restore and
verify object hashes/references before resuming signing. Do not delete orphan
objects automatically. Application deletion guards are not a substitute for
provider retention controls and independently protected backups.

References: [Render Free](https://render.com/docs/free),
[R2 atomic conditional writes](https://developers.cloudflare.com/r2/api/s3/api/),
[Resend API](https://resend.com/docs/api-reference/emails/send-email).
