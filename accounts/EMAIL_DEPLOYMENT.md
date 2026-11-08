# Email operations

Production is explicitly selected by `DJANGO_ENV=production`; do not deploy with
this variable omitted or set to development. Keep `DJANGO_DEBUG=False` and configure
allowed hosts and HTTPS/proxy handling for the actual deployment separately.

## Required production environment

- `EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend`
- `EMAIL_HOST`, `EMAIL_PORT` (1..65535), `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`
- `EMAIL_USE_TLS=true`, `EMAIL_USE_SSL=false` for STARTTLS, or false/true for
  implicit TLS. Select the mode and port required by your provider.
- `DEFAULT_FROM_EMAIL`: authorized sender address (legacy display-name syntax is
  accepted); `EMAIL_FROM_NAME=VeriMeet` controls the display name.
- `EMAIL_TIMEOUT=20`: positive finite seconds below the 120-second worker lease.
  Socket timeouts are not guaranteed total wall-clock deadlines.
- `APPLICATION_ORIGIN=https://your-domain.example`: canonical origin, no credentials,
  path, query or fragment. HTTPS is mandatory in production.

Startup rejects missing/placeholder production mail settings with sanitized errors.
The defaults are development console output only. Console output contains sensitive
links: do not retain it in shared logs. Never print environment values or backend
exceptions containing credentials, recipient addresses, tokens, or message bodies.

Choose a provider independently. Verify the sender/domain with that provider;
configure its required SPF, DKIM and DMARC records and test alignment. Provision
credentials through restricted deployment secrets, never Git. No provider, domain,
hosting platform or scheduler is provisioned by this implementation.

## Database and processors

Apply the normal project migrations before serving this code, including accounts
0006 (invitation outbox) and 0010 (verification outbox). The development 0010 migration
is already applied; do not reapply it manually. Back up the database and protect
recipient/history data. Validate contention on the actual production database.

Run both independent finite commands in the same deployment environment:

    python manage.py process_invitation_deliveries --base-url https://your-domain.example --limit 100
    python manage.py process_verification_deliveries --base-url https://your-domain.example --limit 100

The origin must match APPLICATION_ORIGIN (an optional trailing slash is accepted).
With no canonical origin, development retains explicit worker origins. Request-driven
Allauth email links use the canonical origin when configured, preserving link paths
and tokens. Django Sites is not enabled.

Schedule each command every minute as an initial recommendation; choose platform
scheduling separately. Default batch size is 100; supported range is 1..1000. Adjust
cadence/batches based on backlog, provider limits and measured runtime. Finite commands
must be scheduled repeatedly; running the web server does not drain either outbox.

Overlapping runs use conditional claims and 120-second ownership leases. Expired
leases are reclaimable; stale workers cannot overwrite newer results. Keep backend
submission time below the lease. No locks span SMTP. Crashes and uncertain SMTP
acceptance can cause duplicates: this is at-least-once submission, not exactly-once
or guaranteed inbox delivery. Do not change retry or lease behavior to hide that race.

## Monitoring and recovery

Monitor aggregate submitted/retried/failed/cancelled/expired counts, nonzero command
exits, pending due ages, oldest processing leases, and failed records. Individual mail
failures are counted and may still yield exit code zero; exit monitoring alone is
insufficient. Use restricted ORM/admin diagnostics; avoid exporting recipient histories
or links. No dedicated health endpoint or alert transport is installed.

Both processors retry transient/uncertain submission with exponential backoff from
60 seconds, capped at one hour. Verify scheduler activity, SMTP settings and provider
status before recovery. Abandoned leases recover on subsequent scheduled runs.
Invitation failures can be retried through the existing authorized invitation UI,
resetting the budget without changing token or expiry. Verification generations have
five attempts and a three-day unsent lifetime; terminal rows are not manually reset.
A newly authorized Allauth resend creates a new generation subject to its normal
limits. Do not revive cancelled/expired requests or edit tokens in the database.

See INVITATION_DELIVERY.md and VERIFICATION_DELIVERY.md for lifecycle and race details.
Establish an operational owner, alert thresholds/destinations, and controlled real
inbox smoke tests as external deployment tasks. No real mail is sent by local tests.
