# Verification email delivery

Deploy accounts/0010_verificationemaildelivery through the normal migration
process before serving this code. This implementation does not migrate the
existing development database. No existing verification messages are backfilled.

Only InvitationAccountAdapter.send_confirmation_mail is intercepted. Allauth
65.20.0 still authorizes signup/add-address/resend and applies its cooldowns.
Its email_confirmation_sent signal means accepted for queuing, not SMTP delivery.
Other Allauth email types and the independent invitation outbox remain unchanged.

Enqueue locks User then EmailAddress and inserts in the caller's SQL transaction.
A partial unique constraint permits one pending/processing generation per original
address. Repeated approved requests coalesce; terminal histories remain and a new
approved request creates another generation. Rollback removes the queued row.
No on_commit-only persistence or background submission from requests is used.

Rows bind original account/address identifiers, recipient, session version and
signup context. They contain no confirmation key, URL or rendered message.
Access to recipient/history data must remain restricted. Address verification,
supported changes/deletion and account deletion cancel unsent work via signals.
Account deactivation cancels within the existing status transaction (queryset
updates do not emit save signals). Reactivation cannot revive cancelled rows.
The worker independently rechecks identity, account activity/version, verification
and expiration immediately before submission, including raw-queryset changes.

Run a finite processor regularly:

    python manage.py process_verification_deliveries --base-url https://trusted.example --limit 100

Limit is 1..1000. An explicit trusted HTTP(S) origin is required, with no credentials,
path, query or fragment. Keep the configured Django Site consistent with that
origin for existing Allauth message context. HMAC link mode is required; switching
to verification codes or database-backed confirmation keys requires a separately
reviewed integration. No settings are changed automatically.

Claims use UUID ownership and 120-second leases. Expired claims are reclaimable;
stale or cancelled owners cannot complete another worker's result. Each generation
has a three-day lifetime and at most five claimed attempts. Failed/zero submissions
retry with 60-second exponential backoff capped at one hour; exhaustion is failed.
Crashes consume a claim attempt. Expired requests become expired; invalid identities
become cancelled. Terminal rows are not automatically reprocessed.
The atomic claim update requires attempts < 5 and an unexpired request. Due pending
or lease-expired processing rows that exhaust their budget are retired to failed
without incrementing attempts or submitting again. An unexpired fifth lease remains
owned until completion or lease expiry; retirement never steals that live claim.
Expired pending requests are processed even if their retry schedule lies later.

Every attempt creates a fresh standard Allauth EmailConfirmationHMAC link in memory
and renders existing signup/non-signup templates. It never calls the enqueue/send-
confirmation API recursively. Link validation and confirmation POST remain Allauth's
unchanged behavior; old issued links are not invalidated by issuing a newer link.
The processor requires autocommit and holds no transaction across SMTP submission.

submitted means the configured backend reported one submission, not inbox delivery.
SMTP exceptions may follow actual acceptance: retry/crash/lease recovery can submit
duplicates. This is at-least-once submission, never exactly-once delivery. Cancellation
cannot recall SMTP already in flight; pre-send checks minimize that unavoidable race.
Ownership, lease and request expiration are checked again after lifecycle validation,
immediately before submission. Expiry before that final check prevents SMTP. Expiry
after the check or during SMTP can allow another worker to reclaim within the budget;
the stale worker cannot record completion. A final lost fifth lease is retired without
a sixth claim, even if its SMTP result is uncertain. The existing configured SMTP
timeout is 20 seconds, below the 120-second lease, but a backend timeout is not a
guaranteed end-to-end wall-clock bound. Custom or misconfigured longer timeouts can
increase overlapping submissions. This does not provide exactly-once delivery or a
distributed transaction; do not hold database locks across SMTP to hide that race.
Cancellation also does not retroactively alter Allauth's validation of issued links.

Monitor aggregate command counts, nonzero operational exits, due/lease ages and
failed rows. Errors are fixed sanitized descriptions; never log keys, URLs, message
bodies or sensitive backend responses. Lease duration must exceed the backend's
maximum submission timeout. Raw SQL/private ORM bypasses remain trusted boundaries.
Test real locking/contention on the deployment database; SQLite can reject a
contending request, which must retry rather than assume enqueue succeeded.

Workstream 10 must establish the production origin/Site, mail provider credentials,
timeouts, sender configuration and delivery monitoring. Scheduling this finite
command is an operational prerequisite, not implemented here. Console and in-memory
backends do not deliver inbox mail. No public status or retry endpoint is introduced.
