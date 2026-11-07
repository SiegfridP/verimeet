# Invitation delivery operations

Apply migration accounts/0006 during the normal approved deployment process.
It creates delivery storage only: it does not resend or invalidate existing invitations.
Existing valid invitations can be explicitly queued from their department's invitation page.

Schedule the following finite command regularly (for example, once per minute), using the
project environment and a trusted deployment origin:

    python manage.py process_invitation_deliveries --base-url https://your-site.example --limit 100

The default backend remains the configured Django MAILERS backend. Console submission is
not SMTP delivery. Configure SMTP only through the existing deployment configuration.
No tokens or URLs are printed by the command. Monitor nonzero exits and failed records.

Optional Django settings: INVITATION_DELIVERY_MAX_ATTEMPTS (default 5),
INVITATION_DELIVERY_LEASE_SECONDS (default 120). Keep both positive; keep the lease longer
than the maximum backend submission timeout. Retries back off from 60 seconds to at most
3600 seconds. Manual retry of a terminal failed delivery resets its attempt budget,
without changing the invitation token, recipient, department, or expiry.

The processor requires autocommit and performs no SMTP work inside a database transaction.
Claims are conditional updates, not skip_locked locks. Lease-expired owners cannot update
results. Recovery after a crash or ambiguous SMTP response can submit duplicate messages;
this is at-least-once submission, never exactly-once or guaranteed inbox delivery.
An in-flight message cannot be recalled during replacement/deletion or expiry. Pre-send
validation minimizes this race; revoked/expired links remain unusable. A lease expiring
while a worker is still in SMTP may permit overlapping submissions, but cannot let that
worker overwrite a newer result. Test real contention on the deployment database.

Pending/processing deliveries are cancelled before ORM invitation deletion, including
replacement and parent cascades. SET_NULL retains their history. Failed, expired and
submitted history is retained unchanged. Old tokens are never copied into delivery rows.
Acceptance, authentication and verified-email checks remain independent of delivery state.
