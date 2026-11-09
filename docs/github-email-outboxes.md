# Gmail outbox processing with GitHub Actions

The `Process email outboxes` workflow runs every five minutes and supports **Run
workflow** on the repository's default branch. It uses Python 3.14 and the complete
pinned requirements, matching the Docker runtime. It calls the two existing
management commands with five rows per outbox per run, without migrations,
collectstatic, Gunicorn or any changes to business logic.

## Setup

In repository **Settings → Secrets and variables → Actions → Repository secrets**,
add exactly these secrets (never paste values into a workflow, issue or log):

| Secret | Value |
| --- | --- |
| `GMAIL_ADDRESS` | Dedicated VeriMeet Gmail address; used as login and From address |
| `GMAIL_APP_PASSWORD` | Google App Password, not the account password; paste without display grouping spaces |
| `DATABASE_URL` | Same Neon database as Render, with the supplied TLS parameters retained |
| `DJANGO_SECRET_KEY` | Exact stable production key from Render; confirmation links depend on it |
| `SIGNING_KEY_ENCRYPTION_KEY` | Exact stable production Fernet key, required by existing startup validation |
| `GOOGLE_CLIENT_ID` | Same production Google client ID; required by existing startup validation |
| `GOOGLE_CLIENT_SECRET` | Same production Google client secret; required by existing startup validation |

The runner uses SMTP `smtp.gmail.com:587` with STARTTLS, a 20-second timeout,
`APPLICATION_ORIGIN=https://verimeet.onrender.com`, production security settings,
and database evidence. No Resend key or object-storage credentials are needed on
the runner. This does not change the Render web service's email backend.

1. Ensure the deployed database migrations already exist. This workflow never
   repairs or applies schema changes. Match default-branch code to deployed code.
2. Ensure the Neon connection policy permits the GitHub-hosted runner. Prefer a
   dedicated database role with only the permissions these processors require;
   no schema modification permission is needed. Do not print the connection URL.
3. After review, publish the workflow to the default branch through your normal
   process. Enable Actions and allow the two SHA-pinned official actions. Protect
   the default branch and require trusted review of workflow/code changes: these
   jobs have production secrets and database access. No PR trigger is configured.
4. Open **Actions → Process email outboxes → Run workflow** on the default branch.
   This is a real delivery run: due queued messages can be sent to real recipients.
   Use a controlled invitation first and verify delivery and confirmation links.
5. Inspect the aggregate submitted/retried/failed/cancelled/expired counts for both
   commands. A green workflow means the processors ran, not that every email was
   delivered: individual mail failures can be counted without a nonzero exit.
   Enable workflow-failure notifications and periodically inspect queue age and
   failed counts through authorized application diagnostics.

## Limits and recovery

Concurrency allows only one active run; scheduled/manual runs do not cancel an
active mail submission. Pending runs may be replaced by newer runs. Existing
database claims and 120-second leases remain the recovery mechanism for timeout,
cancellation or uncertain SMTP acceptance; delivery is at-least-once and duplicates
remain possible. Do not reset leases/tokens manually. The job has a ten-minute
limit and each batch is bounded to five rows; no unbounded loop is introduced.

GitHub schedules are best-effort, can be delayed/dropped, and are subject to Actions
minutes/billing limits. Public repositories can have schedules disabled after
inactivity. This is suitable for testing, not a guaranteed five-minute mail SLA.
Gmail account quotas, App Password eligibility and student-domain filtering still
apply. Do not enable debug logging or upload environment/message dumps as artifacts.
These two outboxes work independently of Render sleeping. Password-reset and other
direct web-request emails still use the web service's configured backend.

References: [GitHub scheduled events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule),
[Google App Passwords](https://support.google.com/accounts/answer/185833),
[Gmail SMTP](https://developers.google.com/workspace/gmail/imap/imap-smtp).
