# Account status and session revocation

Only fresh, active VeriMeet Global Admins may manage eligible non-admin accounts.
Self-targeting and all Global Admin targets are prohibited. Application controls
require a signed confirmation state and CSRF-protected POST; Django Admin requires
explicit confirmation and delegates transitions to the same service. Combined
privilege/status changes cannot remove target protection. There is no bulk action.

`change_account_status` locks actor and target in stable order using no-op writes
for SQLite, reloads authority and target flags, and commits status, revocation
version and audit together. Admin role edits use the same locking order. Status
changes preserve memberships, keys, invitations, retained assets and evidence.

`session_version` increments on deactivation. It participates in Django's session
authentication hash, including secret-key fallback handling. Version zero keeps
pre-deployment session compatibility; after revocation, old hashes never match,
even following reactivation. Password and Google logins use existing backends;
no password/key changes or session-table scans are required. A login using a stale
pre-deactivation User can issue a cookie, but that cookie fails validation on its
next request. Ordinary saves cannot overwrite a stale revocation version.

No mechanism can cancel an HTTP action already completed. Requests that loaded
their authenticated user before deactivation may finish; sensitive status mutations
recheck authority under lock. Actual simultaneous-process contention should also
be exercised during integration testing.

Apply `accounts.0009_account_session_version` through the normal deployment
process before serving the updated code. This task does not apply it to the
development database. Direct SQL/private ORM calls remain trusted-code boundaries;
operational scripts must use the service for status changes and must not reset
revocation counters. No account deletion or bulk status procedure is provided.

Existing-account model saves ignore activity and revocation fields; queryset/bulk
writes to these fields are rejected. Initial creation retains the requested default
activity. The service alone performs supported status updates through its locked
internal ORM boundary. Admin privilege forms bind the original security flags in
a signed state token: unchanged flags merge from fresh state, while explicit edits
conflicting with fresh state are rejected. Tokens expire after one hour.
The Admin token also binds the original activity and session version to the target
account. Activity intent is compared with that signed original value, not a
POST-time database instance. Under the shared locks, any activity/version mismatch
rejects the entire submission, including unrelated edits and status cycles that
return to the same activity. Fresh signed expectations are passed unchanged to
the status service; no-op status persistence cannot overwrite newer account state.

Status confirmations validate expected activity and session version before no-op
handling. Stale/replayed/expired confirmations fail. A service call requesting an
already-current state with a matching version returns False without an audit event
or version increment; the web UI always requests the opposite state seen on GET.
