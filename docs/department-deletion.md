# Confirmed Department destruction

Only persisted, authenticated, active Global Admins (`is_admin` or `is_superuser`)
can use this workflow. Django Admin additionally requires its usual staff and
model permission checks. The application page does not require staff status.

Individual Admin deletion and the replacement bulk action share the application
confirmation page and centralized service. Confirmation requires typed `DELETE`,
a reason, and a signed ten-minute inventory token. Actor, database alias, exact
root IDs and a hash of affected rows are bound into the token. Successful tokens
are recorded in surviving audit events and rejected on reuse. Invalid/stale
submissions show a fresh inventory and require confirmation again.

Direct Department ORM deletion is rejected. The service revalidates the actor
under a row lock and uses one database transaction for the entire batch. It locks
all Departments in deterministic order because membership guards can span other
Departments, then target Meetings and Attendance and the inventoried descendants.
This conservative strategy may briefly block unrelated Department operations.
The context-local capability contains exact model/row IDs and the database alias;
it is installed only inside the validated transaction and reset in `finally`.

Snapshot and historical-roster rows are explicitly deleted before the Department
cascade. Their PROTECT relationships and ordinary deletion guards remain intact.
Attendance Admin permissions are unchanged. A failure, including audit insertion
failure, rolls back the batch and its audit records.

User accounts, signing keys, profile signatures, retained signatures and immutable
underlying storage bytes are retained. Snapshot bytes can become inaccessible
through normal application relationships after their relational metadata is
removed. There is deliberately no storage cleanup or orphan purging.

Department deletion audits preserve actor ID, target names/IDs, reason, operation
ID, timestamp and batch record counts. Existing audit relationships become null;
stable IDs and deletion metadata survive. Delivery history survives invitation
deletion; queued/processing invitations are cancelled, but already submitted mail
cannot be recalled.

Run isolated SQLite checks without selecting a database from `.env`:

```powershell
.\venv\Scripts\python.exe -B -m accounts.run_department_tests
.\venv\Scripts\python.exe -B -m accounts.run_department_tests check
```

The runner forces in-memory SQLite and a test signing-encryption key. Extra test
labels may be supplied as arguments. SQLite verifies atomic rollback, stale
inventories and scope cleanup; it cannot establish PostgreSQL row-lock or deadlock
behavior. A separate local PostgreSQL concurrency run is still required before
claiming production-equivalent concurrency guarantees. No Render/Neon or external
storage access is part of these checks. Large inventories are materialized and
hashed in memory; very large Departments may require later bounded pagination
and performance work without changing confirmation semantics.


## Review corrections

Expiration is checked again after locked inventory validation, immediately before
creating the capability. PostgreSQL SQLSTATE 40P01 (deadlock) and 55P03 (lock not
available/lock timeout) are handled only after the deletion transaction unwinds.
A separate `department.deletion_failed` audit marker invalidates that operation's
confirmation. No successful-deletion event survives a failed transaction. If even
the failure marker cannot be persisted, the database exception propagates for
server diagnosis; the workflow never automatically retries destruction.

The runner now configures two independent in-memory SQLite aliases, forces the
locmem mailer, clears external email/storage credentials and endpoints, disables
durable external storage, and denies Python socket connections. It accepts only
the listed focused regression modules/classes, rather than arbitrary test labels.
Tests can explicitly override storage configuration for mocked evidence tests;
the socket guard remains active. This is not an operating-system network sandbox.

Lock-order review: membership/status/profile-name paths acquire Department locks
before user changes; finalization acquires Department then Meeting; signing locks
Meeting then User then Attendance. Deletion retains these relative orders. User
administration and foreign-key checks can still introduce contention or inversions
when an existing transaction holds a User lock before requesting a Department.
The narrow failure handler supplies rollback and reconfirmation, not a proof that
all deadlocks are eliminated. No PostgreSQL executable or Windows service was
available during corrections; no infrastructure was installed or configured.

Remaining local PostgreSQL validation: in a disposable database, use independent
connections and barriers to race deletion against signing, finalization,
membership creation/removal, user administration, and another deletion. Assert
bounded completion (or the documented safe lock failure), no partial descendants,
no successful audit on rollback, exactly one successful operation where applicable,
unchanged external evidence, revoked-token rejection, and capability cleanup.
Also test genuine 40P01 and 55P03 exceptions; SQLite tests inject driver SQLSTATEs
and cannot prove server lock behavior. Do not use deployment database URLs.


## Transaction ownership and relationship review

The deletion service uses a durable atomic block and must be called outside an
existing application transaction (including ATOMIC_REQUESTS). Nested calls fail
before deletion or failure-marker handling. This makes the failure marker written
after rollback independent of a caller transaction, without secondary connections.
The public service explicitly rejects any enclosing atomic block or disabled
autocommit, including Django TestCase isolation blocks. Successful-deletion tests
use TransactionTestCase rather than bypassing the production guard.

Inventory creation validates the reviewed reverse-relationship manifest against
Django's collector candidates, including hidden relations. New or changed deletion
relationships fail closed until their inventory and retention semantics are reviewed.
Generic deletion relations also fail closed. The existing graph has no omitted
cascade/protected models. Retained SET_NULL edges are explicitly recorded too.
