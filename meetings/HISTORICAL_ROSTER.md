# Historical roster

Migration 0009 adds one protected roster per newly finalized Meeting. Apply through
the normal migration process; this implementation does not apply it to development.
No legacy rows are backfilled. Viewing/exporting never captures a roster.

Meeting.save captures on Draft -> Finished and direct Finished/Archived creation,
in the same transaction. Entries are sorted by copied user ID, capped at 10,000,
validated and immutable. Global Admin authority alone adds nobody. Active explicit
members plus active legacy-only department users are unioned with all assignments.
Assigned anomalies are retained with member=false and no invented role.

Absent means captured members without an assignment, not attendance status Absent.
Names, roles and assignment classification never change. Current attendance and
signing summaries remain live. Finished/Archived Attendance cannot be deleted, including
through User cascades. Deletion of an unassigned User may proceed while copied roster
identity remains; signed evidence continues to independently block deletion. HistoricalRoster protects
Meeting deletion; existing Department deletion guards remain in force.

Finalization locks Department before Meeting. Membership.save and collected removal
share Department write serialization; assignment creation/reassignment locks Meeting.
SQLite serializes all writers once the Department no-op write succeeds; concurrent
profile edits therefore commit wholly before or after capture. SQLITE_BUSY is a
failed transaction requiring caller retry, never permission to assume capture succeeded.
Do not catch database errors inside the atomic block and continue.

Limitations: PostgreSQL/other database deployment needs dedicated contention validation
and a unified profile/membership lock protocol before claiming the same cross-row
name/population guarantee. Existing Admin/user deletion transactions may already hold
User/Attendance locks before membership removal: database deadlocks must roll back and
be retried; no deadlock-free guarantee is claimed. Bulk Membership insertion/update,
raw SQL and explicit base QuerySet/ORM bypasses are trusted administrative boundaries.
Meeting bulk status transitions are rejected; bulk creation supports Draft only.
Attendance structural queryset/bulk creation is rejected; use instance saves.
Raw SQL is not protected. Do not use these bypasses for normal finalization.

Legacy finalized meetings display current surviving assignments and an explicit
historical-roster-unavailable notice. They never fabricate an Absent list. PDFs remain
dynamic: signing, attendance, generation time and renderer versions can change bytes.
Signed payload formats are unchanged.

## Operation-level synchronization (no lock tracker)

No connection-local state, transaction tokens or inferred lock ownership are used.
HTTP finalization enters atomic, guards Department, locks/revalidates Meeting, saves
status and captures once through Meeting.save, then records the finalization audit.
Failure rolls everything back. Direct Meeting.save uses the same capture and actual
Department guard; callers must not already hold incompatible Meeting/User locks.
Arbitrary caller-owned lock order is unsupported and cannot be detected.

Name-writing operations freeze exact User IDs, discover explicit memberships, legacy
anchors (even currently suppressed ones) and anomalous assignment departments, acquire
sorted Department write guards, then revalidate scope and users. Expansion fails closed;
retry the entire operation. Queryset updates write only frozen IDs, not the original
mutable filter. Full instance saves always participate because stale names may be
written. Admin guards scope before its User locks; signature-file saves participate
before User writes. Bulk name/legacy-anchor updates remain restricted.

Membership saves include both old/new users/departments and their legacy anchors.
Collected removal guards that scope before deletion, so removing a last membership in
another department coordinates with the newly activated legacy roster. Invitation
acceptance/elevation pre-guard their affected user scope. Department deletion pre-guards
membership users before Meeting/Attendance work. No permission/fallback policy changes.

SQLite writer serialization is covered by deterministic TransactionTestCase tests.
PostgreSQL/other row-locking backend behavior is not validated. Relationship expansion
can still occur after revalidation on a row-locking database without a larger shared
user/membership protocol. Existing caller-owned User locks, cascades or membership
bulk operations may deadlock or bypass ordering: roll back and retry, never continue
inside a failed transaction. No universal deadlock-prevention guarantee is claimed.

Bulk Membership writes are trusted administrative boundaries, not supported normal
membership workflows. Raw SQL, base QuerySet calls and private ORM bypasses remain
outside protection. No database-level immutability is claimed. Nested savepoints and
reused atomic objects carry no Python lock state. Legacy meetings remain unbackfilled.

Final correction: User creation is identified by _state.adding, including explicit
primary keys, and inserts cannot fall back to overwriting an existing account.
Legacy-department creations acquire the Department guard before insertion; key
creation and signature guards remain in force. Existing saves use profile synchronization.

Guard revalidation compares membership row IDs/users/departments/roles, User activity
and legacy anchors, and assignment identities, not just Department sets. Same-scope
replacement or role/activity changes before guard acquisition cause a retry. Supported
account activity services also guard affected Departments before User locks. This does
not validate row-locking database races after revalidation, nor make bulk/raw writes
supported normal membership operations. SQLite remains the tested backend.
