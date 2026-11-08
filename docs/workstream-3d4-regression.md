# Workstream 3D-4 regression recovery

Date: 2026-11-08. Review baseline: `main`, `eea4dec`.

## 1. Baseline and execution boundaries

Before editing, branch and HEAD matched the requested baseline and `git status
--short` was empty. The committed 3D-4A-1 routing/dashboard recovery was preserved.
Tests use Django's isolated test database; no development migrations or data
changes were performed. No staging, commits, pushes, live OAuth, real email
delivery, deployment configuration changes, or Workstream 4 features were used.

The initial sandbox could not access the virtual environment's base Python.
Subsequent Python commands ran with execution approval. PowerShell's native
stderr redirection reports Django's normal test-database messages as error records;
the Django summaries below are the authoritative test outcomes. The final full
run uses native command redirection to preserve its process exit status.

## 2. 3D-4A: account and invitation recovery

Files:

- `accounts/test_fixtures.py`: shared helpers for temporary private signature
  storage and explicit initial PNG uploads for named fixture users.
- `accounts/test_batch14.py`: complete the department creator's onboarding and
  prove that the injected creation audit failure is reached.
- `accounts/test_invitation_delivery.py`: onboard the AP, Officer, and foreign AP
  request actors without changing their roles or delivery assertions.
- `accounts/tests.py`: onboard the MultiDepartment/RBAC request actors and the
  two new invitation recipients used in acceptance tests. Existing routing
  recovery remains unchanged.
- `accounts/test_batch12.py`: onboard existing request actors, preserve the newly
  registered recipient's incomplete state, and assert the complete signup,
  verification, onboarding, invitation-return, explicit-acceptance sequence.
- `accounts/test_onboarding_compatibility.py`: remove the blanket signature-valid
  mock; retain every inherited compatibility test using the real base fixtures.

Root cause: older users lacked the mandatory PNG. Middleware redirected GETs and
rejected mutations before invitation, authorization, or transactional code ran.
The original Batch 14 audit rollback test could pass without calling the audit
function. It now asserts one call, the handled failure response, and rollback of
the department, membership, and audit rows.

Batch 12 now checks absence of membership after registration, after verification,
and after onboarding. A mutation before onboarding returns 403; only the final
explicit acceptance creates membership. Existing ownership, verified secondary
email, role-preservation, token-consumption, stale-context, unrelated-login,
OAuth-state simulation, and account-bound intent assertions remain in place.
The unrelated-login test's second account also has a genuine signature so its
denial reaches invitation authorization.

Checkpoint command:

```powershell
.\venv\Scripts\python.exe manage.py test accounts --noinput
```

First checkpoint: 292 tests, 3 failures, 0 errors, 150.800 seconds. The failures
were two newly created recipients missing signatures and the compatibility mock
misreporting the new signup recipient as onboarded. Corrected checkpoint:
**292 passed, 0 failures, 0 errors, 0 skips, 164.078 seconds**.

Exact unsuccessful tests at the first checkpoint (all corrected):

- `accounts.tests.MultiDepartmentAndRBACTests.test_invitation_creation_and_acceptance_roles`
- `accounts.tests.MultiDepartmentAndRBACTests.test_legacy_invitation_role_s_mapped_to_officer`
- `accounts.test_onboarding_compatibility.InvitationCompatibility.test_signup_verification_continuation`

## 3. 3D-4B: meeting workflow recovery

Files:

- `meetings/tests.py`: explicit real PNG fixtures for request actors in routing,
  creation/assignment, draft editing/finalization, cryptographic integration,
  signing, verification, attendance, QR, and PDF classes.
- `meetings/test_attendance_integrity.py`: genuine onboarding for the scanning
  Officer, so archive/race tests reach their intended attendance code.
- `meetings/test_participant_integrity.py`: retain compatibility tests, but use
  the corrected base fixtures instead of uploading a second initial signature
  over an existing signature or sweeping all users into completed onboarding.

`meetings/test_parent_deletion.py` was investigated and run without modification.
Its historical evidence fixtures and admin actors already exercise the intended
guards. Intentionally inactive/incomplete assignment candidates and historical
signed records in the focused integrity modules remain unchanged.

Root cause: missing onboarding in older authenticated request fixtures. Once
those actors reach the views, existing creation, editing, participant assignment,
department isolation, finalization, archival, signing, attendance, evidence,
deletion, and audit assertions require no policy or production changes.

## 4. 3D-4C: QR, audit, PDF, and integration recovery

The QR/signature/audit classes share the corrected fixture setup in
`meetings/tests.py`; invitation-delivery coverage is included in 3D-4A.
The baseline's missing VerificationQR/AuditLog records and JSON decoding errors
were downstream effects of requests stopped by onboarding. Re-running with real
uploads removed those errors without changing cryptography or QR behavior.

Two PDF tests additionally need an onboarded Officer to reach the PDF
authorization/UI checks. They upload only within those individual tests. The
separate PDF snapshot fixture still has no PNG and retains its explicit absence
assertion. No PNG embedding or signing-time visual snapshot feature was added.

Combined 3D-4B/3D-4C checkpoint command:

```powershell
.\venv\Scripts\python.exe manage.py test meetings.tests meetings.test_attendance_integrity meetings.test_participant_integrity meetings.test_parent_deletion --noinput
```

Result: **278 tests, 276 passed, 2 failures, 0 errors, 0 skips, 744.413 seconds**.
This run imported the PDF tests before the two individual fixture corrections.
Exact unsuccessful tests:

- `meetings.tests.Batch10PDFTests.test_export_links_and_officer_exclusion`
- `meetings.tests.Batch10PDFTests.test_permissions_and_methods`

Both received an onboarding redirect instead of reaching the expected Officer
authorization/UI response. The corrected focused checkpoint:

```powershell
.\venv\Scripts\python.exe manage.py test meetings.tests.Batch10PDFTests --noinput
```

**10 passed, 0 failures, 0 errors, 0 skips, 6.840 seconds**. It includes real PDF
rendering, pagination, Unicode text extraction, resource denial, detached
snapshots, sensitive-data exclusions, access control, and transactional auditing.

## 5. Test quality and production changes

All changes are test fixtures, stronger assertions, or this report. No production
code, models, migrations, policy, authorization, retention, lifecycle, or
cryptographic behavior changed. No tests were deleted or skipped. All inherited
compatibility test cases remain discoverable. Temporary storage has registered
cleanup, including setup failures; uploads use the supported initial FieldFile
API with genuine PNG bytes. No signature validation flags are forged.

The mandatory onboarding middleware stays enabled. Existing account revocation,
invitation ownership and explicit acceptance, Global Admin/AP/Officer boundaries,
membership precedence, POST/CSRF, QR token expiry/revocation, audit rollback,
delivery state transitions, signature retention, and deletion assertions remain.

## 6. 3D-4D: full integration verification

The untouched baseline run discovered/executed 570 tests in 883.264 seconds and
reported 183 failures and 23 errors. These are unittest failure/error counts,
including subtests; they should not be subtracted from 570 to infer a precise
baseline passed-test count.

Final command:

```powershell
.\venv\Scripts\python.exe manage.py test --noinput
```

Final result: **570 discovered, 570 passed, 0 failures, 0 errors, 0 skipped,
852.997 seconds; process exit code 0**. The test database was destroyed at
completion. Exact remaining unsuccessful tests: **none**. Discovery remains
570, matching the baseline; no tests were removed or skipped.

All 3D-4A, 3D-4B, 3D-4C, and 3D-4D automated checkpoints are complete. The final
full run includes every affected account and meeting module and the final PDF
and signup assertions, superseding the interim fixture failures.

**Workstream 3D-4 is ready for closure following independent review.** Workstream
3's automated regression/integration gate is clear. Overall release sign-off
still needs the manual checks below; this session does not certify production
deployment or live identity/email integration.

## 7. Additional checks, risks, and manual verification

- `manage.py check`: no issues (0 silenced), exit code 0; rerun at completion.
- `manage.py makemigrations --check --dry-run`: no changes detected, exit code 0;
  rerun at completion. No development migrations applied.
- `git diff --check`: no whitespace errors, exit code 0.
- Branch/HEAD remain `main` / `eea4dec`; staged diff is empty.
- Final source changes: eight modified tracked test files, plus the new
  `accounts/test_fixtures.py` helper and this report. The tracked diff is
  90 insertions and 40 deletions across eight files; Git's ordinary diff stat
  excludes the two untracked files. All changes remain unstaged/uncommitted.

No remaining automated failures or confirmed production defects were found.

Windows GLib emits installed-app association warnings during real PDF rendering;
the focused rendering tests pass. No renderer behavior was changed to suppress
them.

Manual verification was not performed in a browser or against production. Before
overall Workstream 3/release sign-off, confirm the browser signup/email/onboarding/
explicit-acceptance journey, account deactivation/reactivation across independent
sessions, and private-signature access at the deployed public origin. Existing
deployment requirements in `private-signatures.md` and `account-status.md` remain
applicable; no development migration or deployment action was taken here.

Raw execution logs are retained outside the working tree at
`C:/Users/seah/AppData/Local/Temp/verimeet-3d4-20261108-eea4dec/` for independent
review. The phase totals above are from the completed Django summaries, not
interim progress output.
