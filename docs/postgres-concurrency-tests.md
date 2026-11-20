# Disposable local PostgreSQL Department tests

Preparation does not connect to PostgreSQL. Use the guarded module runner only;
production settings and `.env` are never imported by this configuration.

Approved PostgreSQL target: `127.0.0.1:5432/verimeet_concurrency_test`, role
`verimeet_test_user1`. Password source: process environment variable
`VERIMEET_PG_TEST_PASSWORD`. Do not use a Neon password.

Static check (no password or database required):

```powershell
Set-Location E:\codes\verimeet
.\venv\Scripts\python.exe -B -m accounts.run_postgres_department_tests --check-config
```

Set the local password without echoing it or placing it in shell history:

```powershell
$localPgSecret = Read-Host 'Local PostgreSQL test role password' -AsSecureString
$localPgPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($localPgSecret)
try {
    $env:VERIMEET_PG_TEST_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($localPgPointer)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($localPgPointer)
    Remove-Variable localPgSecret, localPgPointer
}
```

Future execution, only after confirming the named database is disposable:

```powershell
try {
    .\venv\Scripts\python.exe -B -m accounts.run_postgres_department_tests --run --confirm-disposable verimeet_concurrency_test
}
finally {
    Remove-Item Env:VERIMEET_PG_TEST_PASSWORD -ErrorAction SilentlyContinue
}
```

This command was NOT executed during preparation. It WILL migrate and tests WILL
flush/delete records in the approved database. The database must already exist
and contain no records that need preservation. No PostgreSQL CREATE DATABASE,
DROP DATABASE, maintenance-database connection, or test database cloning is used.
The PostgreSQL database and schema remain afterward; do not use normal Django
`manage.py test` to bypass the runner. A second alias required by existing
regressions is independent in-memory SQLite, not another PostgreSQL database.

The local role does not need CREATEDB for this runner. It needs CONNECT on the
approved database, USAGE and CREATE on public, and ownership/privileges sufficient
to migrate, truncate, and manage every test table/sequence. Prefer an exclusively
owned disposable database with no tables owned by other roles. Privileges and
server availability were not checked during preparation. The future runner checks
connected database/user/server address/port and public-schema USAGE/CREATE before
migrations; migration errors still surface if existing object ownership is wrong.
Restrict the local role's grants to the disposable environment separately.

The runner requires non-atomic requests and direct-session affinity. Connection,
lock and statement timeouts are bounded. It uses temporary media/signature roots,
in-memory default storage, locmem mail, test-only encryption, blank external
credentials, and Python socket guards. psycopg's C transport is not intercepted
by Python socket guards: explicit connection configuration and the server identity
query protect its target. This is not an OS network sandbox.

Existing Department regression labels are allowlisted; the default runs
`accounts.test_department_deletion`. This includes a thread/interleaving regression,
but does not constitute the full independent-connection PostgreSQL concurrency
matrix. Dedicated races against signing, finalization, membership/user changes,
and overlapping bulk deletion still need to be implemented and run. Existing tests
also contain mocked PostgreSQL protocol cases; distinguish those from real server
coverage. No dependencies, databases, or services are installed by this runner.

## Hardened authorization and connection boundary

Loading these settings installs process-local Django and driver guards immediately.
Database access is denied until the dedicated runner authorizes `--run` or the
read-only `--preflight` mode. Direct `manage.py migrate`, `flush`, or `test` cannot
obtain a connection through this configuration without that authorization.
The configuration is checked on every Django ensure/connect path; each new
PostgreSQL connection also verifies its actual database, user, server address,
port, and backend PID before Django initialization or application SQL. Worker
threads may open independent connections only through the approved Django alias.
Additional aliases, changed targets/options, maintenance-database routing, and
direct psycopg module/class connections are denied. Async driver connections are
disabled. PostgreSQL create/drop helpers remain unused; only the existing approved
database is migrated/flushed after explicit destructive-test confirmation.

Expected driver connection failures are replaced with fixed diagnostics and, when
available, a validated five-character SQLSTATE. Passwords, DSNs and configuration
dictionaries are not printed. Unexpected programming exceptions are not broadly
suppressed. Private driver hooks in static tests are mocked and never contact a
server. Run only reviewed tests: malicious Python can undo process monkey patches,
use low-level native APIs, or launch a subprocess. This is not a hostile-code
sandbox. The role's server grants should remain restricted to the disposable DB.

Python socket connect, connect_ex, sendto, sendmsg (where available), and
create_connection are denied, including Python loopback networking. Legitimate
Django PostgreSQL connections use the allowlisted psycopg C transport. Native
transports and subprocesses are outside the socket guard. For stronger isolation,
use an OS firewall/sandbox allowing only the dedicated local PostgreSQL endpoint,
or a dedicated offline VM. Do not claim complete network isolation from these
Python guards alone.

## Subsequent non-destructive local validation (not executed in preparation)

First verify the listener from PowerShell without credentials or SQL:

```powershell
$listeners = Get-NetTCPConnection -LocalPort 5432 -State Listen
$listeners | Select-Object LocalAddress, LocalPort, OwningProcess
$listeners.OwningProcess | Sort-Object -Unique | ForEach-Object {
    Get-CimInstance Win32_Process -Filter "ProcessId = $_" |
        Select-Object ProcessId, Name, ExecutablePath
}
Get-Service *postgres* | Select-Object Name, Status
```

Confirm that the listener belongs to the intended installed PostgreSQL executable
and local service, not a proxy/forwarder. Inspect its executable version in file
properties and compare it with PostgreSQL 18.7. Do not proceed if the owner is
unknown, is a proxy, or the executable path cannot be verified. Elevated read-only
PowerShell may be needed to see executable paths. This is an operator verification;
matching IP/port or a momentary backend PID does not alone prove session affinity.

Set the dedicated password using the secure prompt above, then run only:

```powershell
.\venv\Scripts\python.exe -B -m accounts.run_postgres_department_tests --preflight
Remove-Item Env:VERIMEET_PG_TEST_PASSWORD -ErrorAction SilentlyContinue
```

Preflight opens only the pinned local target, checks actual identity and PID,
queries version/backend PID, then closes connections. It does not migrate, flush,
create/drop databases, or run tests. A connection starts a read-only identity
probe which is rolled back before Django initializes the session. Later concurrency
tests must compare independent backend PIDs and prove same-session advisory-lock
ownership across transaction rollback and marker commit; preflight alone does not
establish those concurrency guarantees. Real role privileges and server behavior
remain unverified until an approved local connection is made.

Static/mocked infrastructure validation (no real connections):

```powershell
.\venv\Scripts\python.exe -B -m accounts.test_postgres_infrastructure
.\venv\Scripts\python.exe -B -m accounts.run_postgres_department_tests --check-config
```
