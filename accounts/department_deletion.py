"""Confirmed Department deletion. Immutable evidence bytes are retained."""
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from weakref import WeakValueDictionary
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
import json
import logging
import re
import uuid
from django.conf import settings
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.db import transaction, connections, OperationalError
from django.db.models import F, Q
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import Department, Membership, User, Invitation, InvitationDelivery, RoleElevationRequest
from .audit import record
from meetings.models import (Meeting, Attendance, VerificationQR, SigningVisualSnapshot,
                             HistoricalRoster, QRSession, QRUsage, AuditLog)

_scope = ContextVar('department_deletion_scope', default=None)
SALT = 'department-destruction-v1'
CLAIM_EVENT = 'department.deletion_claimed'


class DepartmentDeletionUnavailable(RuntimeError):
    """The database configuration cannot safely execute Department deletion."""


@dataclass(frozen=True)
class _DeletionScope:
    actor_id: int
    operation_id: str
    using: str
    descendants: object


def authorized(actor):
    return bool(actor and actor.pk and actor.is_authenticated and actor.is_active
                and (actor.is_admin or actor.is_superuser))


def scoped(instance, using):
    scope = _scope.get()
    return bool(scope and scope.using == using and connections[using].in_atomic_block
                and instance.pk in scope.descendants.get(instance._meta.label, frozenset()))


@receiver(pre_delete, sender=Department, dispatch_uid='protect_department_evidence')
def protect_department_evidence(sender, instance, using, **kwargs):
    if not scoped(instance, using):
        raise PermissionDenied('Use the confirmed Global Admin Department deletion workflow.')


# Reviewed reverse-FK edges traversed by Django's deletion collector. SET_NULL
# edges are retained, not traversed; CASCADE/PROTECT descendants are inventoried.
REVIEWED_RELATIONS = frozenset({
    ('accounts.Department', 'accounts.User', 'department', 'SET_NULL'),
    ('accounts.Department', 'accounts.Membership', 'department', 'CASCADE'),
    ('accounts.Department', 'accounts.Invitation', 'department', 'CASCADE'),
    ('accounts.Department', 'accounts.RoleElevationRequest', 'department', 'CASCADE'),
    ('accounts.Department', 'meetings.Meeting', 'department', 'CASCADE'),
    ('accounts.Department', 'meetings.AuditLog', 'department', 'SET_NULL'),
    ('meetings.Meeting', 'meetings.Attendance', 'meeting', 'CASCADE'),
    ('meetings.Meeting', 'meetings.AuditLog', 'meeting', 'SET_NULL'),
    ('meetings.Meeting', 'meetings.QRSession', 'meeting', 'CASCADE'),
    ('meetings.Meeting', 'meetings.HistoricalRoster', 'meeting', 'PROTECT'),
    ('meetings.Attendance', 'meetings.SigningVisualSnapshot', 'attendance', 'PROTECT'),
    ('meetings.Attendance', 'meetings.VerificationQR', 'attendance', 'CASCADE'),
    ('meetings.QRSession', 'meetings.QRUsage', 'qr_session', 'CASCADE'),
    ('accounts.Invitation', 'accounts.InvitationDelivery', 'invitation', 'SET_NULL'),
})


def deletion_relations():
    from django.db.models.deletion import get_candidate_relations_to_delete
    pending, visited, edges = [Department], set(), set()
    while pending:
        model = pending.pop()
        if model in visited:
            continue
        visited.add(model)
        # Generic relations also require explicit inventory/collector review.
        if any(hasattr(field, 'bulk_related_objects') for field in model._meta.private_fields):
            raise PermissionDenied('Unreviewed generic deletion relationship.')
        for relation in get_candidate_relations_to_delete(model._meta):
            child, field = relation.related_model, relation.field
            policy = field.remote_field.on_delete.__name__
            edges.add((model._meta.label, child._meta.label, field.name, policy))
            if policy in {'CASCADE', 'PROTECT', 'RESTRICT'}:
                pending.append(child)
    return frozenset(edges)


def validate_deletion_relations():
    if deletion_relations() != REVIEWED_RELATIONS:
        raise PermissionDenied('Department deletion relationships changed; inventory review required.')


def inventory(ids, using, *, lock=False):
    validate_deletion_relations()
    ids = sorted(set(ids))
    if not ids or any(type(pk) is not int or pk <= 0 for pk in ids):
        raise PermissionDenied('Invalid Department selection.')
    departments = list(Department.objects.using(using).filter(pk__in=ids).order_by('pk'))
    if [d.pk for d in departments] != ids:
        raise PermissionDenied('Department selection changed. Start again.')
    queries = {
        Department: Department.objects.filter(pk__in=ids),
        Meeting: Meeting.objects.filter(department_id__in=ids),
        Attendance: Attendance.objects.filter(meeting__department_id__in=ids),
        VerificationQR: VerificationQR.objects.filter(attendance__meeting__department_id__in=ids),
        SigningVisualSnapshot: SigningVisualSnapshot.objects.filter(attendance__meeting__department_id__in=ids),
        HistoricalRoster: HistoricalRoster.objects.filter(meeting__department_id__in=ids),
        Membership: Membership.objects.filter(department_id__in=ids),
        Invitation: Invitation.objects.filter(department_id__in=ids),
        RoleElevationRequest: RoleElevationRequest.objects.filter(department_id__in=ids),
        InvitationDelivery: InvitationDelivery.objects.filter(invitation__department_id__in=ids),
        QRSession: QRSession.objects.filter(meeting__department_id__in=ids),
        QRUsage: QRUsage.objects.filter(qr_session__meeting__department_id__in=ids),
    }
    if lock:
        for model, query in queries.items():
            list(query.using(using).order_by('pk').select_for_update())
    rows = {m._meta.label: list(q.using(using).order_by('pk').values()) for m, q in queries.items()}
    retained = {
        'detached_users': list(User.objects.using(using).filter(department_id__in=ids).order_by('pk').values('id', 'department_id')),
        'retained_audits': list(AuditLog.objects.using(using).filter(Q(department_id__in=ids) | Q(meeting__department_id__in=ids)).order_by('pk').values_list('pk', flat=True)),
    }
    revision = sha256(json.dumps([rows, retained], sort_keys=True, default=str).encode()).hexdigest()
    counts = {label: len(values) for label, values in rows.items()}
    counts['signed_attendance'] = queries[Attendance].using(using).filter(
        Q(has_signed=True) | Q(signed_at__isnull=False) |
        (Q(cryptographic_signature__isnull=False) & ~Q(cryptographic_signature=''))).count()
    for status in ('Draft', 'Finished', 'Archived'):
        counts['meetings_' + status] = queries[Meeting].using(using).filter(status=status).count()
    counts['users_detached'] = User.objects.using(using).filter(department_id__in=ids).count()
    counts['audit_records_retained'] = AuditLog.objects.using(using).filter(Q(department_id__in=ids) | Q(meeting__department_id__in=ids)).count()
    scope = {label: frozenset(row['id'] for row in values) for label, values in rows.items()}
    return departments, counts, revision, scope


def prepare(actor, ids, using='default'):
    current = User.objects.using(using).filter(pk=getattr(actor, 'pk', None)).first()
    if not authorized(actor) or not authorized(current):
        raise PermissionDenied('Active Global Admin access required.')
    departments, counts, revision, _ = inventory(ids, using)
    token = signing.dumps(dict(actor=current.pk, using=using, ids=[d.pk for d in departments],
                              revision=revision, operation=uuid.uuid4().hex), salt=SALT)
    return departments, counts, token


def _delete_departments(actor, ids, *, confirmation, payload, reason, using, session_check):
    with transaction.atomic(using=using, durable=True):
        session_check()
        # Membership guards span Departments. Lock the complete set in order
        # before taking any child or actor locks to avoid subset inversions.
        for pk in Department.objects.using(using).order_by('pk').values_list('pk', flat=True):
            Department.objects.using(using).filter(pk=pk).update(name=F('name'))
        list(Department.objects.using(using).order_by('pk').select_for_update())
        for pk in Meeting.objects.using(using).filter(department_id__in=ids).order_by('pk').values_list('pk', flat=True):
            Meeting.objects.using(using).filter(pk=pk).update(status=F('status'))
        list(Meeting.objects.using(using).filter(department_id__in=ids).order_by('pk').select_for_update())
        current = User.objects.using(using).select_for_update().filter(pk=actor.pk).first()
        if not authorized(current):
            raise PermissionDenied('Global Admin privileges changed.')
        list(Attendance.objects.using(using).filter(meeting__department_id__in=ids).order_by('pk').select_for_update())
        departments, counts, revision, scope = inventory(ids, using, lock=True)
        if revision != payload['revision']:
            raise PermissionDenied('Affected records changed. Review and confirm again.')
        try:
            signing.loads(confirmation, salt=SALT, max_age=600)
        except signing.BadSignature:
            raise PermissionDenied('Confirmation expired while waiting. Review and confirm again.') from None
        session_check()
        marker = _scope.set(_DeletionScope(current.pk, payload['operation'], using,
                                          MappingProxyType(scope)))
        try:
            for department in departments:
                for membership in Membership.objects.using(using).filter(department=department).order_by('pk'):
                    record(current, 'membership.removed', membership, department,
                           {'user_id': membership.user_id, 'previous_role': membership.role}, using=using)
                record(current, 'department.deleted', department, department, {
                    'operation_id': payload['operation'], 'reason': reason.strip(),
                    'departments': [{'id': d.pk, 'name': d.name} for d in departments],
                    'affected_counts': counts, 'actor_id': current.pk,
                    'evidence_bytes_retained': True}, using=using)
            SigningVisualSnapshot.objects.using(using).filter(pk__in=scope[SigningVisualSnapshot._meta.label]).delete()
            HistoricalRoster.objects.using(using).filter(pk__in=scope[HistoricalRoster._meta.label]).delete()
            Department.objects.using(using).filter(pk__in=ids).delete()
            session_check()
        finally:
            _scope.reset(marker)


# SQLite compatibility only; production PostgreSQL serializes across workers.
_local_operations = WeakValueDictionary()
_local_operations_guard = Lock()


@contextmanager
def _operation_lock(connection, operation):
    if connection.vendor == 'postgresql':
        # An administrator must explicitly attest backend-session affinity for
        # this alias. PID sampling alone cannot detect a transaction pooler that
        # happens to return the same backend during a short probe.
        affinity = getattr(settings, 'DEPARTMENT_DELETION_SESSION_AFFINITY', {}).get(connection.alias)
        host = str(connection.settings_dict.get('HOST', '')).lower()
        if affinity not in {'direct', 'session'} or '-pooler' in host or 'pgbouncer' in host:
            raise DepartmentDeletionUnavailable(
                'Department deletion requires explicitly configured backend-session affinity.')
        key = int.from_bytes(sha256(json.dumps(
            ['verimeet.department-delete', connection.alias, operation]).encode()).digest()[:8],
            byteorder='big', signed=True)
        raw = None
        discarded = False
        cleanup_error = None
        def discard():
            nonlocal discarded, cleanup_error
            if discarded:
                if cleanup_error is not None:
                    raise cleanup_error
                return
            discarded = True
            errors = []
            replacement = connection.connection
            handles = [raw] if raw is not None else []
            if replacement is not None and replacement is not raw:
                handles.append(replacement)
            # No cursor/ensure_connection calls here. Close the original session
            # and any replacement even if Django's close() would short-circuit.
            for handle in handles:
                try:
                    handle.close()
                except Exception as exc:
                    errors.append(exc)
            try:
                connection.close()
            except Exception as exc:
                errors.append(exc)
            finally:
                connection.connection = None
                connection.run_on_commit = []
                connection.errors_occurred = True
                connection.health_check_done = False
                if connection.in_atomic_block:
                    connection.closed_in_transaction = True
                    connection.needs_rollback = True
            if errors:
                cleanup_error = (errors[0] if len(errors) == 1 else
                                 ExceptionGroup('Department deletion connection cleanup failed.', errors))
                raise cleanup_error
        def check_handle():
            # Proxies can supply a driver-visible cancellation PID that
            # differs from the SQL backend PID used to verify lock ownership.
            if raw is None or connection.connection is not raw or raw.closed:
                raise RuntimeError('Department deletion backend session changed.')
        def check_session():
            try:
                check_handle()
                with connection.cursor() as cursor:
                    check_handle()
                    cursor.execute('SELECT pg_backend_pid()')
                    if cursor.fetchone()[0] != pid:
                        raise RuntimeError('Department deletion backend session changed.')
            except Exception:
                discard()
                raise
        try:
            with connection.cursor() as cursor:
                raw = connection.connection
                cursor.execute('SELECT pg_backend_pid(), pg_try_advisory_lock(%s)', [key])
                pid, acquired = cursor.fetchone()
                check_handle()
        except Exception:
            discard()
            raise
        if not acquired:
            raise PermissionDenied('This deletion confirmation is already being processed. Review again later.')
        try:
            yield check_session
        finally:
            try:
                check_handle()
                with connection.cursor() as cursor:
                    check_handle()
                    # CASE prevents unlocking on an unexpected backend.
                    cursor.execute('SELECT pg_backend_pid(), CASE WHEN pg_backend_pid() = %s '
                                   'THEN pg_advisory_unlock(%s) ELSE false END', [pid, key])
                    released_pid, released = cursor.fetchone()
                    if released_pid != pid or not released:
                        raise RuntimeError('Department deletion backend session changed.')
            except Exception:
                discard()
                raise
    elif connection.vendor == 'sqlite':
        with _local_operations_guard:
            lock = _local_operations.get((connection.alias, operation))
            if lock is None:
                lock = Lock()
                _local_operations[(connection.alias, operation)] = lock
        if not lock.acquire(blocking=False):
            raise PermissionDenied('This deletion confirmation is already being processed. Review again later.')
        try:
            yield lambda: None
        finally:
            lock.release()
    else:
        raise RuntimeError('Unsupported Department deletion database backend.')


def _log_deletion_failure(stage, exc, claim_committed, deletion_committed):
    # Temporary production diagnostic. Logging must never mask the original error.
    try:
        sqlstate = '-'
        for error in (exc.__cause__, exc):
            code = getattr(error, 'sqlstate', None) or getattr(error, 'pgcode', None)
            if isinstance(code, str) and re.fullmatch(r'[0-9A-Z]{5}', code):
                sqlstate = code
                break
        logging.getLogger('gunicorn.error').error(
            'Department deletion failed stage=%s exception=%s sqlstate=%s '
            'claim_committed=%s deletion_committed=%s',
            stage, type(exc).__name__, sqlstate, claim_committed, deletion_committed,
        )
    except Exception:
        pass


def delete_departments(actor, ids, *, confirmation, typed, reason, using='default'):
    stage = 'request_validation'
    claim_committed = deletion_committed = False
    body_error = None
    try:
        connection, ids, payload = _validate_deletion_request(actor, ids, confirmation, typed, reason, using)
        stage = 'advisory_lock_acquisition'
        with _operation_lock(connection, payload['operation']) as session_check:
            try:
                stage = 'confirmation_claim'
                _claim_confirmation(actor, payload['operation'], using, session_check)
                claim_committed = True
                stage = 'deletion_transaction'
                try:
                    result = _delete_departments(actor, ids, confirmation=confirmation, payload=payload,
                                                 reason=reason, using=using, session_check=session_check)
                except OperationalError as exc:
                    cause = exc.__cause__
                    code = getattr(cause, 'sqlstate', None) or getattr(cause, 'pgcode', None)
                    if code not in {'40P01', '55P03'}:
                        raise
                    # The deletion transaction rolled back. The committed claim
                    # prevents replay even if recording this outcome fails.
                    stage = 'failure_audit'
                    session_check()
                    AuditLog.objects.using(using).create(
                        event_type='department.deletion_failed', action='Department deletion lock failure',
                        metadata={'operation_id': payload['operation'], 'actor_id': actor.pk})
                    session_check()
                    raise PermissionDenied('Deletion was rolled back because records were busy. Review and confirm again.') from None
                deletion_committed = True
            except Exception as exc:
                body_error = exc
                raise
        return result
    except Exception as exc:
        expected_errors = (PermissionDenied, DepartmentDeletionUnavailable)
        if body_error is not None and not isinstance(body_error, expected_errors):
            _log_deletion_failure(stage, body_error, claim_committed, deletion_committed)
        if exc is not body_error and not isinstance(exc, expected_errors):
            if stage not in {'request_validation', 'advisory_lock_acquisition'}:
                stage = 'advisory_lock_cleanup'
            _log_deletion_failure(stage, exc, claim_committed, deletion_committed)
        raise


def _validate_deletion_request(actor, ids, confirmation, typed, reason, using):
    connection = connections[using]
    if connection.in_atomic_block or not connection.get_autocommit():
        raise RuntimeError('Department deletion requires ownership of its transaction.')
    if not authorized(actor) or typed != 'DELETE' or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 1000:
        raise PermissionDenied('Active Global Admin, typed DELETE and a reason are required.')
    try:
        payload = signing.loads(confirmation, salt=SALT, max_age=600)
    except signing.BadSignature:
        raise PermissionDenied('Invalid or expired confirmation. Start again.') from None
    ids = sorted(set(ids))
    if payload.get('actor') != actor.pk or payload.get('using') != using or payload.get('ids') != ids:
        raise PermissionDenied('Confirmation does not match this operation.')
    return connection, ids, payload


def _claim_confirmation(actor, operation, using, session_check):
    # Commit consumption before any deletion writes. Keep the claim free of
    # foreign keys so it does not depend on the rows the operation may remove.
    with transaction.atomic(using=using, durable=True):
        session_check()
        if not authorized(User.objects.using(using).filter(pk=actor.pk).first()):
            raise PermissionDenied('Global Admin privileges changed.')
        audits = AuditLog.objects.using(using)
        if audits.filter(event_type__in=(CLAIM_EVENT, 'department.deleted', 'department.deletion_failed'),
                         metadata__operation_id=operation).exists():
            raise PermissionDenied('Confirmation already used.')
        audits.create(event_type=CLAIM_EVENT, action='Department deletion confirmation claimed',
                      metadata={'operation_id': operation, 'actor_id': actor.pk})


def delete_with_audit(actor, department, **kwargs):
    return delete_departments(actor, [department.pk], using=kwargs.pop('using', None) or department._state.db or 'default', **kwargs)
