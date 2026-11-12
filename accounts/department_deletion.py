"""Confirmed Department deletion. Immutable evidence bytes are retained."""
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
import json
import uuid
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


def _delete_departments(actor, ids, *, confirmation, typed, reason, using='default'):
    if not authorized(actor) or typed != 'DELETE' or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 1000:
        raise PermissionDenied('Active Global Admin, typed DELETE and a reason are required.')
    try:
        payload = signing.loads(confirmation, salt=SALT, max_age=600)
    except signing.BadSignature:
        raise PermissionDenied('Invalid or expired confirmation. Start again.') from None
    ids = sorted(set(ids))
    if payload.get('actor') != actor.pk or payload.get('using') != using or payload.get('ids') != ids:
        raise PermissionDenied('Confirmation does not match this operation.')
    with transaction.atomic(using=using, durable=True):
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
        if AuditLog.objects.using(using).filter(event_type__in=('department.deleted', 'department.deletion_failed'),
                metadata__operation_id=payload['operation']).exists():
            raise PermissionDenied('Confirmation already used.')
        list(Attendance.objects.using(using).filter(meeting__department_id__in=ids).order_by('pk').select_for_update())
        departments, counts, revision, scope = inventory(ids, using, lock=True)
        if revision != payload['revision']:
            raise PermissionDenied('Affected records changed. Review and confirm again.')
        try:
            signing.loads(confirmation, salt=SALT, max_age=600)
        except signing.BadSignature:
            raise PermissionDenied('Confirmation expired while waiting. Review and confirm again.') from None
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
        finally:
            _scope.reset(marker)


def delete_departments(actor, ids, *, confirmation, typed, reason, using='default'):
    connection = connections[using]
    if connection.in_atomic_block or not connection.get_autocommit():
        raise RuntimeError('Department deletion requires ownership of its transaction.')
    try:
        return _delete_departments(actor, ids, confirmation=confirmation, typed=typed,
                                   reason=reason, using=using)
    except OperationalError as exc:
        cause = exc.__cause__
        code = getattr(cause, 'sqlstate', None) or getattr(cause, 'pgcode', None)
        if code not in {'40P01', '55P03'}:
            raise
        # The inner atomic block has exited and rolled back, including audits.
        # Retain a failure marker so this confirmation cannot be reused.
        payload = signing.loads(confirmation, salt=SALT)
        AuditLog.objects.using(using).create(
            event_type='department.deletion_failed', action='Department deletion lock failure',
            metadata={'operation_id': payload['operation'], 'actor_id': actor.pk})
        raise PermissionDenied('Deletion was rolled back because records were busy. Review and confirm again.') from None


def delete_with_audit(actor, department, **kwargs):
    return delete_departments(actor, [department.pk], using=kwargs.pop('using', None) or department._state.db or 'default', **kwargs)
