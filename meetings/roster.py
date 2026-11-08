"""Finalization roster. Department -> Meeting -> Attendance lock order."""
from django.core.exceptions import ValidationError, PermissionDenied
from django.db.models import F, Q, Exists, OuterRef
from accounts.models import Department, User, Membership


def lock_departments(ids, using='default'):
    from django.db import connections
    if not connections[using].in_atomic_block:
        raise PermissionDenied('Roster write guards require an atomic transaction.')
    for pk in sorted(set(ids) - {None}):
        Department.objects.using(using).filter(pk=pk).update(name=F('name'))


def user_department_scope(ids, using='default'):
    # Include the legacy anchor even while explicit membership suppresses it:
    # removing the last explicit membership can activate that relationship.
    from .models import Attendance
    departments = set(Membership.objects.using(using).filter(user_id__in=ids).values_list('department_id', flat=True))
    departments.update(User.objects.using(using).filter(pk__in=ids).exclude(department_id=None).values_list('department_id', flat=True))
    departments.update(Attendance.objects.using(using).filter(user_id__in=ids).values_list('meeting__department_id', flat=True))
    return departments


def user_membership_state(ids, using='default'):
    # Membership identity and role matter even when the Department set is unchanged.
    # Active/legacy state affects classification; assignment identity affects scope.
    from .models import Attendance
    return (
        tuple(User.objects.using(using).filter(pk__in=ids).order_by('pk').values_list('pk', 'is_active', 'department_id')),
        tuple(Membership.objects.using(using).filter(user_id__in=ids).order_by('pk').values_list('pk', 'user_id', 'department_id', 'role')),
        tuple(Attendance.objects.using(using).filter(user_id__in=ids).order_by('pk').values_list('pk', 'user_id', 'meeting_id', 'meeting__department_id')),
    )


def lock_user_scope(ids, using='default', extra_departments=()):
    ids = tuple(sorted(set(ids)))
    before = user_membership_state(ids, using)
    departments = user_department_scope(ids, using) | set(extra_departments)
    lock_departments(departments, using)
    if user_membership_state(ids, using) != before or not user_department_scope(ids, using).issubset(departments):
        raise PermissionDenied('Roster relationship scope changed. Retry the entire operation.')
    return ids


def lock_profile_names(users, using='default', extra_departments=()):
    # Evaluate a mutable caller filter exactly once. All subsequent reads/writes
    # use these IDs, never a reevaluation of the original filter.
    ids = tuple(sorted(set(users.values_list('pk', flat=True))))
    lock_user_scope(ids, using, extra_departments)
    frozen = User.objects.using(using).filter(pk__in=ids)
    persisted = list(frozen.values('pk', 'first_name', 'last_name', 'department_id'))
    if {row['pk'] for row in persisted} != set(ids):
        raise PermissionDenied('Profile targets changed. Retry the entire operation.')
    return frozen


def validate_entries(entries):
    keys = {'user_id', 'name', 'role', 'assigned', 'member'}
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValidationError('Invalid or oversized historical roster.')
    last = 0
    for row in entries:
        if (not isinstance(row, dict) or set(row) != keys or type(row['user_id']) is not int
                or row['user_id'] <= last or type(row['assigned']) is not bool
                or type(row['member']) is not bool or not (row['assigned'] or row['member'])
                or row['role'] not in (None, 'AP', 'O') or not isinstance(row['name'], str)
                or not row['name'] or len(row['name']) > 300):
            raise ValidationError('Invalid historical roster entry.')
        last = row['user_id']


def capture_roster(meeting, using='default'):
    from .models import Attendance, HistoricalRoster
    from .reading import participant_name
    assignments = set(Attendance.objects.using(using).filter(meeting=meeting).values_list('user_id', flat=True))
    memberships = dict(Membership.objects.using(using).filter(department_id=meeting.department_id).values_list('user_id','role'))
    users = User.objects.using(using).annotate(any_membership=Exists(Membership.objects.using(using).filter(user_id=OuterRef('pk'))))
    users = users.filter(Q(pk__in=assignments) | Q(is_active=True, pk__in=memberships) |
                         Q(is_active=True, department_id=meeting.department_id, any_membership=False)).order_by('pk')
    entries = []
    for user in users:
        role = memberships.get(user.pk)
        legacy = user.department_id == meeting.department_id and not user.any_membership
        member = user.is_active and (role is not None or legacy)
        entries.append(dict(user_id=user.pk, name=participant_name(user.first_name,user.last_name),
                            role=role or ('O' if legacy else None), assigned=user.pk in assignments, member=bool(member)))
    snapshot = HistoricalRoster(meeting=meeting, entries=entries)
    snapshot._capture_authorized = True
    snapshot.save(using=using)


def guard_assignment(attendance, using):
    from .models import Attendance, Meeting
    old = Attendance.objects.using(using).filter(pk=attendance.pk).values('meeting_id','user_id').first() if attendance.pk else None
    structural = old is None or old['meeting_id'] != attendance.meeting_id or old['user_id'] != attendance.user_id
    if structural:
        ids = {attendance.meeting_id} | ({old['meeting_id']} if old else set())
        for pk in sorted(ids):
            Meeting.objects.using(using).filter(pk=pk).update(status=F('status'))
        if Meeting.objects.using(using).filter(pk__in=ids).exclude(status='Draft').exists():
            raise PermissionDenied('Assignments are frozen after finalization.')


def roster_groups(meeting_id, status):
    from .models import HistoricalRoster, Attendance
    snapshot = HistoricalRoster.objects.filter(meeting_id=meeting_id).first()
    live = {row['user_id']: row for row in Attendance.objects.filter(meeting_id=meeting_id).values('user_id','status','has_signed')}
    if not snapshot:
        return None
    assigned, absent = [], []
    for entry in snapshot.entries:
        if entry['assigned']:
            row = live.get(entry['user_id'])
            attendance = row['status'] if row else 'Record unavailable'
            signing = ('Signed' if row and row['has_signed'] else
                       'Eligible by attendance; signing access required' if row and status == 'Finished' and attendance in ('Attended','Late') else 'Not eligible')
            assigned.append(dict(name=entry['name'], status=attendance, signing=signing))
        elif entry['member']:
            absent.append(dict(name=entry['name']))
    return assigned, absent
