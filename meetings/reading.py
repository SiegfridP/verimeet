"""Finalized, department-wide reading policy and minimal participant projection."""
from accounts.dashboard_context import department_allowed
from accounts.models import Membership
from .models import Meeting


def officer_can_read(user, meeting):
    return (user.is_authenticated and user.is_active and meeting.department.is_active
            and meeting.status in ('Finished', 'Archived')
            and department_allowed(user, meeting.department)
            and (Membership.objects.filter(user=user, department=meeting.department, role='O').exists()
                 or (user.department_id == meeting.department_id and not Membership.objects.filter(user=user).exists())))


def participant_name(first, last):
    first, last = ' '.join((first or '').split()), ' '.join((last or '').split())
    return f'{first} {last}' if first and last else 'Name not provided'


def capture_read_document(meeting_id):
    # Do not fetch signing evidence, identifiers, emails or username fallbacks.
    fields = ('id', 'title', 'department_id', 'department__name', 'status',
              'minutes_content', 'created_at', 'updated_at', 'attendees__id',
              'attendees__user__first_name', 'attendees__user__last_name')
    rows = list(Meeting.objects.filter(pk=meeting_id).values(*fields).order_by('attendees__id'))
    if not rows:
        raise Meeting.DoesNotExist
    first = rows[0]
    if first['status'] not in ('Finished', 'Archived'):
        raise ValueError('Only finalized documents can be read.')
    result = {key: first[key] for key in ('id', 'title', 'department_id', 'status',
              'minutes_content', 'created_at', 'updated_at')}
    result['department_name'] = first['department__name']
    result['attendees'] = [{'name': participant_name(row['attendees__user__first_name'],
                           row['attendees__user__last_name'])} for row in rows if row['attendees__id'] is not None]
    from .roster import roster_groups
    groups = roster_groups(meeting_id, first['status'])
    if groups is not None:
        result['attendees'], result['absent'] = groups
    else:
        from .models import Attendance
        live = list(Attendance.objects.filter(meeting_id=meeting_id).values('status','has_signed').order_by('id'))
        for entry, row in zip(result['attendees'], live):
            entry.update(status=row['status'], signing='Signed' if row['has_signed'] else
                         'Eligible by attendance; signing access required' if first['status'] == 'Finished' and row['status'] in ('Attended','Late') else 'Not eligible')
        result['absent'] = []
    result['historical_roster_available'] = groups is not None
    result['officer_read_only'] = True
    return result
