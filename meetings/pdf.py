"""On-demand finalized document rendering. No stored artifacts or signing mutations."""
from django.template.loader import render_to_string
from django.utils import timezone
from .crypto import verify_attendance_signature
from .models import Meeting

TEMPLATE_VERSION = '1'


def capture_document(meeting_id):
    # One joined SELECT: avoid separate lazy queries mixing document/signature states.
    rows = list(Meeting.objects.filter(pk=meeting_id).values(
        'id', 'title', 'department_id', 'department__name', 'status',
        'minutes_content', 'created_at', 'updated_at',
        'attendees__id', 'attendees__user_id', 'attendees__user__first_name',
        'attendees__user__last_name', 'attendees__user__public_key',
        'attendees__status', 'attendees__has_signed', 'attendees__signed_at',
        'attendees__annotation', 'attendees__cryptographic_signature',
    ).order_by('attendees__id'))
    if not rows:
        raise Meeting.DoesNotExist
    first = rows[0]
    if first['status'] not in ('Finished', 'Archived'):
        raise ValueError('Only finalized documents can be exported.')
    document = {key: first[key] for key in (
        'id', 'title', 'department_id', 'status', 'minutes_content', 'created_at', 'updated_at')}
    document.update(department_name=first['department__name'], attendees=[], generated_at=timezone.now())
    for row in rows:
        if row['attendees__id'] is None:
            continue
        signed = row['attendees__has_signed']
        label = 'Unsigned'
        if signed:
            result = verify_attendance_signature(
                public_key_pem=row['attendees__user__public_key'],
                meeting_id=first['id'], department_id=first['department_id'],
                title=first['title'], minutes_content=first['minutes_content'],
                annotation=row['attendees__annotation'] or '',
                signature_hex=row['attendees__cryptographic_signature'],
            )
            label = ('Valid canonical ECDSA signature' if result['format'] == 'canonical'
                     else 'Valid legacy ECDSA signature' if result['format'] == 'legacy'
                     else 'Invalid signature') if result['valid'] else 'Invalid signature'
        name = ' '.join(filter(None, [row['attendees__user__first_name'], row['attendees__user__last_name']]))
        document['attendees'].append({
            'name': name or f"Officer #{row['attendees__user_id']}",
            'status': row['attendees__status'], 'verification': label,
            'signed_at': row['attendees__signed_at'],
            'annotation': row['attendees__annotation'] or '',
        })
    return document


def deny_resource(url, *args, **kwargs):
    # This self-contained template requires no external assets, including data URLs.
    raise ValueError('External PDF resources are disabled.')


def generate_meeting_pdf(document):
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        raise RuntimeError('WeasyPrint and its native libraries are required.') from exc
    html = render_to_string('pdf/final_minutes.html', {'document': document})
    return HTML(string=html, url_fetcher=deny_resource).write_pdf()
