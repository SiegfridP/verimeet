"""On-demand finalized document rendering. No stored artifacts or signing mutations."""
from django.template.loader import render_to_string
from django.utils import timezone
from .crypto import verify_attendance_signature
from .models import Meeting

TEMPLATE_VERSION = '2'
MAX_IMAGE_PIXELS = 12_000_000


def metadata_text(value):
    return ''.join(c for c in value if c.isprintable())[:200]


def capture_document(meeting_id, *, officer_read_only=False):
    if officer_read_only:
        from .reading import capture_read_document
        document = capture_read_document(meeting_id)
        document.update(metadata_title=metadata_text(document['title']), generated_at=timezone.now(), resources={})
        return document
    # One joined SELECT: avoid separate lazy queries mixing document/signature states.
    rows = list(Meeting.objects.filter(pk=meeting_id).values(
        'id', 'title', 'department_id', 'department__name', 'status',
        'minutes_content', 'created_at', 'updated_at',
        'attendees__id', 'attendees__user_id', 'attendees__user__first_name',
        'attendees__user__last_name', 'attendees__user__public_key',
        'attendees__status', 'attendees__has_signed', 'attendees__signed_at',
        'attendees__annotation', 'attendees__cryptographic_signature',
        'attendees__visual_snapshot__storage_identifier', 'attendees__visual_snapshot__content_sha256',
        'attendees__visual_snapshot__byte_length', 'attendees__visual_snapshot__width',
        'attendees__visual_snapshot__height', 'attendees__visual_snapshot__signer_name',
    ).order_by('attendees__id'))
    if not rows:
        raise Meeting.DoesNotExist
    first = rows[0]
    if first['status'] not in ('Finished', 'Archived'):
        raise ValueError('Only finalized documents can be exported.')
    document = {key: first[key] for key in (
        'id', 'title', 'department_id', 'status', 'minutes_content', 'created_at', 'updated_at')}
    document.update(department_name=first['department__name'], attendees=[], generated_at=timezone.now())
    document['metadata_title'] = metadata_text(first['title'])
    resources = document['resources'] = {}
    total_bytes = 0
    total_pixels = 0
    for index, row in enumerate(rows):
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
        name = row['attendees__visual_snapshot__signer_name'] if signed else ' '.join(filter(None, [row['attendees__user__first_name'], row['attendees__user__last_name']]))
        image_url = None
        width = row['attendees__visual_snapshot__width'] or 0
        height = row['attendees__visual_snapshot__height'] or 0
        pixels = width * height
        if signed and index < 100 and total_pixels + pixels <= MAX_IMAGE_PIXELS:
            from .visual_evidence import read_snapshot
            prefix = 'attendees__visual_snapshot__'
            data = read_snapshot(*(row[prefix + field] for field in (
                'storage_identifier', 'content_sha256', 'byte_length', 'width', 'height')))
            if data and total_bytes + len(data) <= 16 * 1024 * 1024:
                from uuid import uuid4
                image_url = 'evidence:' + uuid4().hex
                resources[image_url] = data
                total_bytes += len(data)
                total_pixels += pixels
        document['attendees'].append({
            'name': name or 'Name unavailable',
            'image_url': image_url, 'signed': signed,
            'status': row['attendees__status'], 'verification': label,
            'signed_at': row['attendees__signed_at'],
            'annotation': row['attendees__annotation'] or '',
        })
    from .roster import roster_groups
    from .models import HistoricalRoster
    snapshot = HistoricalRoster.objects.filter(meeting_id=meeting_id).first()
    document['historical_roster_available'] = snapshot is not None
    document['absent'] = []
    if snapshot:
        current = {row['attendees__user_id']: attendee for row, attendee in zip(
            [row for row in rows if row['attendees__id'] is not None], document['attendees'])}
        document['attendees'] = []
        for entry in snapshot.entries:
            if entry['assigned']:
                attendee = current.get(entry['user_id'], dict(status='Record unavailable', verification='Unavailable', signed=False, signed_at=None, annotation='', image_url=None))
                document['attendees'].append(dict(attendee, name=entry['name']))
            elif entry['member']:
                document['absent'].append({'name': entry['name']})
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
    resources = document.get('resources', {})
    from weasyprint.urls import URLFetcher, URLFetcherResponse
    class EvidenceFetcher(URLFetcher):
        def fetch(self, url, headers=None):
            if url in resources:
                return URLFetcherResponse(url, body=resources[url], headers={'Content-Type': 'image/png'})
            return deny_resource(url)
    return HTML(string=html, url_fetcher=EvidenceFetcher(
        allowed_protocols=[], fail_on_errors=True)).write_pdf()
