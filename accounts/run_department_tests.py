"""Run focused checks against forced in-memory SQLite, never DATABASE_URL."""
import os
from base64 import urlsafe_b64encode
os.environ.update(DJANGO_ENV='development', DATABASE_URL='', DJANGO_SECRET_KEY='local-tests-only', DJANGO_DEBUG='False', EVIDENCE_BACKEND='database')
os.environ['SIGNING_KEY_ENCRYPTION_KEY'] = urlsafe_b64encode(b'0' * 32).decode()
os.environ.update(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    EMAIL_HOST='localhost', EMAIL_HOST_USER='', EMAIL_HOST_PASSWORD='', RESEND_API_KEY='',
    APPLICATION_ORIGIN='', EVIDENCE_ENDPOINT='', EVIDENCE_BUCKET='',
    EVIDENCE_ACCESS_KEY_ID='', EVIDENCE_SECRET_ACCESS_KEY='')
os.environ['DJANGO_SETTINGS_MODULE']='core.settings'
from django.conf import settings
settings.DATABASES={alias:{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}
                    for alias in ('default', 'deletion_test') }
settings.EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'
settings.MAILERS={'default':{'BACKEND':'django.core.mail.backends.locmem.EmailBackend'}}
settings.DURABLE_EVIDENCE=False
settings.ALLOWED_HOSTS=['testserver','localhost']
# Fail closed if a focused test unexpectedly attempts Python socket networking.
from unittest.mock import patch
patch('socket.socket.connect', side_effect=RuntimeError('Network disabled in deletion tests')).start()
patch('socket.create_connection', side_effect=RuntimeError('Network disabled in deletion tests')).start()
import django
django.setup()
from django.test.utils import get_runner
import sys
if len(sys.argv)>1 and sys.argv[1]=='check':
    from django.core.management import call_command
    call_command('check')
else:
    allowed = ('accounts.test_department_deletion', 'accounts.test_batch14',
        'meetings.test_attendance_integrity', 'meetings.test_roster_integrity',
        'meetings.test_visual_evidence', 'meetings.tests.Batch09StructuredAuditTests',
        'meetings.tests.Batch09MeetingAdminAuditTests', 'meetings.tests.Batch09AuditCorrectionAdminTests')
    if any(label not in allowed for label in sys.argv[1:]):
        raise SystemExit('Only the focused deletion regression labels are supported.')
    raise SystemExit(get_runner(settings)(verbosity=1).run_tests(sys.argv[1:] or ['accounts.test_department_deletion','meetings.test_attendance_integrity']))
