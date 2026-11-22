from unittest.mock import patch
from django.test import TestCase
from django.db import transaction
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.db.models.deletion import ProtectedError
from accounts.models import User, Department, Membership
from accounts.test_fixtures import signature_storage, complete_onboarding
from .models import Meeting, Attendance, HistoricalRoster
from .reading import capture_read_document, officer_can_read, participant_name
from .pdf import capture_document, generate_meeting_pdf


class RosterTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.department = Department.objects.create(name='Historical department')
        self.member = User.objects.create_user(username='PRIVATE_USER', first_name='First', last_name='Member')
        self.absent = User.objects.create_user(username='absent', first_name='Absent', last_name='Member')
        for user in (self.member,self.absent):
            Membership.objects.create(user=user, department=self.department, role='O')
        self.meeting = Meeting.objects.create(department=self.department,title='Historical minutes',minutes_content='Final agenda')
        self.attendance = Attendance.objects.create(meeting=self.meeting,user=self.member)

    def finalize(self):
        self.meeting.status='Finished'
        self.meeting.save()
        return self.meeting.historical_roster

    def test_internal_participant_name_priority(self):
        for first, last, username, expected in (
            ('  First ', ' Last ', ' handle ', 'handle'),
            ('  First ', ' Last ', ' ', 'First Last'),
            ('', '', 'handle', 'handle'),
            ('First', '', 'handle', 'handle'),
            ('', 'Last', 'handle', 'handle'),
            ('  ', '', ' ', 'Name not provided'),
        ):
            with self.subTest(first=first, last=last, username=username):
                self.assertEqual(participant_name(first, last, username), expected)

    def test_existing_roster_placeholder_survives_profile_changes(self):
        complete_onboarding(self.member)
        with patch('meetings.reading.participant_name', return_value='Name not provided'):
            snapshot = self.finalize()
        User.objects.filter(pk=self.member.pk).update(username='new-handle')
        url = reverse('review_meeting', args=[self.meeting.pk])
        for reader, officer in ((self.member, True),
                                (User.objects.create_superuser(username='roster-admin'), False)):
            self.client.force_login(reader)
            response = self.client.get(url)
            self.assertContains(response, 'Name not provided')
            self.assertNotContains(response, '<span class="participant-name">new-handle</span>')
            document = capture_document(self.meeting.pk, officer_read_only=officer)
            self.assertEqual(document['attendees'][0]['name'], 'Name not provided')
        snapshot.refresh_from_db()
        self.assertEqual(snapshot.entries[0]['name'], 'Name not provided')

    def test_population_and_live_status_separation(self):
        inactive = User.objects.create_user(username='inactive',is_active=False)
        Membership.objects.create(user=inactive,department=self.department)
        legacy = User.objects.create_user(username='legacy',department=self.department)
        admin = User.objects.create_user(username='admin',is_admin=True)
        anomalous = User.objects.create_user(username='anomaly')
        Attendance.objects.create(meeting=self.meeting,user=anomalous)
        snapshot=self.finalize()
        rows={row['user_id']:row for row in snapshot.entries}
        self.assertNotIn(inactive.pk,rows)
        self.assertNotIn(admin.pk,rows)
        self.assertTrue(rows[legacy.pk]['member'])
        self.assertEqual(rows[legacy.pk]['role'],'O')
        self.assertFalse(rows[anomalous.pk]['member'])
        self.assertIsNone(rows[anomalous.pk]['role'])
        self.assertTrue(rows[self.member.pk]['assigned'])
        self.assertFalse(rows[self.absent.pk]['assigned'])
        original=snapshot.entries
        self.member.first_name='Changed'; self.member.save()
        Membership.objects.filter(user=self.absent).delete()
        Membership.objects.filter(user=self.member).update(role='AP')
        joined=User.objects.create_user(username='new')
        Membership.objects.create(user=joined,department=self.department)
        Attendance.objects.filter(pk=self.attendance.pk).update(status='Late',has_signed=True)
        result=capture_read_document(self.meeting.pk)
        self.assertEqual(result['attendees'][0]['name'],'PRIVATE_USER')
        self.assertEqual(result['attendees'][0]['status'],'Late')
        self.assertEqual(result['attendees'][0]['signing'],'Signed')
        self.assertIn({'name':'absent'},result['absent'])
        self.meeting.status='Archived';self.meeting.save()
        snapshot.refresh_from_db(); self.assertEqual(snapshot.entries,original)
        self.assertEqual(HistoricalRoster.objects.count(),1)

    def test_rollback_empty_direct_creation_and_repeated_capture(self):
        with patch('meetings.roster.capture_roster',side_effect=RuntimeError('capture failure')):
            with self.assertRaises(RuntimeError):self.finalize()
        self.meeting.refresh_from_db(); self.assertEqual(self.meeting.status,'Draft')
        self.assertFalse(HistoricalRoster.objects.exists())
        snapshot=self.finalize();self.meeting.save();self.assertEqual(HistoricalRoster.objects.count(),1)
        other=Department.objects.create(name='Empty')
        direct=Meeting.objects.create(department=other,title='Direct',status='Archived')
        self.assertEqual(direct.historical_roster.entries,[])
        with self.assertRaises(ValidationError):Meeting.objects.filter(pk=self.meeting.pk).update(status='Draft')
        with self.assertRaises(ValidationError):Meeting.objects.bulk_create([Meeting(department=other,title='Invalid',status='Finished')])

    def test_immutable_and_assignment_guards_with_user_deletion(self):
        snapshot=self.finalize()
        for operation in (lambda:snapshot.save(),lambda:HistoricalRoster.objects.update(entries=[]),lambda:snapshot.delete(),lambda:self.meeting.delete()):
            with self.assertRaises((PermissionDenied,ProtectedError)):
                with transaction.atomic():operation()
        with self.assertRaises(PermissionDenied):Attendance.objects.create(meeting=self.meeting,user=self.absent)
        with self.assertRaises(PermissionDenied), transaction.atomic():self.attendance.delete()
        with self.assertRaises(ValidationError):Attendance.objects.filter(pk=self.attendance.pk).update(user=self.absent)
        Attendance.objects.filter(pk=self.attendance.pk).update(status='Attended')
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.member.delete()
        self.assertEqual(capture_read_document(self.meeting.pk)['attendees'][0]['name'],'PRIVATE_USER')

    def test_browser_pdf_and_inactive_authorization(self):
        complete_onboarding(self.member)
        self.finalize()
        self.client.force_login(self.member)
        response=self.client.get(reverse('review_meeting',args=[self.meeting.pk]))
        for value in ('PRIVATE_USER','absent','Absent','Not eligible'):
            self.assertContains(response,value)
        self.assertNotContains(response,'First Member')
        self.member.is_active=False
        self.assertFalse(officer_can_read(self.member,self.meeting))
        for officer in (True,False):
            document=capture_document(self.meeting.pk,officer_read_only=officer)
            self.assertEqual(document['attendees'][0]['name'],'PRIVATE_USER')
            self.assertEqual(document['absent'],[{'name':'absent'}])
            self.assertTrue(generate_meeting_pdf(document).startswith(b'%PDF-'))

    def test_admin_structural_change_and_legacy_fallback(self):
        from django.contrib.admin.sites import AdminSite
        from django.test import RequestFactory
        from .admin import AttendanceAdmin
        from django.db import connection
        self.finalize()
        request=RequestFactory().post('/')
        request.user=User.objects.create_superuser(username='root')
        admin=AttendanceAdmin(Attendance,AdminSite())
        with self.assertRaises(PermissionDenied), transaction.atomic():
            admin.save_model(request,Attendance(meeting=self.meeting,user=self.absent),None,False)
        # Simulate a pre-migration finalized row; production APIs cannot remove this evidence.
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM meetings_historicalroster WHERE meeting_id = %s',[self.meeting.pk])
        result=capture_read_document(self.meeting.pk)
        self.assertFalse(result['historical_roster_available'])
        self.assertEqual(result['attendees'][0]['name'], self.member.username)
        self.assertEqual(result['absent'],[])
        self.assertFalse(HistoricalRoster.objects.exists())
        from django.template.loader import render_to_string
        for officer in (True, False):
            document = capture_document(self.meeting.pk, officer_read_only=officer)
            html = render_to_string('pdf/final_minutes.html', {'document': document})
            self.assertIn('Historical department roster unavailable for this legacy meeting.', html)
            self.assertNotIn('Unassigned Department Members', html)
            self.assertEqual(document['attendees'][0]['name'], self.member.username)

    def test_pdf_extracted_historical_absent_after_membership_and_name_changes(self):
        import shutil, subprocess
        from tempfile import TemporaryDirectory
        from pathlib import Path
        attended = User.objects.create_user(username='present', first_name='Present', last_name='Member')
        Membership.objects.create(user=attended, department=self.department, role='O')
        Attendance.objects.create(meeting=self.meeting, user=attended, status='Attended')
        self.finalize()
        self.absent.first_name='Changed';self.absent.save()
        Membership.objects.filter(user=self.absent).delete()
        self.absent.delete()
        extractor=shutil.which('pdftotext') or 'C:/Program Files/Git/ucrt64/bin/pdftotext.exe'
        for officer in (True,False):
            with TemporaryDirectory() as directory:
                pdf=Path(directory)/'roster.pdf';text=Path(directory)/'roster.txt'
                pdf.write_bytes(generate_meeting_pdf(capture_document(self.meeting.pk,officer_read_only=officer)))
                result=subprocess.run([extractor,'-layout','-enc','UTF-8',str(pdf),str(text)],capture_output=True,timeout=60)
                self.assertEqual(result.returncode,0)
                content=text.read_text(encoding='utf-8')
            self.assertIn('Department members who were not assigned to this meeting when it was finalized. This section is separate from recorded attendance status.', ' '.join(content.split()))
            self.assertIn('Unassigned Department Members', content)
            self.assertIn('Not attended', content)
            self.assertIn('Attended', content)
            if not officer:
                self.assertIn('Unsigned', content)
            self.assertIn('absent',content)
            self.assertIn('PRIVATE_USER',content)
            self.assertNotIn('Changed',content)
            self.assertNotIn('First Member',content)
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.status, 'Absent')

    def test_pdf_formats_manila_time_for_both_reader_variants(self):
        from datetime import datetime
        from django.template.loader import render_to_string
        from django.utils import timezone

        instant = datetime.fromisoformat('2026-11-16T00:57:23.468089+00:00')
        self.finalize()
        Meeting.objects.filter(pk=self.meeting.pk).update(created_at=instant)
        self.client.force_login(User.objects.create_superuser(username='timezone-admin'))
        self.assertContains(
            self.client.get(reverse('review_meeting', args=[self.meeting.pk])),
            '11/16/26, 8:57 AM PHT',
        )
        for officer in (True, False):
            document = capture_document(self.meeting.pk, officer_read_only=officer)
            self.assertEqual(document['created_at'], instant)
            document['updated_at'] = datetime.fromisoformat('2026-11-16T16:01:00+00:00')
            with timezone.override('UTC'):
                html = render_to_string('pdf/final_minutes.html', {'document': document})
            self.assertIn('11/16/26, 8:57 AM PHT', html)
            self.assertIn('11/17/26, 12:01 AM PHT', html)
            self.assertIn(f'content="{document["generated_at"].isoformat()}"', html)
            if not officer:
                self.assertIn('No signing timestamp', html)

    def test_signing_after_finalization_retains_roster(self):
        import time
        from .crypto import generate_hmac_qr_token
        complete_onboarding(self.member)
        snapshot=self.finalize()
        original=snapshot.entries
        self.attendance.status='Attended';self.attendance.save(update_fields=['status'])
        timestamp=str(int(time.time()))
        signature=generate_hmac_qr_token(self.meeting.pk,timestamp)
        self.client.force_login(self.member)
        response=self.client.post(reverse('sign_meeting',args=[self.meeting.pk]),{'t':timestamp,'sig':signature,'annotation':'Authorized note'})
        self.assertEqual(response.status_code,302)
        self.attendance.refresh_from_db();self.assertTrue(self.attendance.has_signed)
        snapshot.refresh_from_db();self.assertEqual(snapshot.entries,original)

    def test_http_finalization_audit_failure_rolls_back_snapshot(self):
        from .models import AuditLog
        ap=User.objects.create_user(username='finalizing-ap')
        Membership.objects.create(user=ap,department=self.department,role='AP')
        complete_onboarding(ap)
        self.client.force_login(ap)
        with patch.object(AuditLog.objects,'create',side_effect=RuntimeError('audit failure')):
            with self.assertRaises(RuntimeError):
                self.client.post(reverse('finalize_meeting',args=[self.meeting.pk]))
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.status,'Draft')
        self.assertFalse(HistoricalRoster.objects.exists())


from django.test import TransactionTestCase
class SQLiteRosterContentionTests(TransactionTestCase):
    def test_membership_assignment_and_profile_writers_cannot_cross_capture(self):
        from django.db import connection, connections, OperationalError
        from threading import Thread
        from .roster import lock_departments
        if connection.vendor != 'sqlite':
            self.skipTest('SQLite-specific write serialization')
        department=Department.objects.create(name='Concurrent')
        user=User.objects.create_user(username='concurrent',first_name='Original',last_name='Member')
        membership=Membership.objects.create(user=user,department=department)
        meeting=Meeting.objects.create(department=department,title='Concurrent capture')
        joining=User.objects.create_user(username='joining')
        operations=(lambda: Membership.objects.create(user=joining,department=department),
                    lambda: Membership.objects.filter(pk=membership.pk).delete(),
                    lambda: User.objects.filter(pk=user.pk).update(first_name='Changed'),
                    lambda: User.objects.filter(pk=user.pk).update(username='changed'),
                    lambda: user.save(update_fields=['username']),
                    lambda: Attendance.objects.create(meeting=meeting,user=user))
        user.username = 'changed'
        with transaction.atomic():
            lock_departments([department.pk])
            for operation in operations:
                errors=[]
                def worker():
                    try: operation()
                    except OperationalError: errors.append('contention')
                    finally: connections.close_all()
                thread=Thread(target=worker);thread.start();thread.join(10)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors,['contention'])
            meeting.status='Finished';meeting.save()
        entry=meeting.historical_roster.entries[0]
        self.assertEqual(entry['name'],'concurrent')
        self.assertFalse(entry['assigned'])
