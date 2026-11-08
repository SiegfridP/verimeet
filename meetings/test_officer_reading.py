from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import shutil
import subprocess
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from accounts.models import User, Department, Membership
from accounts.test_fixtures import signature_storage, complete_onboarding
from .models import Meeting, Attendance, AuditLog, QRSession
from .pdf import capture_document, generate_meeting_pdf


class OfficerReadingTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.dept = Department.objects.create(name='Reading department')
        self.other = Department.objects.create(name='Other department')
        self.admin = User.objects.create_user(username='reading-admin', is_admin=True)
        self.ap = User.objects.create_user(username='reading-ap')
        self.assigned = User.objects.create_user(username='PRIVATE_USERNAME', email='private@example.test', first_name='  Alice ', last_name=' Reader ')
        self.unassigned = User.objects.create_user(username='unassigned-reader')
        self.outside = User.objects.create_user(username='outside-reader')
        self.none = User.objects.create_user(username='no-membership')
        complete_onboarding(self.ap, self.assigned, self.unassigned, self.outside, self.none)
        for user, department, role in ((self.ap,self.dept,'AP'), (self.assigned,self.dept,'O'),
                                       (self.unassigned,self.dept,'O'),(self.outside,self.other,'O')):
            Membership.objects.create(user=user, department=department, role=role)
        self.meeting = Meeting.objects.create(department=self.dept, title='Approved document',
            minutes_content='Agenda item one\nFull finalized minutes', status='Draft')
        self.att = Attendance.objects.create(meeting=self.meeting,user=self.assigned,status='Late',
            has_signed=True, signed_at=timezone.now(), annotation='PRIVATE_ANNOTATION', cryptographic_signature='PRIVATE_CRYPTO')
        self.unnamed = User.objects.create_user(username='PRIVATE_FALLBACK')
        Attendance.objects.create(meeting=self.meeting,user=self.unnamed)
        self.meeting.status='Finished'
        self.meeting.save()

    def url(self, name):
        return reverse(name,args=[self.meeting.pk])

    def test_review_and_pdf_role_lifecycle_matrix(self):
        for status in ('Draft','Finished','Archived'):
            # Test-only lifecycle matrix setup bypasses production transition guards.
            from django.db.models.query import QuerySet
            QuerySet.update(Meeting.objects.filter(pk=self.meeting.pk), status=status)
            for user in (self.admin,self.ap,self.assigned,self.unassigned,self.outside,self.none):
                self.client.force_login(user)
                manager = user in (self.admin,self.ap)
                reader = user in (self.assigned,self.unassigned)
                for route in ('review_meeting','export_meeting_pdf'):
                    expected = 200 if ((manager and (route=='review_meeting' or status!='Draft')) or (reader and status!='Draft')) else 403
                    with self.subTest(status=status,user=user.username,route=route), patch('meetings.pdf.generate_meeting_pdf',return_value=b'%PDF-test'):
                        self.assertEqual(self.client.get(self.url(route)).status_code,expected)
        self.client.logout()
        for route in ('review_meeting','export_meeting_pdf'):
            self.assertEqual(self.client.get(self.url(route)).status_code,302)

    def test_inactive_and_legacy_policy(self):
        self.client.force_login(self.unassigned)
        Department.objects.filter(pk=self.dept.pk).update(is_active=False)
        for route in ('review_meeting','export_meeting_pdf'):
            self.assertEqual(self.client.get(self.url(route)).status_code,403)
        Department.objects.filter(pk=self.dept.pk).update(is_active=True)
        User.objects.filter(pk=self.none.pk).update(department=self.dept)
        self.client.force_login(User.objects.get(pk=self.none.pk))
        self.assertEqual(self.client.get(self.url('review_meeting')).status_code,200)
        Membership.objects.create(user=self.none,department=self.other,role='O')
        self.assertEqual(self.client.get(self.url('review_meeting')).status_code,403)

    def test_review_privacy_and_no_mutation(self):
        self.client.force_login(self.unassigned)
        before=(list(Meeting.objects.values()),list(Attendance.objects.values()),AuditLog.objects.count(),QRSession.objects.count())
        response=self.client.get(self.url('review_meeting'))
        for value in ('Approved document','Agenda item one','Full finalized minutes','Alice Reader','Name not provided','Export PDF'):
            self.assertContains(response,value)
        for value in ('PRIVATE_',self.assigned.email,'Manage Attendance','Document History','Pending Signature','btn-finalize-meeting','Generate Signing QR'):
            self.assertNotContains(response,value)
        self.assertEqual([row['name'] for row in response.context['attendees']],['Alice Reader','Name not provided'])
        self.assertIsInstance(response.context['meeting'],dict)
        with patch('meetings.pdf.generate_meeting_pdf',return_value=b'%PDF-test'):
            response=self.client.get(self.url('export_meeting_pdf'))
        self.assertEqual(response['Cache-Control'],'private, no-store, max-age=0')
        self.assertEqual(before,(list(Meeting.objects.values()),list(Attendance.objects.values()),AuditLog.objects.count(),QRSession.objects.count()))

    def test_dashboard_read_links_and_personal_actions(self):
        draft=Meeting.objects.create(department=self.dept,title='Draft hidden content')
        archived=Meeting.objects.create(department=self.dept,title='Archived document',status='Archived')
        for user in (self.assigned,self.unassigned):
            self.client.force_login(user)
            response=self.client.get(reverse('department_dashboard',args=[self.dept.pk]),{'q':'document','status':'Finished'})
            self.assertContains(response,'Read Minutes',count=1)
            self.assertContains(response,'dashboard_context=')
            response=self.client.get(reverse('department_dashboard',args=[self.dept.pk]))
            self.assertContains(response,'Read Minutes',count=2)
            self.assertNotContains(response,reverse('review_meeting',args=[draft.pk]))
            self.assertContains(response,reverse('review_meeting',args=[archived.pk]))
            if user==self.assigned:
                self.assertContains(response,'My attendance details')
                self.assertContains(response,'My Signature QR')
            else:
                self.assertNotContains(response,'My attendance details')
                self.assertNotContains(response,'My Signature QR')

    def test_actual_officer_pdf_text_privacy_and_manager_evidence(self):
        extractor=shutil.which('pdftotext') or 'C:/Program Files/Git/ucrt64/bin/pdftotext.exe'
        self.assertTrue(Path(extractor).exists())
        for officer in (True,False):
            document=capture_document(self.meeting.pk,officer_read_only=officer)
            if officer:
                self.assertEqual([row['name'] for row in document['attendees']],['Alice Reader','Name not provided'])
                self.assertEqual(document['resources'],{})
            pdf=generate_meeting_pdf(document)
            with TemporaryDirectory() as directory:
                source=Path(directory)/'minutes.pdf'; target=Path(directory)/'minutes.txt'
                source.write_bytes(pdf)
                result=subprocess.run([extractor,'-layout','-enc','UTF-8',str(source),str(target)],capture_output=True,timeout=60)
                self.assertEqual(result.returncode,0)
                text=target.read_text(encoding='utf-8')
            for value in ('Approved document','Agenda item one','Full finalized minutes'):
                self.assertIn(value,text)
            if officer:
                for value in ('Alice Reader','Name not provided'): self.assertIn(value,text)
                for value in ('PRIVATE_',self.assigned.email,'Unsigned','Invalid signature','Attendance and signatures','Annotation','signing timestamp'):
                    self.assertNotIn(value,text)
            else:
                for value in ('Attendance and signatures','Late','Invalid signature','PRIVATE_ANNOTATION'):
                    self.assertIn(value,text)

    def test_mutation_and_history_guards_stay_closed(self):
        self.client.force_login(self.unassigned)
        for route in ('edit_meeting','assign_participants','meeting_attendance','document_history'):
            self.assertEqual(self.client.get(self.url(route)).status_code,403)
        for route in ('finalize_meeting','generate_attendance_qr','generate_signing_qr'):
            self.assertEqual(self.client.post(self.url(route)).status_code,403)
        self.assertEqual(self.client.post(reverse('revoke_qr_session',args=[self.meeting.pk,999])).status_code,403)
        self.assertEqual(self.client.post(reverse('update_attendance_status',args=[self.meeting.pk,self.att.pk]),{'status':'Attended'}).status_code,403)
