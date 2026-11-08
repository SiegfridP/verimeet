from accounts.test_fixtures import set_meeting_fixture_state
from tempfile import TemporaryDirectory
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.files.base import ContentFile
from accounts.models import User, Department, Membership
from accounts.account_status import change_account_status
from accounts.test_onboarding import png
from meetings.models import Meeting, Attendance, AuditLog
from meetings.forms import MeetingForm, AssignParticipantsForm
from . import tests as existing_tests


class ParticipantIntegrityTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory(); self.addCleanup(directory.cleanup)
        setting = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
        setting.enable(); self.addCleanup(setting.disable)
        self.dept = Department.objects.create(name='Assignments')
        self.other = Department.objects.create(name='Other')
        self.ap = User.objects.create_user(username='ap')
        self.ap.signature_image.save('signature.png', ContentFile(png()))
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')
        self.admin = User.objects.create_user(username='global', is_admin=True)
        self.officer = User.objects.create_user(username='officer')
        self.second = User.objects.create_user(username='second')
        for user in (self.officer, self.second):
            Membership.objects.create(user=user, department=self.dept)
        self.meeting = Meeting.objects.create(department=self.dept, title='Draft')
        self.attendance = Attendance.objects.create(meeting=self.meeting, user=self.officer)
        self.url = reverse('assign_participants', args=[self.meeting.pk])
        self.client.force_login(self.ap)

    def test_existing_inactive_is_visible_selected_and_preserved(self):
        change_account_status(self.admin, self.officer.pk, False)
        response = self.client.get(self.url)
        field = response.context['form'].fields['participants']
        self.assertTrue(field.queryset.filter(pk=self.officer.pk).exists())
        self.assertContains(response, 'Inactive')
        self.assertContains(response, 'checked')
        response = self.client.post(self.url, {'participants': [self.officer.pk, self.second.pk]})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())
        event = AuditLog.objects.get(event_type='meeting.participants_changed')
        self.assertEqual(event.metadata['added_ids'], [self.second.pk])
        self.assertEqual(event.metadata['removed_ids'], [])

    def test_authoritative_membership_suppresses_stale_legacy_pointer(self):
        stale = User.objects.create_user(username='stale', department=self.dept)
        Membership.objects.create(user=stale, department=self.other)
        for form in (MeetingForm({'title': 'New', 'participants': [stale.pk]}, department=self.dept),
                     AssignParticipantsForm({'participants': [stale.pk]}, department=self.dept, meeting=self.meeting)):
            self.assertFalse(form.is_valid())
            self.assertIn('participants', form.errors)

    def test_explicit_inactive_removal_and_noop_audits(self):
        change_account_status(self.admin, self.officer.pk, False)
        self.assertEqual(self.client.post(self.url, {'participants': [self.officer.pk]}).status_code, 302)
        self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())
        self.assertFalse(AuditLog.objects.filter(event_type='meeting.participants_changed').exists())
        self.assertEqual(self.client.post(self.url, {'participants': []}).status_code, 302)
        self.assertFalse(Attendance.objects.filter(pk=self.attendance.pk).exists())
        event = AuditLog.objects.get(event_type='meeting.participants_changed')
        self.assertEqual(event.metadata['removed_ids'], [self.officer.pk])
        self.assertEqual(event.user_id, self.ap.pk)

    def test_new_inactive_and_cross_department_posts_are_rejected(self):
        inactive = User.objects.create_user(username='inactive', is_active=False)
        Membership.objects.create(user=inactive, department=self.dept)
        outsider = User.objects.create_user(username='outsider')
        Membership.objects.create(user=outsider, department=self.other)
        for user in (inactive, outsider):
            response = self.client.post(self.url, {'participants': [self.officer.pk, user.pk]})
            self.assertEqual(response.status_code, 200)
            self.assertIn('participants', response.context['form'].errors)
            self.assertFalse(Attendance.objects.filter(meeting=self.meeting, user=user).exists())
            form = MeetingForm({'title': 'Creation', 'participants': [user.pk]}, department=self.dept)
            self.assertFalse(form.is_valid())
        self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())

    def test_membership_and_legacy_rules_match_both_forms(self):
        legacy = User.objects.create_user(username='legacy', department=self.dept)
        for user in (legacy, self.second):
            creation = MeetingForm({'title': 'New', 'participants': [user.pk]}, department=self.dept)
            assignment = AssignParticipantsForm({'participants': [user.pk]}, department=self.dept, meeting=self.meeting)
            self.assertTrue(creation.is_valid(), creation.errors)
            self.assertTrue(assignment.is_valid(), assignment.errors)
        Membership.objects.create(user=legacy, department=self.other)
        self.assertFalse(MeetingForm({'title': 'New', 'participants': [legacy.pk]}, department=self.dept).is_valid())
        self.assertFalse(AssignParticipantsForm({'participants': [legacy.pk]}, department=self.dept, meeting=self.meeting).is_valid())

    def test_inactive_department_and_locked_lifecycle(self):
        for status in ('Finished', 'Archived'):
            # Fixture-only lifecycle transition; no signed records are changed.
            set_meeting_fixture_state(Meeting.objects.filter(pk=self.meeting.pk), status=status)
            self.assertEqual(self.client.post(self.url, {'participants': []}).status_code, 403)
            self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())
        self.meeting = Meeting.objects.create(department=self.dept, title='Inactive draft')
        self.url = reverse('assign_participants', args=[self.meeting.pk])
        Department.objects.filter(pk=self.dept.pk).update(is_active=False)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, {'participants': []}).status_code, 403)
        self.assertFalse(MeetingForm({'title': 'New', 'participants': [self.second.pk]}, department=self.dept).is_valid())
        self.assertFalse(AssignParticipantsForm({'participants': []}, department=self.dept, meeting=self.meeting).is_valid())

    def test_signed_inactive_attendance_remains_protected(self):
        self.attendance.has_signed = True
        self.attendance.cryptographic_signature = 'historical evidence'
        self.attendance.save()
        change_account_status(self.admin, self.officer.pk, False)
        self.assertEqual(self.client.post(self.url, {'participants': [self.second.pk]}).status_code, 302)
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.cryptographic_signature, 'historical evidence')
        self.assertTrue(self.attendance.has_signed)
        self.assertEqual(AuditLog.objects.get(event_type='meeting.participants_changed').metadata['removed_ids'], [])

    def test_officer_and_other_department_ap_denied(self):
        foreign_ap = User.objects.create_user(username='foreign-ap')
        Membership.objects.create(user=foreign_ap, department=self.other, role='AP')
        for user in (self.officer, foreign_ap):
            user.signature_image.save('signature.png', ContentFile(png()))
            self.client.force_login(user)
            self.assertEqual(self.client.post(self.url, {'participants': []}).status_code, 403)
        self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())

    def test_global_admin_and_initial_creation_choices(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(self.url, {'participants': [self.officer.pk, self.second.pk]}).status_code, 302)
        self.assertEqual(set(Attendance.objects.filter(meeting=self.meeting).values_list('user_id', flat=True)),
                         {self.officer.pk, self.second.pk})


class ExistingAssignmentCompatibility(existing_tests.MeetingCreationAndAssignmentTests):
    pass


class ExistingAssignmentAuditCompatibility(TestCase):
    # Only the assignment-specific contract from the broader audit test class.
    def setUp(self):
        existing_tests.Batch09StructuredAuditTests.setUp(self)

    test_assignment_deltas_and_noop = existing_tests.Batch09StructuredAuditTests.test_assignment_deltas_and_noop
