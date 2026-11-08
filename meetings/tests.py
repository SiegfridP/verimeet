import time
from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import Department, User, Membership
from meetings.models import Meeting, Attendance, AuditLog, QRSession, QRUsage
from meetings.crypto import generate_hmac_qr_token
from accounts.test_fixtures import signature_storage, complete_onboarding

class MeetingRoutingAndSecurityTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.client = Client()
        self.dept = Department.objects.create(name='Engineering', contact_email='eng@example.com')
        # Authorized Personnel for Engineering
        self.ap_user = User.objects.create_user(
            username='ap_eng',
            password='password123'
        )
        Membership.objects.create(user=self.ap_user, department=self.dept, role='AP')

        # Global Admin (application-wide authority, not local AP)
        self.global_admin = User.objects.create_user(
            username='global_admin',
            password='password123',
            is_admin=True
        )

        # Assigned Officer in Engineering
        self.officer_user = User.objects.create_user(
            username='officer_eng',
            password='password123'
        )
        Membership.objects.create(user=self.officer_user, department=self.dept, role='O')

        # Unassigned Officer in Engineering
        self.unassigned_officer = User.objects.create_user(
            username='unassigned_eng',
            password='password123'
        )
        Membership.objects.create(user=self.unassigned_officer, department=self.dept, role='O')

        # User in another department
        self.other_dept = Department.objects.create(name='Arts', contact_email='arts@example.com')
        self.other_user = User.objects.create_user(
            username='officer_art',
            password='password123'
        )
        Membership.objects.create(user=self.other_user, department=self.other_dept, role='O')
        complete_onboarding(self.ap_user, self.officer_user, self.unassigned_officer, self.other_user)

        self.draft_meeting = Meeting.objects.create(
            department=self.dept,
            title='Draft Meeting',
            minutes_content='Draft notes',
            status='Draft'
        )
        self.finished_meeting = Meeting.objects.create(
            department=self.dept,
            title='Finished Meeting',
            minutes_content='Final notes',
            status='Finished'
        )

        # Pre-assign self.officer_user as eligible signer for finished_meeting
        self.attendance = Attendance.objects.create(
            meeting=self.finished_meeting,
            user=self.officer_user,
            has_signed=False,
            status='Attended',
        )

    def test_admin_dashboard_restrictions(self):
        """Global Admin dashboard permits Global Admins; denies AP and Officers."""
        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_unauth.status_code, 302)
        self.assertTrue(r_unauth.headers['Location'].startswith('/accounts/auth/login/'))

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer_user)
        r_officer = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_officer.status_code, 403)

        # Authorized Personnel -> 403 Forbidden (AP does NOT receive Global Admin authority)
        self.client.force_login(self.ap_user)
        r_ap = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_ap.status_code, 403)

        # Global Admin -> renders successfully
        self.client.force_login(self.global_admin)
        r_admin = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_admin.status_code, 200)

    def test_dashboard_compatibility_redirects(self):
        """Dashboard URLs redirect Officers to the canonical department dashboard."""
        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(reverse('student_dashboard'))
        self.assertEqual(r_unauth.status_code, 302)
        self.assertTrue(r_unauth.headers['Location'].startswith('/accounts/auth/login/'))

        r_unauth_officer = self.client.get(reverse('officer_dashboard'))
        self.assertEqual(r_unauth_officer.status_code, 302)
        self.assertTrue(r_unauth_officer.headers['Location'].startswith('/accounts/auth/login/'))

        # Officer visiting legacy dashboard -> redirects to department_dashboard and renders real Officer UI
        self.client.force_login(self.officer_user)
        r_officer_legacy = self.client.get(reverse('student_dashboard'))
        self.assertRedirects(r_officer_legacy, reverse('department_dashboard', args=[self.dept.id]))

        # Officer visiting officer_dashboard -> redirects to department_dashboard and renders member_dashboard.html
        r_officer = self.client.get(reverse('officer_dashboard'))
        self.assertRedirects(r_officer, reverse('department_dashboard', args=[self.dept.id]))

        # Following redirect renders canonical accounts/member_dashboard.html with Officer Dashboard heading
        r_followed = self.client.get(reverse('officer_dashboard'), follow=True)
        self.assertEqual(r_followed.status_code, 200)
        self.assertTemplateUsed(r_followed, 'accounts/member_dashboard.html')
        self.assertContains(r_followed, 'Officer Dashboard')

        # Officer attempting cross-department access via query param is forbidden
        r_forbidden = self.client.get(f"{reverse('officer_dashboard')}?dept_id={self.other_dept.id}")
        self.assertEqual(r_forbidden.status_code, 403)

        # AP visiting legacy AP dashboard -> redirects to department_dashboard
        self.client.force_login(self.ap_user)
        r_ap = self.client.get(reverse('authorized_personnel_dashboard'))
        self.assertRedirects(r_ap, reverse('department_dashboard', args=[self.dept.id]))

    def test_projector_qr_view_authorization(self):
        """Projector QR requires AP or Global Admin and Finished meeting status."""
        url_finished = reverse('projector_qr_view', args=[self.finished_meeting.id])
        url_draft = reverse('projector_qr_view', args=[self.draft_meeting.id])

        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(url_finished)
        self.assertEqual(r_unauth.status_code, 302)

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer_user)
        r_officer = self.client.get(url_finished)
        self.assertEqual(r_officer.status_code, 403)

        # AP with Draft meeting -> 403 Forbidden
        self.client.force_login(self.ap_user)
        r_draft = self.client.get(url_draft)
        self.assertEqual(r_draft.status_code, 403)

        # AP with Finished meeting -> 200 OK
        r_ok = self.client.get(url_finished)
        self.assertEqual(r_ok.status_code, 200)

        # Global Admin with Finished meeting -> 200 OK
        self.client.force_login(self.global_admin)
        r_admin_ok = self.client.get(url_finished)
        self.assertEqual(r_admin_ok.status_code, 200)

    def test_lock_meeting_authorization_and_redirect(self):
        """Lock meeting requires AP, rejects GET (405), and finalizes on POST redirecting to department dashboard."""
        url_lock = reverse('lock_meeting', args=[self.draft_meeting.id])

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer_user)
        r_forbidden = self.client.post(url_lock)
        self.assertEqual(r_forbidden.status_code, 403)

        # AP GET -> 405 Method Not Allowed (GET never locks/finalizes)
        self.client.force_login(self.ap_user)
        r_get = self.client.get(url_lock)
        self.assertEqual(r_get.status_code, 405)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # AP POST -> locks meeting and redirects to department_dashboard
        r_lock = self.client.post(url_lock)
        self.assertRedirects(r_lock, reverse('department_dashboard', args=[self.dept.id]))

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Finished')

    def test_sign_meeting_missing_tokens(self):
        """Missing security tokens should return 403 controlled error."""
        self.client.force_login(self.officer_user)
        base_url = reverse('sign_meeting', args=[self.finished_meeting.id])

        # No params
        r1 = self.client.get(base_url)
        self.assertEqual(r1.status_code, 403)

        # Only timestamp
        r2 = self.client.get(f"{base_url}?t={int(time.time())}")
        self.assertEqual(r2.status_code, 403)

        # Only sig
        r3 = self.client.get(f"{base_url}?sig=invalid_signature")
        self.assertEqual(r3.status_code, 403)

    def test_sign_meeting_malformed_tokens(self):
        """Malformed security tokens must return 403 instead of an unhandled 500 error."""
        self.client.force_login(self.officer_user)
        base_url = reverse('sign_meeting', args=[self.finished_meeting.id])

        r = self.client.get(f"{base_url}?t=not_a_number&sig=abcdef123456")
        self.assertEqual(r.status_code, 403)

    def test_sign_meeting_expired_and_future_tokens(self):
        """Expired and future tokens should return 403."""
        self.client.force_login(self.officer_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])

        # Expired token (> 3600 seconds ago)
        expired_ts = str(int(time.time()) - 4000)
        expired_sig = generate_hmac_qr_token(meeting_id, expired_ts)
        r_expired = self.client.get(f"{base_url}?t={expired_ts}&sig={expired_sig}")
        self.assertEqual(r_expired.status_code, 403)

        # Future token (< 0 seconds ago)
        future_ts = str(int(time.time()) + 1000)
        future_sig = generate_hmac_qr_token(meeting_id, future_ts)
        r_future = self.client.get(f"{base_url}?t={future_ts}&sig={future_sig}")
        self.assertEqual(r_future.status_code, 403)

    def test_sign_meeting_invalid_signature(self):
        """Mismatched HMAC signature should return 403."""
        self.client.force_login(self.officer_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        r = self.client.get(f"{base_url}?t={ts}&sig=bad_signature_hex")
        self.assertEqual(r.status_code, 403)

    def test_sign_meeting_assigned_eligible_officer_succeeds(self):
        """Assigned Officer with valid QR token can access signing page and submit signature."""
        self.client.force_login(self.officer_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)
        # Access page
        r_get = self.client.get(f"{base_url}?t={ts}&sig={sig}")
        self.assertEqual(r_get.status_code, 200)

        # Submit signature with annotation
        r_post = self.client.post(
            f"{base_url}?t={ts}&sig={sig}",
            data={'annotation': 'Reviewed and confirmed.'}
        )
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))

        self.attendance.refresh_from_db()
        self.assertTrue(self.attendance.has_signed)
        self.assertEqual(self.attendance.annotation, 'Reviewed and confirmed.')
        self.assertIsNotNone(self.attendance.cryptographic_signature)

    def test_sign_meeting_unassigned_officer_denied(self):
        """Unassigned department member cannot self-create attendance or sign."""
        self.client.force_login(self.unassigned_officer)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)

        # Attempt to access signing page
        r = self.client.get(f"{base_url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'You are not an assigned eligible signer', r.content)

        # Ensure no attendance record was created
        self.assertFalse(Attendance.objects.filter(meeting=self.finished_meeting, user=self.unassigned_officer).exists())

    def test_sign_meeting_cross_department_denied(self):
        """Member of another department is denied even with valid QR token."""
        self.client.force_login(self.other_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)

        r = self.client.get(f"{base_url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)

    def test_sign_meeting_already_signed_denied(self):
        """Officer who already signed cannot re-sign."""
        self.attendance.has_signed = True
        self.attendance.save()

        self.client.force_login(self.officer_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)

        r = self.client.get(f"{base_url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'You have already signed this document', r.content)


class MeetingCreationAndAssignmentTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.client = Client()
        self.dept = Department.objects.create(name='Computer Science', contact_email='cs@example.com')
        self.other_dept = Department.objects.create(name='Mechanical Engineering', contact_email='me@example.com')

        # Authorized Personnel for CS
        self.ap_user = User.objects.create_user(username='ap_cs', password='password123', email='ap_cs@example.com')
        Membership.objects.create(user=self.ap_user, department=self.dept, role='AP')

        # Authorized Personnel for Other Dept
        self.ap_other = User.objects.create_user(username='ap_other', password='password123', email='ap_other@example.com')
        Membership.objects.create(user=self.ap_other, department=self.other_dept, role='AP')

        # Global Admin
        self.global_admin = User.objects.create_user(username='admin_boss', password='password123', is_admin=True)

        # Officers in CS
        self.officer1 = User.objects.create_user(username='officer1_cs', password='password123', email='o1@example.com')
        Membership.objects.create(user=self.officer1, department=self.dept, role='O')

        self.officer2 = User.objects.create_user(username='officer2_cs', password='password123', email='o2@example.com')
        Membership.objects.create(user=self.officer2, department=self.dept, role='O')

        # Officer in Other Dept
        self.officer_other = User.objects.create_user(username='officer_other', password='password123', email='other@example.com')
        Membership.objects.create(user=self.officer_other, department=self.other_dept, role='O')
        complete_onboarding(self.ap_user, self.ap_other, self.officer1, self.officer2, self.officer_other)

    def test_authorized_ap_create_meeting_success(self):
        """Authorized AP can create a valid meeting with assigned participants and audit log."""
        self.client.force_login(self.ap_user)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        # GET creation page
        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 200)
        self.assertTemplateUsed(r_get, 'meetings/create_meeting.html')
        self.assertContains(r_get, 'Create Meeting Minutes')
        self.assertContains(r_get, self.officer1.username)

        # POST valid meeting
        data = {
            'department_id': self.dept.id,
            'title': 'CS Faculty General Meeting',
            'minutes_content': 'Discussion on curriculum revisions and thesis defense schedules.',
            'participants': [self.officer1.id, self.officer2.id],
        }
        r_post = self.client.post(url, data=data)
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))

        # Verify meeting created in database
        meeting = Meeting.objects.get(title='CS Faculty General Meeting')
        self.assertEqual(meeting.department, self.dept)
        self.assertEqual(meeting.status, 'Draft')
        self.assertEqual(meeting.minutes_content, data['minutes_content'])

        # Verify participants assigned
        attendee_user_ids = set(meeting.attendees.values_list('user_id', flat=True))
        self.assertEqual(attendee_user_ids, {self.officer1.id, self.officer2.id})

        # Verify AuditLog created
        self.assertTrue(AuditLog.objects.filter(meeting=meeting, user=self.ap_user, department=self.dept).exists())

    def test_create_meeting_missing_required_fields_rejected(self):
        """Meeting creation without required title is rejected with form validation error."""
        self.client.force_login(self.ap_user)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        data = {
            'department_id': self.dept.id,
            'title': '   ',  # Empty or whitespace only
            'minutes_content': 'Notes without a title',
        }
        r = self.client.post(url, data=data)
        self.assertEqual(r.status_code, 200)
        self.assertFormError(r.context['form'], 'title', 'Meeting title is required.')
        self.assertFalse(Meeting.objects.filter(department=self.dept).exists())

    def test_officer_cannot_create_meeting(self):
        """Officers cannot access creation page or submit meeting creation POST."""
        self.client.force_login(self.officer1)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        # GET attempt -> 403 Forbidden
        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 403)

        # POST attempt -> 403 Forbidden
        r_post = self.client.post(url, data={'title': 'Unauthorized Meeting', 'department_id': self.dept.id})
        self.assertEqual(r_post.status_code, 403)
        self.assertFalse(Meeting.objects.filter(title='Unauthorized Meeting').exists())

    def test_unauthenticated_cannot_create_meeting(self):
        """Unauthenticated requests to meeting creation redirect to login."""
        url = reverse('create_meeting_dept', args=[self.dept.id])
        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 302)
        self.assertTrue(r_get.headers['Location'].startswith('/accounts/auth/login/'))

        r_post = self.client.post(url, data={'title': 'Anon Meeting'})
        self.assertEqual(r_post.status_code, 302)
        self.assertTrue(r_post.headers['Location'].startswith('/accounts/auth/login/'))

    def test_ap_cannot_create_meeting_in_other_department(self):
        """AP cannot create meetings in a department where they lack AP membership."""
        self.client.force_login(self.ap_user)  # AP for CS, not Other Dept

        # Attempt to create via URL param
        url_other = reverse('create_meeting_dept', args=[self.other_dept.id])
        r = self.client.get(url_other)
        self.assertEqual(r.status_code, 403)

        # Attempt to create via POST
        r_post = self.client.post(url_other, data={'title': 'Cross Dept Meeting', 'department_id': self.other_dept.id})
        self.assertEqual(r_post.status_code, 403)
        self.assertFalse(Meeting.objects.filter(title='Cross Dept Meeting').exists())

    def test_cannot_assign_cross_department_user(self):
        """Attempting to assign a user from another department is rejected."""
        self.client.force_login(self.ap_user)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        data = {
            'department_id': self.dept.id,
            'title': 'Cross Member Test',
            'participants': [self.officer_other.id],  # From other_dept
        }
        r = self.client.post(url, data=data)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Meeting.objects.filter(title='Cross Member Test').exists())
        self.assertTrue(r.context['form'].errors)

    def test_cannot_assign_nonexistent_user(self):
        """Attempting to assign a nonexistent user ID is rejected."""
        self.client.force_login(self.ap_user)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        data = {
            'department_id': self.dept.id,
            'title': 'Invalid User Test',
            'participants': [999999],
        }
        r = self.client.post(url, data=data)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Meeting.objects.filter(title='Invalid User Test').exists())

    def test_empty_participants_selection_allowed(self):
        """Creating a meeting without immediately assigning participants is valid."""
        self.client.force_login(self.ap_user)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        data = {
            'department_id': self.dept.id,
            'title': 'Meeting with No Initial Attendees',
            'minutes_content': 'Agenda only',
        }
        r = self.client.post(url, data=data)
        self.assertRedirects(r, reverse('department_dashboard', args=[self.dept.id]))

        meeting = Meeting.objects.get(title='Meeting with No Initial Attendees')
        self.assertEqual(meeting.attendees.count(), 0)

    def test_assign_participants_updates_draft_meeting(self):
        """Authorized AP can manage participants for an existing Draft meeting."""
        meeting = Meeting.objects.create(department=self.dept, title='Existing Draft', status='Draft')
        Attendance.objects.create(meeting=meeting, user=self.officer1)

        self.client.force_login(self.ap_user)
        url = reverse('assign_participants', args=[meeting.id])

        # GET shows existing assignment
        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 200)
        self.assertTemplateUsed(r_get, 'meetings/assign_participants.html')

        # POST updates: add officer2, remove officer1
        data = {
            'participants': [self.officer2.id],
        }
        r_post = self.client.post(url, data=data)
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))

        attendees = set(meeting.attendees.values_list('user_id', flat=True))
        self.assertEqual(attendees, {self.officer2.id})
        self.assertFalse(meeting.attendees.filter(user=self.officer1).exists())

    def test_assign_participants_revalidates_lifecycle_after_write_guard(self):
        from unittest.mock import patch
        from meetings.attendance_integrity import lock_mutable_meetings

        for actor in (self.ap_user, self.global_admin):
            for status in ('Finished', 'Archived'):
                with self.subTest(actor=actor.username, status=status):
                    meeting = Meeting.objects.create(department=self.dept, title='Assignment race')
                    original = Attendance.objects.create(meeting=meeting, user=self.officer1)
                    self.client.force_login(actor)

                    def change_lifecycle_then_guard(meeting_ids):
                        # Deterministic interleaving at the write boundary, not a row-lock test.
                        Meeting.objects.filter(pk=meeting.pk).update(status=status)
                        lock_mutable_meetings(meeting_ids)

                    with patch('meetings.views.lock_mutable_meetings', side_effect=change_lifecycle_then_guard) as guard:
                        response = self.client.post(reverse('assign_participants', args=[meeting.pk]),
                                                    {'participants': [self.officer2.pk]})
                    self.assertEqual(response.status_code, 403)
                    guard.assert_called_once_with([meeting.pk])
                    self.assertEqual(list(meeting.attendees.values_list('pk', 'user_id')),
                                     [(original.pk, self.officer1.pk)])
                    self.assertFalse(AuditLog.objects.filter(meeting=meeting,
                                     event_type='meeting.participants_changed').exists())

    def test_global_admin_assigns_draft_participants(self):
        meeting = Meeting.objects.create(department=self.dept, title='Global assignment')
        self.client.force_login(self.global_admin)
        response = self.client.post(reverse('assign_participants', args=[meeting.pk]),
                                    {'participants': [self.officer1.pk]})
        self.assertRedirects(response, reverse('department_dashboard', args=[self.dept.pk]))
        self.assertEqual(list(meeting.attendees.values_list('user_id', flat=True)), [self.officer1.pk])
        self.assertEqual(AuditLog.objects.filter(meeting=meeting,
                         event_type='meeting.participants_changed').count(), 1)

    def test_assign_participants_denied_for_officers_and_other_ap(self):
        """Officers and APs from other departments cannot access or modify assignments."""
        meeting = Meeting.objects.create(department=self.dept, title='Isolation Meeting', status='Draft')
        url = reverse('assign_participants', args=[meeting.id])

        # Officer -> 403
        self.client.force_login(self.officer1)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, data={'participants': [self.officer1.id]}).status_code, 403)

        # Other Dept AP -> 403
        self.client.force_login(self.ap_other)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, data={'participants': [self.officer1.id]}).status_code, 403)

    def test_assign_participants_blocked_on_locked_or_finished_meeting(self):
        """Participant modifications on Finished meetings are rejected."""
        finished_meeting = Meeting.objects.create(department=self.dept, title='Locked Meeting', status='Finished')
        Attendance.objects.create(meeting=finished_meeting, user=self.officer1)

        self.client.force_login(self.ap_user)
        url = reverse('assign_participants', args=[finished_meeting.id])

        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 403)

        r_post = self.client.post(url, data={'participants': [self.officer2.id]})
        self.assertEqual(r_post.status_code, 403)

        # Confirm attendees were not modified
        self.assertEqual(list(finished_meeting.attendees.values_list('user_id', flat=True)), [self.officer1.id])

    def test_assign_participants_preserves_signed_attendances(self):
        """Unchecking an attendee who already signed does not delete their signed attendance record."""
        meeting = Meeting.objects.create(department=self.dept, title='Draft with Signature', status='Draft')
        att_signed = Attendance.objects.create(meeting=meeting, user=self.officer1, has_signed=True, annotation='Signed note')

        self.client.force_login(self.ap_user)
        url = reverse('assign_participants', args=[meeting.id])

        # Submit with only officer2, omitting officer1
        r_post = self.client.post(url, data={'participants': [self.officer2.id]})
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))

        # officer1 must still exist because has_signed is True
        self.assertTrue(meeting.attendees.filter(user=self.officer1).exists())
        # officer2 must also be added
        self.assertTrue(meeting.attendees.filter(user=self.officer2).exists())

    def test_global_admin_can_create_meeting(self):
        """Global Admin can create a meeting in a specified department."""
        self.client.force_login(self.global_admin)
        url = reverse('create_meeting_dept', args=[self.dept.id])

        r = self.client.post(url, data={
            'department_id': self.dept.id,
            'title': 'Admin Created Meeting',
            'participants': [self.officer1.id],
        })
        self.assertRedirects(r, reverse('department_dashboard', args=[self.dept.id]))
        meeting = Meeting.objects.get(title='Admin Created Meeting')
        self.assertEqual(meeting.department, self.dept)
        self.assertTrue(meeting.attendees.filter(user=self.officer1).exists())

    def test_dashboard_displays_meeting_actions_for_ap_only(self):
        """Authorized Dashboard renders meeting creation and management actions; Officer dashboard is read-only."""
        meeting = Meeting.objects.create(department=self.dept, title='Visible Meeting', status='Draft')

        # AP Dashboard
        self.client.force_login(self.ap_user)
        r_ap = self.client.get(reverse('department_dashboard', args=[self.dept.id]))
        self.assertEqual(r_ap.status_code, 200)
        self.assertContains(r_ap, 'Create Meeting')
        self.assertContains(r_ap, 'Visible Meeting')
        self.assertContains(r_ap, 'Assign Participants')
        self.assertContains(r_ap, 'Lock for Signing')

        # Officer Dashboard
        self.client.force_login(self.officer1)
        r_officer = self.client.get(reverse('department_dashboard', args=[self.dept.id]))
        self.assertEqual(r_officer.status_code, 200)
        self.assertContains(r_officer, 'Visible Meeting')
        self.assertNotContains(r_officer, 'Create Meeting')
        self.assertNotContains(r_officer, 'Assign Participants')
        self.assertNotContains(r_officer, 'Lock for Signing')



class Batch04DraftEditingReviewFinalizationTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.dept = Department.objects.create(name='Physics', contact_email='physics@example.com')
        self.other_dept = Department.objects.create(name='Chemistry', contact_email='chem@example.com')

        self.global_admin = User.objects.create_user(
            username='global_admin',
            password='password123',
            is_admin=True
        )

        self.ap_user = User.objects.create_user(
            username='ap_physics',
            password='password123'
        )
        Membership.objects.create(user=self.ap_user, department=self.dept, role='AP')

        self.other_ap = User.objects.create_user(
            username='ap_chem',
            password='password123'
        )
        Membership.objects.create(user=self.other_ap, department=self.other_dept, role='AP')

        self.officer = User.objects.create_user(
            username='officer_physics',
            password='password123'
        )
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        complete_onboarding(self.ap_user, self.other_ap, self.officer)

        self.draft_meeting = Meeting.objects.create(
            department=self.dept,
            title='Initial Draft Title',
            minutes_content='Initial draft minutes content.',
            status='Draft'
        )

        self.finished_meeting = Meeting.objects.create(
            department=self.dept,
            title='Finalized Meeting Title',
            minutes_content='Finalized immutable minutes content.',
            status='Finished'
        )

    def test_ap_can_get_and_post_edit_draft_meeting(self):
        """Authorized AP can load draft edit form and save updated content."""
        self.client.force_login(self.ap_user)
        url_edit = reverse('edit_meeting', args=[self.draft_meeting.id])

        # GET loads form with current data
        r_get = self.client.get(url_edit)
        self.assertEqual(r_get.status_code, 200)
        self.assertContains(r_get, 'Initial Draft Title')
        self.assertContains(r_get, 'Initial draft minutes content.')

        # POST updates data
        r_post = self.client.post(url_edit, {
            'title': 'Updated Draft Title',
            'minutes_content': 'Updated discussion notes and action items.',
        })
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.title, 'Updated Draft Title')
        self.assertEqual(self.draft_meeting.minutes_content, 'Updated discussion notes and action items.')
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # Check AuditLog
        log = AuditLog.objects.filter(meeting=self.draft_meeting, user=self.ap_user).last()
        self.assertIsNotNone(log)
        self.assertIn('Edited draft meeting minutes', log.action)

    def test_edit_draft_preserves_department_and_assignments(self):
        """Editing draft preserves department and existing participant assignments."""
        Attendance.objects.create(meeting=self.draft_meeting, user=self.officer)
        self.client.force_login(self.ap_user)
        url_edit = reverse('edit_meeting', args=[self.draft_meeting.id])

        # Attempt to tamper department
        self.client.post(url_edit, {
            'title': 'Safe Title',
            'minutes_content': 'Safe content.',
            'department': self.other_dept.id,
        })

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.department, self.dept)
        self.assertTrue(self.draft_meeting.attendees.filter(user=self.officer).exists())

    def test_invalid_edit_submission_rejected(self):
        """Empty title is rejected and meeting content remains unmodified."""
        self.client.force_login(self.ap_user)
        url_edit = reverse('edit_meeting', args=[self.draft_meeting.id])

        r = self.client.post(url_edit, {
            'title': '   ',
            'minutes_content': 'Some content.',
        })
        self.assertEqual(r.status_code, 200)
        self.assertFormError(r.context['form'], 'title', 'Meeting title is required.')

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.title, 'Initial Draft Title')

    def test_edit_permissions_enforced(self):
        """Officers and AP from other departments cannot edit Draft meetings."""
        url_edit = reverse('edit_meeting', args=[self.draft_meeting.id])

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer)
        r_officer = self.client.get(url_edit)
        self.assertEqual(r_officer.status_code, 403)
        r_officer_post = self.client.post(url_edit, {'title': 'Hacked Title'})
        self.assertEqual(r_officer_post.status_code, 403)

        # Other Dept AP -> 403 Forbidden
        self.client.force_login(self.other_ap)
        r_other = self.client.get(url_edit)
        self.assertEqual(r_other.status_code, 403)
        r_other_post = self.client.post(url_edit, {'title': 'Other AP Title'})
        self.assertEqual(r_other_post.status_code, 403)

        # Global Admin -> permitted
        self.client.force_login(self.global_admin)
        r_admin = self.client.get(url_edit)
        self.assertEqual(r_admin.status_code, 200)

    def test_cannot_edit_finished_or_archived_meeting(self):
        """Finished or Archived meeting returns 403 on edit GET and POST."""
        url_edit = reverse('edit_meeting', args=[self.finished_meeting.id])
        self.client.force_login(self.ap_user)

        r_get = self.client.get(url_edit)
        self.assertEqual(r_get.status_code, 403)

        r_post = self.client.post(url_edit, {'title': 'Tampered Finalized Title'})
        self.assertEqual(r_post.status_code, 403)

        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.title, 'Finalized Meeting Title')

    def test_review_draft_meeting(self):
        """Review view renders read-only preview and does not alter meeting content."""
        Attendance.objects.create(meeting=self.draft_meeting, user=self.officer)
        url_review = reverse('review_meeting', args=[self.draft_meeting.id])

        # AP can view preview
        self.client.force_login(self.ap_user)
        r = self.client.get(url_review)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Review Meeting Minutes')
        self.assertContains(r, 'Initial Draft Title')
        self.assertContains(r, 'Initial draft minutes content.')
        self.assertContains(r, self.officer.username)
        self.assertContains(r, 'Finalize & Lock for Signing')

        # Reviewing is read-only
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # Officer is forbidden
        self.client.force_login(self.officer)
        r_officer = self.client.get(url_review)
        self.assertEqual(r_officer.status_code, 403)

        # Other Dept AP is forbidden
        self.client.force_login(self.other_ap)
        r_other = self.client.get(url_review)
        self.assertEqual(r_other.status_code, 403)

    def test_finalize_meeting_draft_to_finished(self):
        """Authorized AP finalizes meeting via POST, transitioning status to Finished."""
        url_finalize = reverse('finalize_meeting', args=[self.draft_meeting.id])
        self.client.force_login(self.ap_user)

        r = self.client.post(url_finalize)
        self.assertRedirects(r, reverse('department_dashboard', args=[self.dept.id]))

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Finished')

        log = AuditLog.objects.filter(meeting=self.draft_meeting, user=self.ap_user).last()
        self.assertIsNotNone(log)
        self.assertEqual(log.action, 'Finalized document for signing')

    def test_finalize_get_request_rejected(self):
        """GET request to finalize endpoint returns 405 and does not change status."""
        url_finalize = reverse('finalize_meeting', args=[self.draft_meeting.id])
        self.client.force_login(self.ap_user)

        r = self.client.get(url_finalize)
        self.assertEqual(r.status_code, 405)

        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

    def test_finalize_permissions(self):
        """Officers and AP from other departments cannot finalize meetings."""
        url_finalize = reverse('finalize_meeting', args=[self.draft_meeting.id])

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer)
        r_officer = self.client.post(url_finalize)
        self.assertEqual(r_officer.status_code, 403)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # Other Dept AP -> 403 Forbidden
        self.client.force_login(self.other_ap)
        r_other = self.client.post(url_finalize)
        self.assertEqual(r_other.status_code, 403)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

    def test_cannot_re_finalize_finished_or_archived(self):
        """Attempting to finalize an already Finished meeting returns 403."""
        url_finalize = reverse('finalize_meeting', args=[self.finished_meeting.id])
        self.client.force_login(self.ap_user)

        r = self.client.post(url_finalize)
        self.assertEqual(r.status_code, 403)

    def test_model_level_immutability_on_finished_meeting(self):
        """Model-level validation prevents altering document content of Finished meetings."""
        from django.core.exceptions import ValidationError

        self.finished_meeting.title = 'Altered In Code'
        with self.assertRaises(ValidationError):
            self.finished_meeting.save()

        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.title, 'Finalized Meeting Title')

        # Allowed post-finalization operations:
        # 1. Adding attendance
        att = Attendance.objects.create(meeting=self.finished_meeting, user=self.officer)
        self.assertIsNotNone(att.id)

        # 2. Updating attendance signature / annotation
        att.annotation = 'Approved with notes.'
        att.has_signed = True
        att.save()
        att.refresh_from_db()
        self.assertTrue(att.has_signed)

        # 3. Adding audit logs
        log = AuditLog.objects.create(
            department=self.dept,
            meeting=self.finished_meeting,
            user=self.ap_user,
            action="Verified signature"
        )
        self.assertIsNotNone(log.id)

        # 4. Status transition to Archived
        self.finished_meeting.status = 'Archived'
        self.finished_meeting.save(update_fields=['status', 'updated_at'])
        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.status, 'Archived')

    def test_django_admin_readonly_fields_for_finished(self):
        """Django admin marks content fields as readonly for Finished/Archived meetings."""
        from meetings.admin import MeetingAdmin
        from django.contrib.admin.sites import AdminSite

        admin = MeetingAdmin(Meeting, AdminSite())
        ro_finished = admin.get_readonly_fields(None, self.finished_meeting)
        self.assertIn('title', ro_finished)
        self.assertIn('minutes_content', ro_finished)
        self.assertIn('department', ro_finished)
        self.assertIn('status', ro_finished)

        ro_draft = admin.get_readonly_fields(None, self.draft_meeting)
        self.assertNotIn('title', ro_draft)
        self.assertNotIn('minutes_content', ro_draft)
        self.assertIn('status', ro_draft)

    def test_authorized_dashboard_status_badges_and_css_classes(self):
        """Dashboard renders Draft, Finished, and fallback status badges with CSS classes."""
        archived_meeting = Meeting.objects.create(
            department=self.dept,
            title='Archived Annual Assembly',
            minutes_content='Archived historical notes.',
            status='Archived'
        )
        self.client.force_login(self.ap_user)
        r = self.client.get(reverse('department_dashboard', args=[self.dept.id]))
        self.assertEqual(r.status_code, 200)

        # Confirm CSS classes are declared in <style>
        self.assertContains(r, '.status-badge')
        self.assertContains(r, '.status-draft')
        self.assertContains(r, '.status-finished')
        self.assertContains(r, '.status-other')

        # Confirm meeting badge elements and display values
        self.assertContains(r, '<span class="status-badge status-draft">')
        self.assertContains(r, '<span class="status-badge status-finished">')
        self.assertContains(r, '<span class="status-badge status-other">')
        self.assertContains(r, '>Draft</span>')
        self.assertContains(r, '>Finished</span>')
        self.assertContains(r, '>Archived</span>')
        self.assertNotContains(r, 'PDF Generated')

    def test_lock_meeting_consistency_with_finalize_meeting(self):
        """lock_meeting endpoint requires POST, enforces AP authorization, and updates status atomically."""
        url_lock = reverse('lock_meeting', args=[self.draft_meeting.id])

        # 1. GET is rejected with 405 Method Not Allowed
        self.client.force_login(self.ap_user)
        r_get = self.client.get(url_lock)
        self.assertEqual(r_get.status_code, 405)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # 2. Officer cannot lock/finalize
        self.client.force_login(self.officer)
        r_officer = self.client.post(url_lock)
        self.assertEqual(r_officer.status_code, 403)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # 3. Other Department AP cannot lock/finalize
        self.client.force_login(self.other_ap)
        r_other = self.client.post(url_lock)
        self.assertEqual(r_other.status_code, 403)
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

        # 4. AP from correct department locks/finalizes successfully via POST
        self.client.force_login(self.ap_user)
        r_post = self.client.post(url_lock)
        self.assertRedirects(r_post, reverse('department_dashboard', args=[self.dept.id]))
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Finished')

        # Verify audit log was created
        log = AuditLog.objects.filter(meeting=self.draft_meeting, user=self.ap_user).last()
        self.assertIsNotNone(log)
        self.assertEqual(log.action, 'Finalized document for signing')

        # 5. Cannot re-lock/finalize already Finished meeting
        r_re_lock = self.client.post(url_lock)
        self.assertEqual(r_re_lock.status_code, 403)

    def test_immutability_all_protected_fields_on_finished_meeting(self):
        """Finalized meetings cannot have title, minutes_content, or department changed via any save pathway."""
        from django.core.exceptions import ValidationError
        from meetings.forms import MeetingEditForm

        # Attempt to change title
        self.finished_meeting.title = "Hacked Title"
        with self.assertRaises(ValidationError):
            self.finished_meeting.clean()
        with self.assertRaises(ValidationError):
            self.finished_meeting.save()
        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.title, 'Finalized Meeting Title')

        # Attempt to change minutes_content
        self.finished_meeting.minutes_content = "Tampered minutes content."
        with self.assertRaises(ValidationError):
            self.finished_meeting.clean()
        with self.assertRaises(ValidationError):
            self.finished_meeting.save()
        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.minutes_content, 'Finalized immutable minutes content.')

        # Attempt to change department
        self.finished_meeting.department = self.other_dept
        with self.assertRaises(ValidationError):
            self.finished_meeting.clean()
        with self.assertRaises(ValidationError):
            self.finished_meeting.save()
        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.department, self.dept)

        # Verify MeetingEditForm rejects modifying a finished meeting
        form = MeetingEditForm(
            data={'title': 'Form Tampered', 'minutes_content': 'Form Content'},
            instance=self.finished_meeting
        )
        self.assertFalse(form.is_valid())
        self.assertIn("Cannot edit a locked or finalized meeting.", form.non_field_errors())

    def test_status_transition_draft_to_archived_raises(self):
        """Model validation raises ValidationError when transitioning Draft → Archived (forbidden)."""
        from django.core.exceptions import ValidationError

        # draft_meeting is currently 'Draft' — attempting to jump directly to 'Archived' must fail.
        self.draft_meeting.status = 'Archived'
        with self.assertRaises(ValidationError):
            self.draft_meeting.clean()
        with self.assertRaises(ValidationError):
            self.draft_meeting.save()

        # Confirm the persisted status is still 'Draft'.
        self.draft_meeting.refresh_from_db()
        self.assertEqual(self.draft_meeting.status, 'Draft')

    def test_status_transition_archived_to_draft_raises(self):
        """Model validation raises ValidationError when transitioning Archived → Draft (forbidden)."""
        from django.core.exceptions import ValidationError

        # Establish a valid Archived starting state via legitimate model transitions:
        # Draft → Finished → Archived using normal .save().
        archived_meeting = Meeting.objects.create(
            department=self.dept,
            title='Archived Transition Test Meeting',
            minutes_content='Minutes content for archive test.',
            status='Draft'
        )
        archived_meeting.status = 'Finished'
        archived_meeting.save()
        archived_meeting.status = 'Archived'
        archived_meeting.save()
        archived_meeting.refresh_from_db()
        self.assertEqual(archived_meeting.status, 'Archived')

        # Attempting Archived → Draft must raise ValidationError.
        archived_meeting.status = 'Draft'
        with self.assertRaises(ValidationError):
            archived_meeting.clean()
        with self.assertRaises(ValidationError):
            archived_meeting.save()

        # Confirm the persisted status is still 'Archived'.
        archived_meeting.refresh_from_db()
        self.assertEqual(archived_meeting.status, 'Archived')

    def test_status_transition_archived_to_finished_raises(self):
        """Model validation raises ValidationError when transitioning Archived → Finished (forbidden)."""
        from django.core.exceptions import ValidationError

        # Establish a valid Archived starting state via legitimate model transitions:
        # Draft → Finished → Archived using normal .save().
        archived_meeting = Meeting.objects.create(
            department=self.dept,
            title='Archived Revert Test Meeting',
            minutes_content='Minutes content for revert test.',
            status='Draft'
        )
        archived_meeting.status = 'Finished'
        archived_meeting.save()
        archived_meeting.status = 'Archived'
        archived_meeting.save()
        archived_meeting.refresh_from_db()
        self.assertEqual(archived_meeting.status, 'Archived')

        # Attempting Archived → Finished must raise ValidationError.
        archived_meeting.status = 'Finished'
        with self.assertRaises(ValidationError):
            archived_meeting.clean()
        with self.assertRaises(ValidationError):
            archived_meeting.save()

        # Confirm the persisted status is still 'Archived'.
        archived_meeting.refresh_from_db()
        self.assertEqual(archived_meeting.status, 'Archived')


# ---------------------------------------------------------------------------
# Batch 05 — Digital Signature Lifecycle Tests
# ---------------------------------------------------------------------------

class Batch05CryptographicUnitTests(TestCase):
    """Unit tests for the crypto utility functions in meetings/crypto.py."""

    def setUp(self):
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key
        self.priv_pem, self.pub_pem = generate_ecdsa_keypair()
        self.encrypted_priv = encrypt_private_key(self.priv_pem)

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def test_generate_keypair_returns_pem_strings(self):
        """generate_ecdsa_keypair() returns non-empty PEM strings for both keys."""
        self.assertIsInstance(self.priv_pem, str)
        self.assertIsInstance(self.pub_pem, str)
        self.assertIn('PRIVATE KEY', self.priv_pem)
        self.assertIn('PUBLIC KEY', self.pub_pem)

    def test_generated_private_key_is_secp256r1(self):
        """The generated private key uses the SECP256R1 curve."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key = serialization.load_pem_private_key(
            self.priv_pem.encode('utf-8'), password=None
        )
        self.assertIsInstance(private_key.curve, ec.SECP256R1)

    def test_generated_public_key_matches_private_key(self):
        """The public key derived from the private key matches the returned public key."""
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(
            self.priv_pem.encode('utf-8'), password=None
        )
        derived_pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
        self.assertEqual(derived_pub_pem, self.pub_pem)

    # ------------------------------------------------------------------
    # Encryption / decryption round-trip
    # ------------------------------------------------------------------

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt_private_key / decrypt_private_key round-trip recovers the original PEM."""
        from meetings.crypto import decrypt_private_key
        recovered = decrypt_private_key(self.encrypted_priv)
        self.assertEqual(recovered, self.priv_pem)

    def test_decrypt_with_wrong_key_raises(self):
        """Decrypting with a mismatched Fernet key raises RuntimeError."""
        import os, base64
        from cryptography.fernet import Fernet
        from meetings.crypto import decrypt_private_key
        # Encrypt with a different Fernet key
        other_key = Fernet.generate_key().decode('utf-8')
        token_with_other_key = Fernet(other_key.encode()).encrypt(b'dummy').decode('utf-8')

        # Attempting to decrypt with the env key should fail
        with self.assertRaises(RuntimeError):
            decrypt_private_key(token_with_other_key)

    def test_decrypt_malformed_token_raises(self):
        """decrypt_private_key raises RuntimeError for a clearly invalid token."""
        from meetings.crypto import decrypt_private_key
        with self.assertRaises(RuntimeError):
            decrypt_private_key('not-a-valid-fernet-token')

    # ------------------------------------------------------------------
    # ECDSA signing
    # ------------------------------------------------------------------

    def test_sign_document_data_returns_hex_string(self):
        """sign_document_data() returns a non-empty hex string."""
        from meetings.crypto import sign_document_data
        sig = sign_document_data(self.encrypted_priv, 'test payload')
        self.assertIsInstance(sig, str)
        self.assertTrue(len(sig) > 0)
        # Must be valid hexadecimal
        bytes.fromhex(sig)  # raises ValueError if not hex

    def test_sign_document_data_is_valid_ecdsa_signature(self):
        """The signature produced by sign_document_data() verifies with the corresponding public key."""
        from meetings.crypto import sign_document_data, verify_document_signature
        payload = 'The quick brown fox'
        sig = sign_document_data(self.encrypted_priv, payload)
        self.assertTrue(verify_document_signature(self.pub_pem, payload, sig))

    def test_sign_different_payloads_produce_different_signatures(self):
        """Two distinct payloads produce distinct signatures (probabilistic ECDSA)."""
        from meetings.crypto import sign_document_data
        sig1 = sign_document_data(self.encrypted_priv, 'payload one')
        sig2 = sign_document_data(self.encrypted_priv, 'payload two')
        self.assertNotEqual(sig1, sig2)

    # ------------------------------------------------------------------
    # Signature verification — valid path
    # ------------------------------------------------------------------

    def test_verify_valid_signature_returns_true(self):
        """verify_document_signature() returns True for a correct key/payload/signature triple."""
        from meetings.crypto import sign_document_data, verify_document_signature
        payload = 'canonical meeting payload'
        sig = sign_document_data(self.encrypted_priv, payload)
        self.assertTrue(verify_document_signature(self.pub_pem, payload, sig))

    # ------------------------------------------------------------------
    # Signature verification — invalid / tampered paths
    # ------------------------------------------------------------------

    def test_verify_tampered_payload_returns_false(self):
        """A valid signature does not verify against a modified payload."""
        from meetings.crypto import sign_document_data, verify_document_signature
        payload = 'original content'
        sig = sign_document_data(self.encrypted_priv, payload)
        self.assertFalse(verify_document_signature(self.pub_pem, 'tampered content', sig))

    def test_verify_wrong_public_key_returns_false(self):
        """A valid signature does not verify against a different public key."""
        from meetings.crypto import (
            generate_ecdsa_keypair, encrypt_private_key,
            sign_document_data, verify_document_signature,
        )
        payload = 'document text'
        sig = sign_document_data(self.encrypted_priv, payload)

        _, other_pub_pem = generate_ecdsa_keypair()
        self.assertFalse(verify_document_signature(other_pub_pem, payload, sig))

    def test_verify_modified_signature_returns_false(self):
        """A byte-modified signature is rejected."""
        from meetings.crypto import sign_document_data, verify_document_signature
        payload = 'document'
        sig_hex = sign_document_data(self.encrypted_priv, payload)
        # Flip a nibble in the middle of the hex string
        mid = len(sig_hex) // 2
        bad_char = '0' if sig_hex[mid] != '0' else '1'
        tampered_hex = sig_hex[:mid] + bad_char + sig_hex[mid + 1:]
        self.assertFalse(verify_document_signature(self.pub_pem, payload, tampered_hex))

    def test_verify_malformed_signature_hex_returns_false(self):
        """Malformed (non-hex) signature string returns False without raising."""
        from meetings.crypto import verify_document_signature
        self.assertFalse(verify_document_signature(self.pub_pem, 'payload', 'not-hex!!'))

    def test_verify_malformed_public_key_returns_false(self):
        """A malformed public key returns False without raising."""
        from meetings.crypto import sign_document_data, verify_document_signature
        sig = sign_document_data(self.encrypted_priv, 'payload')
        self.assertFalse(verify_document_signature('not-a-pem', 'payload', sig))

    def test_verify_empty_inputs_return_false(self):
        """Any empty argument to verify_document_signature returns False."""
        from meetings.crypto import sign_document_data, verify_document_signature
        sig = sign_document_data(self.encrypted_priv, 'payload')
        self.assertFalse(verify_document_signature('', 'payload', sig))
        self.assertFalse(verify_document_signature(self.pub_pem, '', sig))
        self.assertFalse(verify_document_signature(self.pub_pem, 'payload', ''))


class Batch05DocumentIntegrityTests(TestCase):
    """Tests that the canonical payload binds meeting identity, department, title,
    minutes content, and annotation, and that legacy payload verification is supported."""

    def setUp(self):
        signature_storage(self)
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key
        self.dept = Department.objects.create(name='Integrity Dept', contact_email='i@example.com')
        self.other_dept = Department.objects.create(name='Other Integrity Dept', contact_email='oi@example.com')
        self.ap = User.objects.create_user(username='integrity_ap', password='pw')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')
        self.officer = User.objects.create_user(username='integrity_officer', password='pw')
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        complete_onboarding(self.ap, self.officer)

        # Give the officer a fresh ECDSA key pair so we control it
        priv_pem, pub_pem = generate_ecdsa_keypair()
        encrypted_priv = encrypt_private_key(priv_pem)
        User.objects.filter(pk=self.officer.pk).update(
            private_key=encrypted_priv, public_key=pub_pem
        )
        self.officer.refresh_from_db()

        self.meeting = Meeting.objects.create(
            department=self.dept,
            title='Integrity Meeting',
            minutes_content='These are the finalized minutes.',
            status='Finished',
        )
        self.attendance = Attendance.objects.create(
            meeting=self.meeting, user=self.officer, has_signed=False
        )

    def _sign_attendance(self, annotation=''):
        """Helper: sign the attendance record programmatically using canonical payload."""
        from meetings.crypto import sign_document_data
        from meetings.views import _build_signing_payload
        payload = _build_signing_payload(self.meeting, annotation)
        sig = sign_document_data(self.officer.private_key, payload)
        self.attendance.annotation = annotation
        self.attendance.has_signed = True
        self.attendance.cryptographic_signature = sig
        self.attendance.save()

    def _sign_legacy_attendance(self, annotation=''):
        """Helper: sign the attendance record programmatically using legacy payload."""
        from meetings.crypto import sign_document_data
        from meetings.views import _build_legacy_signing_payload
        payload = _build_legacy_signing_payload(self.meeting, annotation)
        sig = sign_document_data(self.officer.private_key, payload)
        self.attendance.annotation = annotation
        self.attendance.has_signed = True
        self.attendance.cryptographic_signature = sig
        self.attendance.save()

    def test_signature_verifies_against_original_payload(self):
        """A canonical signature recorded at signing time verifies correctly against the same payload."""
        from meetings.crypto import verify_document_signature
        from meetings.views import _build_signing_payload

        annotation = 'My annotation'
        self._sign_attendance(annotation)
        self.attendance.refresh_from_db()

        payload = _build_signing_payload(self.meeting, annotation)
        self.assertTrue(
            verify_document_signature(
                self.officer.public_key,
                payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signature_does_not_verify_for_different_meeting_id(self):
        """A signature bound to meeting A does not verify when the meeting ID is different
        (i.e., identical minutes in a second meeting cannot reuse the signature)."""
        from meetings.crypto import verify_document_signature
        from meetings.views import _build_signing_payload

        annotation = ''
        self._sign_attendance(annotation)
        self.attendance.refresh_from_db()

        # Create a second meeting with the same content but a different pk.
        second_meeting = Meeting.objects.create(
            department=self.dept,
            title='Integrity Meeting',
            minutes_content='These are the finalized minutes.',
            status='Finished',
        )
        wrong_payload = _build_signing_payload(second_meeting, annotation)
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                wrong_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signature_fails_if_department_tampered(self):
        """A signature bound to department A fails verification if the department ID is altered."""
        from meetings.crypto import verify_document_signature

        annotation = ''
        self._sign_attendance(annotation)
        self.attendance.refresh_from_db()

        tampered_payload = (
            f"meeting_id:{self.meeting.id}\n"
            f"department_id:{self.other_dept.id}\n"
            f"title:{self.meeting.title}\n"
            f"{self.meeting.minutes_content}\n"
            f"---ANNOTATION---\n"
            f"{annotation}"
        )
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                tampered_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signature_fails_if_title_tampered(self):
        """A signature bound to meeting title fails verification if the title is altered."""
        from meetings.crypto import verify_document_signature

        annotation = ''
        self._sign_attendance(annotation)
        self.attendance.refresh_from_db()

        tampered_payload = (
            f"meeting_id:{self.meeting.id}\n"
            f"department_id:{self.meeting.department_id}\n"
            f"title:Tampered Meeting Title\n"
            f"{self.meeting.minutes_content}\n"
            f"---ANNOTATION---\n"
            f"{annotation}"
        )
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                tampered_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signature_fails_if_minutes_content_tampered(self):
        """A tampered minutes_content value invalidates the stored signature."""
        from meetings.crypto import verify_document_signature

        annotation = ''
        self._sign_attendance(annotation)
        self.attendance.refresh_from_db()

        tampered_payload = (
            f"meeting_id:{self.meeting.id}\n"
            f"department_id:{self.meeting.department_id}\n"
            f"title:{self.meeting.title}\n"
            f"TAMPERED CONTENT\n"
            f"---ANNOTATION---\n"
            f"{annotation}"
        )
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                tampered_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signature_fails_if_annotation_tampered(self):
        """A modified annotation string invalidates the stored signature."""
        from meetings.crypto import verify_document_signature
        from meetings.views import _build_signing_payload

        self._sign_attendance('Original Note')
        self.attendance.refresh_from_db()

        altered_payload = _build_signing_payload(self.meeting, 'Altered Note')
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                altered_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_legacy_signature_verifiable_with_legacy_payload(self):
        """Existing/legacy signatures created without meeting ID headers remain verifiable
        via _build_legacy_signing_payload()."""
        from meetings.crypto import verify_document_signature
        from meetings.views import _build_legacy_signing_payload, _build_signing_payload

        annotation = 'Legacy Note'
        self._sign_legacy_attendance(annotation)
        self.attendance.refresh_from_db()

        # Does NOT verify under canonical meeting-bound payload
        canonical_payload = _build_signing_payload(self.meeting, annotation)
        self.assertFalse(
            verify_document_signature(
                self.officer.public_key,
                canonical_payload,
                self.attendance.cryptographic_signature,
            )
        )

        # DOES verify under legacy payload
        legacy_payload = _build_legacy_signing_payload(self.meeting, annotation)
        self.assertTrue(
            verify_document_signature(
                self.officer.public_key,
                legacy_payload,
                self.attendance.cryptographic_signature,
            )
        )

    def test_signing_does_not_alter_meeting_content(self):
        """Signing via _sign_attendance does not modify the meeting's title,
        minutes_content, or department."""
        self._sign_attendance('Some note')
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.title, 'Integrity Meeting')
        self.assertEqual(self.meeting.minutes_content, 'These are the finalized minutes.')
        self.assertEqual(self.meeting.department, self.dept)
        self.assertEqual(self.meeting.status, 'Finished')


class Batch05SigningWorkflowTests(TestCase):
    """Integration tests for the sign_meeting view and its cryptographic output."""

    def setUp(self):
        signature_storage(self)
        self.client = Client()
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key

        self.dept = Department.objects.create(name='Workflow Dept', contact_email='w@example.com')

        self.ap = User.objects.create_user(username='workflow_ap', password='pw')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')

        # Officer with a fresh known key pair
        self.officer = User.objects.create_user(username='workflow_officer', password='pw')
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        priv_pem, pub_pem = generate_ecdsa_keypair()
        encrypted_priv = encrypt_private_key(priv_pem)
        User.objects.filter(pk=self.officer.pk).update(
            private_key=encrypted_priv, public_key=pub_pem
        )
        self.officer.refresh_from_db()

        self.other_dept = Department.objects.create(name='Other Dept', contact_email='o@example.com')
        self.other_officer = User.objects.create_user(username='other_officer', password='pw')
        Membership.objects.create(user=self.other_officer, department=self.other_dept, role='O')

        self.unassigned = User.objects.create_user(username='unassigned_officer', password='pw')
        Membership.objects.create(user=self.unassigned, department=self.dept, role='O')
        complete_onboarding(self.ap, self.officer, self.other_officer, self.unassigned)

        self.finished_meeting = Meeting.objects.create(
            department=self.dept,
            title='Workflow Meeting',
            minutes_content='Final minutes here.',
            status='Finished',
        )
        self.draft_meeting = Meeting.objects.create(
            department=self.dept,
            title='Draft Meeting',
            minutes_content='Draft content.',
            status='Draft',
        )

        self.attendance = Attendance.objects.create(
            meeting=self.finished_meeting, user=self.officer, has_signed=False, status='Attended'
        )

    def _valid_url(self, meeting_id):
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)
        return reverse('sign_meeting', args=[meeting_id]), ts, sig

    # ------------------------------------------------------------------
    # Successful signing — cryptographic correctness
    # ------------------------------------------------------------------

    def test_successful_sign_produces_valid_ecdsa_signature(self):
        """After a successful sign_meeting POST, the stored signature verifies against
        the signer's public key and the canonical payload."""
        from meetings.crypto import verify_document_signature
        from meetings.views import _build_signing_payload

        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        annotation = 'Confirmed by officer.'

        r = self.client.post(f"{url}?t={ts}&sig={sig}", data={'annotation': annotation})
        self.assertRedirects(r, reverse('department_dashboard', args=[self.dept.id]))

        self.attendance.refresh_from_db()
        self.assertTrue(self.attendance.has_signed)
        self.assertIsNotNone(self.attendance.cryptographic_signature)

        payload = _build_signing_payload(self.finished_meeting, annotation)
        self.officer.refresh_from_db()
        self.assertTrue(
            verify_document_signature(
                self.officer.public_key,
                payload,
                self.attendance.cryptographic_signature,
            ),
            "Stored cryptographic_signature must verify against signer's public key.",
        )

    def test_signing_does_not_change_meeting_content(self):
        """sign_meeting must not alter title, minutes_content, department, or status."""
        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        self.client.post(f"{url}?t={ts}&sig={sig}", data={'annotation': 'note'})

        self.finished_meeting.refresh_from_db()
        self.assertEqual(self.finished_meeting.title, 'Workflow Meeting')
        self.assertEqual(self.finished_meeting.minutes_content, 'Final minutes here.')
        self.assertEqual(self.finished_meeting.department, self.dept)
        self.assertEqual(self.finished_meeting.status, 'Finished')

    # ------------------------------------------------------------------
    # Authorization enforcement
    # ------------------------------------------------------------------

    def test_draft_meeting_cannot_be_signed(self):
        """sign_meeting returns 403 for a Draft meeting regardless of token validity."""
        Attendance.objects.create(meeting=self.draft_meeting, user=self.officer)
        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.draft_meeting.id)
        r = self.client.get(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)

    def test_unassigned_officer_cannot_sign(self):
        """An officer not listed in Attendance for the meeting is denied."""
        self.client.force_login(self.unassigned)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        r = self.client.get(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)
        self.assertFalse(
            Attendance.objects.filter(meeting=self.finished_meeting, user=self.unassigned).exists()
        )

    def test_cross_department_officer_cannot_sign(self):
        """An officer from another department is denied."""
        self.client.force_login(self.other_officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        r = self.client.get(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)

    def test_duplicate_signing_rejected(self):
        """An officer who already signed cannot sign again."""
        self.attendance.has_signed = True
        self.attendance.cryptographic_signature = 'already_signed'
        self.attendance.save()

        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        r = self.client.get(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'already signed', r.content)

    def test_has_signed_false_when_crypto_would_fail(self):
        """If the signing user has no private key set, the view returns a controlled
        400 error and does not persist has_signed=True on the attendance record."""
        # Remove the private key so signing will fail.
        User.objects.filter(pk=self.officer.pk).update(private_key=None)
        self.officer.refresh_from_db()

        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)
        r = self.client.post(f"{url}?t={ts}&sig={sig}", data={'annotation': 'x'})
        # Should return controlled 400 Bad Request error.
        self.assertEqual(r.status_code, 400)

        self.attendance.refresh_from_db()
        self.assertFalse(self.attendance.has_signed)
        self.assertIsNone(self.attendance.cryptographic_signature)

    def test_concurrent_duplicate_signing_conditional_update_prevents_overwrite(self):
        """Simulate a race condition where a stale Attendance instance attempts to sign
        after another concurrent request has already persisted a signature.
        Demonstrates that the atomic conditional update affects 0 rows, preserves the
        original signature and timestamp, and creates no duplicate AuditLog."""
        from django.db import transaction
        from django.utils import timezone

        # 1. Retrieve an Attendance instance while has_signed=False (stale instance)
        stale_attendance = Attendance.objects.get(pk=self.attendance.pk)
        self.assertFalse(stale_attendance.has_signed)

        # 2. Simulate another concurrent request winning the race and successfully signing
        first_sig = 'first_concurrent_signature_hex'
        first_annotation = 'First signer note'
        first_signed_at = timezone.now()
        with transaction.atomic():
            Attendance.objects.filter(pk=self.attendance.pk, has_signed=False).update(
                annotation=first_annotation,
                has_signed=True,
                cryptographic_signature=first_sig,
                signed_at=first_signed_at,
            )
            AuditLog.objects.create(
                department=self.dept,
                meeting=self.finished_meeting,
                user=self.officer,
                action="Signed document with annotation"
            )

        initial_audit_count = AuditLog.objects.filter(meeting=self.finished_meeting, user=self.officer).count()
        self.assertEqual(initial_audit_count, 1)

        # 3. Second concurrent request attempts conditional update using stale instance
        second_sig = 'second_concurrent_signature_hex'
        second_annotation = 'Second signer note'
        with transaction.atomic():
            updated = Attendance.objects.filter(
                pk=stale_attendance.pk,
                has_signed=False
            ).update(
                annotation=second_annotation,
                has_signed=True,
                cryptographic_signature=second_sig,
                signed_at=timezone.now()
            )

            # 4. Assert that the update affects zero rows
            self.assertEqual(updated, 0)

            # Conditional check in view: only create AuditLog if updated == 1
            if updated > 0:
                AuditLog.objects.create(
                    department=self.dept,
                    meeting=self.finished_meeting,
                    user=self.officer,
                    action="Signed document with annotation"
                )

        # 5. Assert that the original signature, annotation, and timestamp remain unchanged
        self.attendance.refresh_from_db()
        self.assertTrue(self.attendance.has_signed)
        self.assertEqual(self.attendance.cryptographic_signature, first_sig)
        self.assertEqual(self.attendance.annotation, first_annotation)
        self.assertEqual(self.attendance.signed_at, first_signed_at)

        # 6. Assert that no second AuditLog entry was created
        final_audit_count = AuditLog.objects.filter(meeting=self.finished_meeting, user=self.officer).count()
        self.assertEqual(final_audit_count, 1)

    def test_sign_meeting_concurrent_post_rejected_by_conditional_update(self):
        """Integration test: if a concurrent request signs between initial read and update,
        sign_meeting() returns 403 Forbidden and does not overwrite the record or create a duplicate log."""
        from unittest.mock import patch
        from django.utils import timezone

        self.client.force_login(self.officer)
        url, ts, sig = self._valid_url(self.finished_meeting.id)

        original_filter = Attendance.objects.filter

        # Patch Attendance.objects.filter in meetings.views to simulate another request
        # completing the signature right before the conditional update runs
        def simulate_race_filter(*args, **kwargs):
            if kwargs.get('has_signed') is False and kwargs.get('pk') == self.attendance.pk:
                # Mark as already signed in the database right before the update executes
                original_filter(pk=self.attendance.pk).update(
                    has_signed=True,
                    cryptographic_signature='race_winner_sig',
                    annotation='Race Winner',
                    signed_at=timezone.now()
                )
            return original_filter(*args, **kwargs)

        with patch('meetings.views.Attendance.objects.filter', side_effect=simulate_race_filter):
            r = self.client.post(f"{url}?t={ts}&sig={sig}", data={'annotation': 'Second Request'})
            self.assertEqual(r.status_code, 403)
            self.assertIn(b'already signed', r.content)

        # Verify record was not overwritten
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.cryptographic_signature, 'race_winner_sig')
        self.assertEqual(self.attendance.annotation, 'Race Winner')


class Batch05VerifySignatureViewTests(TestCase):
    """Integration tests for the verify_signature internal endpoint, covering
    both canonical and legacy backward-compatible verification."""

    def setUp(self):
        signature_storage(self)
        self.client = Client()
        import json
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key, sign_document_data
        from meetings.views import _build_signing_payload, _build_legacy_signing_payload

        self.dept = Department.objects.create(name='Verify Dept', contact_email='v@example.com')
        self.other_dept = Department.objects.create(name='Other Verify Dept', contact_email='ov@example.com')

        self.ap = User.objects.create_user(username='verify_ap', password='pw')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')

        self.global_admin = User.objects.create_user(username='verify_admin', password='pw', is_admin=True)

        self.officer = User.objects.create_user(username='verify_officer', password='pw')
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        priv_pem, pub_pem = generate_ecdsa_keypair()
        encrypted_priv = encrypt_private_key(priv_pem)
        User.objects.filter(pk=self.officer.pk).update(
            private_key=encrypted_priv, public_key=pub_pem
        )
        self.officer.refresh_from_db()

        self.other_ap = User.objects.create_user(username='other_ap', password='pw')
        Membership.objects.create(user=self.other_ap, department=self.other_dept, role='AP')
        complete_onboarding(self.ap, self.officer, self.other_ap)

        self.meeting = Meeting.objects.create(
            department=self.dept,
            title='Verify Meeting',
            minutes_content='Minutes to verify.',
            status='Finished',
        )

        # 1. Canonical meeting-bound signature
        annotation = 'Verified note.'
        payload = _build_signing_payload(self.meeting, annotation)
        sig = sign_document_data(self.officer.private_key, payload)
        self.attendance = Attendance.objects.create(
            meeting=self.meeting,
            user=self.officer,
            annotation=annotation,
            has_signed=True,
            cryptographic_signature=sig,
        )

        # 2. Legacy signature (signed with legacy payload: minutes + annotation)
        legacy_officer = User.objects.create_user(username='legacy_officer', password='pw')
        Membership.objects.create(user=legacy_officer, department=self.dept, role='O')
        l_priv, l_pub = generate_ecdsa_keypair()
        l_enc = encrypt_private_key(l_priv)
        User.objects.filter(pk=legacy_officer.pk).update(
            private_key=l_enc, public_key=l_pub
        )
        legacy_officer.refresh_from_db()
        self.legacy_officer = legacy_officer

        legacy_ann = 'Legacy annotation.'
        legacy_payload = _build_legacy_signing_payload(self.meeting, legacy_ann)
        legacy_sig = sign_document_data(self.legacy_officer.private_key, legacy_payload)
        self.legacy_attendance = Attendance.objects.create(
            meeting=self.meeting,
            user=self.legacy_officer,
            annotation=legacy_ann,
            has_signed=True,
            cryptographic_signature=legacy_sig,
        )

    def _url(self, att_id=None):
        target_id = att_id if att_id is not None else self.attendance.id
        return reverse('verify_signature', args=[self.meeting.id, target_id])

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def test_unauthenticated_redirected_to_login(self):
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 302)

    def test_officer_cannot_access_verify_endpoint(self):
        self.client.force_login(self.officer)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 403)

    def test_ap_from_other_department_cannot_verify(self):
        self.client.force_login(self.other_ap)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 403)

    def test_ap_in_department_can_verify(self):
        self.client.force_login(self.ap)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 200)

    def test_global_admin_can_verify(self):
        self.client.force_login(self.global_admin)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 200)

    # ------------------------------------------------------------------
    # Verification correctness (Canonical and Legacy)
    # ------------------------------------------------------------------

    def test_canonical_signature_returns_true_with_canonical_format(self):
        """The endpoint returns valid=true, format=canonical, meeting_bound=true for new signatures."""
        import json
        self.client.force_login(self.ap)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content)
        self.assertTrue(data['valid'])
        self.assertEqual(data['format'], 'canonical')
        self.assertFalse(data['is_legacy'])
        self.assertTrue(data['meeting_bound'])
        self.assertEqual(data['meeting_id'], self.meeting.id)
        self.assertEqual(data['attendance_id'], self.attendance.id)
        self.assertEqual(data['signer'], self.officer.username)

    def test_legacy_signature_returns_true_with_legacy_format(self):
        """The endpoint returns valid=true, format=legacy, is_legacy=true, meeting_bound=false for legacy signatures."""
        import json
        self.client.force_login(self.ap)
        url = self._url(self.legacy_attendance.id)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content)
        self.assertTrue(data['valid'])
        self.assertEqual(data['format'], 'legacy')
        self.assertTrue(data['is_legacy'])
        self.assertFalse(data['meeting_bound'])
        self.assertIn('note', data)
        self.assertEqual(data['attendance_id'], self.legacy_attendance.id)
        self.assertEqual(data['signer'], self.legacy_officer.username)

    def test_tampered_signature_returns_false(self):
        """Storing a corrupted signature causes the endpoint to return valid=false."""
        import json
        self.attendance.cryptographic_signature = 'deadbeef'
        self.attendance.save()

        self.client.force_login(self.ap)
        r = self.client.get(self._url())
        data = json.loads(r.content)
        self.assertFalse(data['valid'])
        self.assertIsNone(data['format'])

    def test_unsigned_attendance_returns_false(self):
        """An attendance record that has not been signed returns valid=false."""
        import json
        unsigned = Attendance.objects.create(
            meeting=self.meeting, user=self.ap, has_signed=False
        )
        url = reverse('verify_signature', args=[self.meeting.id, unsigned.id])
        self.client.force_login(self.ap)
        r = self.client.get(url)
        data = json.loads(r.content)
        self.assertFalse(data['valid'])


class Batch06AttendanceAndAnnotationTests(TestCase):
    """Targeted tests for Batch 06: Attendance records, annotations, and role-based permissions."""

    def setUp(self):
        signature_storage(self)
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key

        self.dept = Department.objects.create(name='Dept 06', contact_email='dept06@example.com')
        self.other_dept = Department.objects.create(name='Other Dept 06', contact_email='other06@example.com')

        # Authorized Personnel for Dept 06
        self.ap = User.objects.create_user(username='ap_user_06', password='pw')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')

        # Authorized Personnel for Other Dept
        self.other_ap = User.objects.create_user(username='other_ap_06', password='pw')
        Membership.objects.create(user=self.other_ap, department=self.other_dept, role='AP')

        # Global Admin
        self.admin = User.objects.create_user(username='admin_user_06', password='pw', is_admin=True)

        # Officer 1 in Dept 06 with ECDSA key pair
        self.officer1 = User.objects.create_user(username='officer1_06', password='pw')
        Membership.objects.create(user=self.officer1, department=self.dept, role='O')
        priv1, pub1 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer1.pk).update(
            private_key=encrypt_private_key(priv1), public_key=pub1
        )
        self.officer1.refresh_from_db()

        # Officer 2 in Dept 06 with ECDSA key pair
        self.officer2 = User.objects.create_user(username='officer2_06', password='pw')
        Membership.objects.create(user=self.officer2, department=self.dept, role='O')
        priv2, pub2 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer2.pk).update(
            private_key=encrypt_private_key(priv2), public_key=pub2
        )
        self.officer2.refresh_from_db()

        # Officer in Other Dept
        self.other_officer = User.objects.create_user(username='other_officer_06', password='pw')
        Membership.objects.create(user=self.other_officer, department=self.other_dept, role='O')

        # Unassigned Officer in Dept 06
        self.unassigned_officer = User.objects.create_user(username='unassigned_06', password='pw')
        Membership.objects.create(user=self.unassigned_officer, department=self.dept, role='O')
        complete_onboarding(self.ap, self.other_ap, self.officer1, self.officer2,
                            self.other_officer, self.unassigned_officer)

        # Finished Meeting in Dept 06
        self.meeting = Meeting.objects.create(
            department=self.dept,
            title='Executive Assembly 06',
            minutes_content='Important minutes content for assembly 06.',
            status='Finished',
        )

        # Assigned Attendance records
        self.att1 = Attendance.objects.create(
            meeting=self.meeting,
            user=self.officer1,
            status='Absent',
        )
        self.att2 = Attendance.objects.create(
            meeting=self.meeting,
            user=self.officer2,
            status='Absent',
        )

    # 1. AP Attendance View
    def test_ap_can_view_department_meeting_attendance(self):
        """Authorized Personnel can view attendance records for meetings in their department."""
        self.client.force_login(self.ap)
        url = reverse('meeting_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Executive Assembly 06')
        self.assertContains(r, self.officer1.username)
        self.assertContains(r, self.officer2.username)

    def test_other_department_ap_cannot_view_attendance(self):
        """Authorized Personnel cannot view attendance for another department's meeting."""
        self.client.force_login(self.other_ap)
        url = reverse('meeting_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 403)

    def test_global_admin_can_view_attendance(self):
        """Global Admin can view attendance for any department's meeting."""
        self.client.force_login(self.admin)
        url = reverse('meeting_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)

    def test_officer_cannot_view_ap_attendance_page(self):
        """Officers are strictly forbidden from viewing the AP attendance management page."""
        self.client.force_login(self.officer1)
        url = reverse('meeting_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 403)

    # 2. AP Updating Attendance Status
    def test_ap_updates_attendance_status_to_attended(self):
        """AP updates an officer's attendance to 'Attended' with timestamp and audit logging."""
        self.client.force_login(self.ap)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])
        r = self.client.post(url, {'status': 'Attended'})
        self.assertEqual(r.status_code, 302)

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertIsNotNone(self.att1.status_updated_at)

        # AuditLog recorded
        audit = AuditLog.objects.filter(meeting=self.meeting, user=self.ap).order_by('-timestamp').first()
        self.assertIsNotNone(audit)
        self.assertIn('Absent to Attended', audit.action)

    def test_ap_updates_attendance_status_to_late_and_absent(self):
        """AP can set status to 'Late' and revert to 'Absent'."""
        self.client.force_login(self.ap)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])

        # Set to Late
        r = self.client.post(url, {'status': 'Late'})
        self.assertEqual(r.status_code, 302)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Late')

        # Revert to Absent
        r = self.client.post(url, {'status': 'Absent'})
        self.assertEqual(r.status_code, 302)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    def test_invalid_attendance_status_rejected(self):
        """Invalid attendance status values are rejected with 400 Bad Request."""
        self.client.force_login(self.ap)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])
        r = self.client.post(url, {'status': 'InvalidChoice'})
        self.assertEqual(r.status_code, 400)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    def test_update_attendance_status_rejects_get(self):
        """GET requests to update_attendance_status are rejected with 405 Method Not Allowed."""
        self.client.force_login(self.ap)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 405)

    def test_officer_cannot_update_attendance_status(self):
        """Officers cannot update attendance records via update_attendance_status."""
        self.client.force_login(self.officer1)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])
        r = self.client.post(url, {'status': 'Attended'})
        self.assertEqual(r.status_code, 403)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    def test_other_dept_ap_cannot_update_attendance_status(self):
        """AP from another department cannot update attendance records."""
        self.client.force_login(self.other_ap)
        url = reverse('update_attendance_status', args=[self.meeting.id, self.att1.id])
        r = self.client.post(url, {'status': 'Attended'})
        self.assertEqual(r.status_code, 403)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    # 3. Officer Personal Attendance View
    def test_officer_can_view_own_attendance_record(self):
        """Officers can view their personal attendance record via my_attendance."""
        self.client.force_login(self.officer1)
        url = reverse('my_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Executive Assembly 06')
        self.assertContains(r, self.officer1.username)
        self.assertNotContains(r, self.officer2.username)

    def test_officer_cannot_modify_via_my_attendance_post(self):
        """Officers cannot POST to my_attendance to alter records (returns 403)."""
        self.client.force_login(self.officer1)
        url = reverse('my_attendance', args=[self.meeting.id])
        r = self.client.post(url, {'status': 'Attended'})
        self.assertEqual(r.status_code, 403)

    def test_unassigned_officer_cannot_view_my_attendance(self):
        """Unassigned officers cannot view my_attendance for a meeting they are not part of."""
        self.client.force_login(self.unassigned_officer)
        url = reverse('my_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 403)

    def test_other_dept_officer_cannot_view_my_attendance(self):
        """Officers from other departments cannot view my_attendance."""
        self.client.force_login(self.other_officer)
        url = reverse('my_attendance', args=[self.meeting.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 403)

    # 4. Duplicate Attendance Record Prevention
    def test_duplicate_attendance_record_prevented(self):
        """Database enforces unique_together on (meeting, user), preventing duplicate attendances."""
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            Attendance.objects.create(meeting=self.meeting, user=self.officer1)

    # 5. Annotations and Signing Workflow
    def test_officer_signs_with_valid_annotation(self):
        """Eligible officer marked Attended can sign document with an optional annotation within length limits."""
        import time
        from meetings.crypto import generate_hmac_qr_token, verify_document_signature
        from meetings.views import _build_signing_payload

        # Mark officer as Attended
        self.att1.status = 'Attended'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])
        annotation_text = "I concur with item 3 subject to budget confirmation."

        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': annotation_text,
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r.status_code, 302)

        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertEqual(self.att1.annotation, annotation_text)
        self.assertIsNotNone(self.att1.cryptographic_signature)
        self.assertIsNotNone(self.att1.signed_at)

        # Verify signature with annotation payload
        payload = _build_signing_payload(self.meeting, annotation_text)
        self.assertTrue(
            verify_document_signature(
                self.officer1.public_key,
                payload,
                self.att1.cryptographic_signature,
            )
        )

    def test_officer_marked_late_can_sign_successfully(self):
        """Eligible officer marked Late can sign document successfully."""
        import time
        from meetings.crypto import generate_hmac_qr_token, verify_document_signature
        from meetings.views import _build_signing_payload

        # Mark officer as Late
        self.att1.status = 'Late'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': 'Attended late due to schedule conflict',
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r.status_code, 302)

        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertIsNotNone(self.att1.cryptographic_signature)

    def test_officer_marked_absent_receives_403(self):
        """Officers marked Absent cannot sign (GET or POST) and receive HTTP 403."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        # Ensure officer is Absent
        self.att1.status = 'Absent'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])

        # GET request blocked
        r_get = self.client.get(f"{url}?t={timestamp}&sig={sig}")
        self.assertEqual(r_get.status_code, 403)
        self.assertIn(b'Attended or Late', r_get.content)

        # POST request blocked
        r_post = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': 'Attempted note',
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r_post.status_code, 403)
        self.assertIn(b'Attended or Late', r_post.content)

        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)
        self.assertIsNone(self.att1.cryptographic_signature)

    def test_officer_with_default_absent_and_null_timestamp_receives_403(self):
        """Newly assigned officer with default Absent status and NULL status_updated_at is rejected."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        self.assertEqual(self.att2.status, 'Absent')
        self.assertIsNone(self.att2.status_updated_at)

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer2)
        url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {'annotation': 'Note'})
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'Attended or Late', r.content)

        self.att2.refresh_from_db()
        self.assertFalse(self.att2.has_signed)

    def test_rejected_absent_signing_does_not_modify_signature_or_create_auditlog(self):
        """Rejected signing for absent officer does not modify signature fields or write signing AuditLog."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        self.att1.status = 'Absent'
        self.att1.save()

        initial_audit_count = AuditLog.objects.filter(meeting=self.meeting).count()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {'annotation': 'Note'})
        self.assertEqual(r.status_code, 403)

        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)
        self.assertIsNone(self.att1.cryptographic_signature)
        self.assertIsNone(self.att1.signed_at)

        # AuditLog count should be completely unchanged
        final_audit_count = AuditLog.objects.filter(meeting=self.meeting).count()
        self.assertEqual(final_audit_count, initial_audit_count)

    def test_conditional_update_rejects_if_status_becomes_absent_before_update(self):
        """If attendance becomes Absent between initial read and database update, conditional update rejects."""
        import time
        from unittest.mock import patch
        from meetings.crypto import generate_hmac_qr_token

        self.att1.status = 'Attended'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])

        original_filter = Attendance.objects.filter

        # Simulate race condition: attendance status is changed to Absent right before conditional update
        def race_attendance_revocation(*args, **kwargs):
            if kwargs.get('has_signed') is False and kwargs.get('pk') == self.att1.pk:
                original_filter(pk=self.att1.pk).update(status='Absent')
            return original_filter(*args, **kwargs)

        with patch('meetings.views.Attendance.objects.filter', side_effect=race_attendance_revocation):
            r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {'annotation': 'Race Note'})
            self.assertEqual(r.status_code, 403)
            self.assertIn(b'Attended or Late', r.content)

        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)
        self.assertIsNone(self.att1.cryptographic_signature)

    def test_annotation_exceeding_length_limit_is_rejected(self):
        """Annotations exceeding 2000 characters are rejected with 400 Bad Request."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        self.att1.status = 'Attended'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])
        too_long_annotation = 'x' * 2001

        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': too_long_annotation,
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r.status_code, 400)
        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)
        self.assertIsNone(self.att1.cryptographic_signature)

    def test_annotation_is_immutable_once_signed(self):
        """Once signed, an attendance record cannot be signed or annotated again."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        self.att1.status = 'Attended'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])

        # Initial successful sign
        r1 = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': 'Initial comment',
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r1.status_code, 302)

        # Attempt to overwrite with new annotation
        r2 = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': 'Modified comment',
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r2.status_code, 403)

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.annotation, 'Initial comment')

    def test_ineligible_officer_cannot_sign_or_annotate(self):
        """Unassigned officers cannot submit annotations or signatures."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)

        self.client.force_login(self.unassigned_officer)
        url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={timestamp}&sig={sig}", {
            'annotation': 'Unauthorized comment',
            't': timestamp,
            'sig': sig,
        })
        self.assertEqual(r.status_code, 403)

    # 6. Meeting Content Immutability
    def test_attendance_and_annotation_do_not_alter_meeting_content(self):
        """Neither attendance updates nor officer annotations modify the meeting title, minutes content, or department."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        original_title = self.meeting.title
        original_minutes = self.meeting.minutes_content
        original_dept = self.meeting.department

        # 1. Update attendance
        self.client.force_login(self.ap)
        self.client.post(reverse('update_attendance_status', args=[self.meeting.id, self.att1.id]), {'status': 'Attended'})

        # 2. Sign with annotation
        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)
        self.client.force_login(self.officer1)
        self.client.post(f"{reverse('sign_meeting', args=[self.meeting.id])}?t={timestamp}&sig={sig}", {
            'annotation': 'My remarks',
            't': timestamp,
            'sig': sig,
        })

        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.title, original_title)
        self.assertEqual(self.meeting.minutes_content, original_minutes)
        self.assertEqual(self.meeting.department, original_dept)
        self.assertEqual(self.meeting.status, 'Finished')

    # 7. Signature Validity Preserved After Attendance Status Change
    def test_signature_remains_valid_if_attendance_status_changes(self):
        """Because the ECDSA signing payload binds meeting content and annotation (not attendance status),
        subsequent attendance status changes do not invalidate previously verified signatures."""
        import time
        from meetings.crypto import generate_hmac_qr_token, verify_document_signature
        from meetings.views import _build_signing_payload

        # Mark officer as Late so they can sign
        self.att1.status = 'Late'
        self.att1.save()

        timestamp = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, timestamp)
        self.client.force_login(self.officer1)
        self.client.post(f"{reverse('sign_meeting', args=[self.meeting.id])}?t={timestamp}&sig={sig}", {
            'annotation': 'Important endorsement',
            't': timestamp,
            'sig': sig,
        })

        self.att1.refresh_from_db()
        payload = _build_signing_payload(self.meeting, 'Important endorsement')
        self.assertTrue(verify_document_signature(self.officer1.public_key, payload, self.att1.cryptographic_signature))

        # AP marks attendance status as Attended
        self.client.force_login(self.ap)
        self.client.post(reverse('update_attendance_status', args=[self.meeting.id, self.att1.id]), {'status': 'Attended'})

        # Verification still succeeds
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertTrue(verify_document_signature(self.officer1.public_key, payload, self.att1.cryptographic_signature))



class Batch07QRAttendanceAndSigningTests(TestCase):
    """Targeted tests for Batch 07: QR Attendance, QR Signing, token lifecycle, and purpose separation."""

    def setUp(self):
        signature_storage(self)
        from meetings.crypto import generate_ecdsa_keypair, encrypt_private_key

        self.dept = Department.objects.create(name='Dept 07', contact_email='dept07@example.com')
        self.other_dept = Department.objects.create(name='Other Dept 07', contact_email='other07@example.com')

        # Authorized Personnel for Dept 07
        self.ap = User.objects.create_user(username='ap_user_07', password='pw')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')

        # Authorized Personnel for Other Dept
        self.other_ap = User.objects.create_user(username='other_ap_07', password='pw')
        Membership.objects.create(user=self.other_ap, department=self.other_dept, role='AP')

        # Global Admin
        self.admin = User.objects.create_user(username='admin_user_07', password='pw', is_admin=True)

        # Assigned Officer 1 in Dept 07
        self.officer1 = User.objects.create_user(username='officer1_07', password='pw')
        Membership.objects.create(user=self.officer1, department=self.dept, role='O')
        priv1, pub1 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer1.pk).update(
            private_key=encrypt_private_key(priv1), public_key=pub1
        )
        self.officer1.refresh_from_db()

        # Assigned Officer 2 in Dept 07
        self.officer2 = User.objects.create_user(username='officer2_07', password='pw')
        Membership.objects.create(user=self.officer2, department=self.dept, role='O')
        priv2, pub2 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer2.pk).update(
            private_key=encrypt_private_key(priv2), public_key=pub2
        )
        self.officer2.refresh_from_db()

        # Unassigned Officer in Dept 07
        self.unassigned_officer = User.objects.create_user(username='unassigned_07', password='pw')
        Membership.objects.create(user=self.unassigned_officer, department=self.dept, role='O')

        # Officer in Other Dept
        self.other_officer = User.objects.create_user(username='other_officer_07', password='pw')
        Membership.objects.create(user=self.other_officer, department=self.other_dept, role='O')
        complete_onboarding(self.ap, self.other_ap, self.officer1, self.officer2,
                            self.unassigned_officer, self.other_officer)

        # Finished Meeting in Dept 07
        self.meeting = Meeting.objects.create(
            department=self.dept,
            title='Executive Council Meeting 07',
            minutes_content='Finalized minutes content for meeting 07.',
            status='Finished',
        )

        # Draft Meeting in Dept 07
        self.draft_meeting = Meeting.objects.create(
            department=self.dept,
            title='Draft Council Meeting 07',
            minutes_content='Draft notes.',
            status='Draft',
        )

        # Assigned Attendance records on Finished meeting
        self.att1 = Attendance.objects.create(
            meeting=self.meeting,
            user=self.officer1,
            status='Absent',
        )
        self.att2 = Attendance.objects.create(
            meeting=self.meeting,
            user=self.officer2,
            status='Absent',
        )

        # Assigned Attendance on Draft meeting
        self.draft_att1 = Attendance.objects.create(
            meeting=self.draft_meeting,
            user=self.officer1,
            status='Absent',
        )

    def _assert_stale_qr_authorization_rejected(self, purpose, change):
        from datetime import timedelta
        from unittest.mock import patch
        from django.utils import timezone
        from meetings.attendance_integrity import lock_mutable_meetings
        from meetings.crypto import generate_qr_session_token

        if purpose == 'signing':
            Attendance.objects.filter(pk=self.att1.pk).update(status='Attended')
        session = QRSession.objects.create(
            meeting=self.meeting, purpose=purpose, created_by=self.ap,
            token=generate_qr_session_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.client.force_login(self.officer1)
        before = list(Attendance.objects.order_by('pk').values())
        audit_count = AuditLog.objects.count()
        usage_count = QRUsage.objects.count()

        def change_after_guard(meeting_ids):
            lock_mutable_meetings(meeting_ids)
            # Deterministically change persisted authorization after the initial
            # validation. This is an interleaving simulation, not a concurrency test.
            sessions = QRSession.objects.filter(pk=session.pk)
            if change == 'revoked':
                sessions.update(is_revoked=True)
            elif change == 'expired':
                sessions.update(expires_at=timezone.now() - timedelta(seconds=1))
            elif change == 'deleted':
                sessions.delete()
            elif change == 'purpose':
                sessions.update(purpose='attendance' if purpose == 'signing' else 'signing')

        route = 'sign_meeting' if purpose == 'signing' else 'scan_attendance_qr'
        url = reverse(route, args=[self.meeting.pk]) + f'?token={session.token}'
        with patch('meetings.views.lock_mutable_meetings', side_effect=change_after_guard) as guard:
            if purpose == 'signing':
                response = self.client.post(url, {'annotation': 'Must not be saved'})
            else:
                response = self.client.post(url)
        guard.assert_called_once_with([self.meeting.pk])
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, {
            'revoked': 'revoked', 'expired': 'expired',
            'deleted': 'Invalid QR code', 'purpose': 'cannot be used',
        }[change], status_code=403)
        self.assertEqual(list(Attendance.objects.order_by('pk').values()), before)
        self.assertEqual(QRUsage.objects.count(), usage_count)
        self.assertEqual(AuditLog.objects.count(), audit_count)

    def test_signing_qr_revoked_after_initial_validation(self):
        self._assert_stale_qr_authorization_rejected('signing', 'revoked')

    def test_signing_qr_expired_after_initial_validation(self):
        self._assert_stale_qr_authorization_rejected('signing', 'expired')

    def test_attendance_qr_revoked_after_initial_validation(self):
        self._assert_stale_qr_authorization_rejected('attendance', 'revoked')

    def test_attendance_qr_expired_after_initial_validation(self):
        self._assert_stale_qr_authorization_rejected('attendance', 'expired')

    def test_qr_deleted_or_purpose_changed_after_initial_validation(self):
        for purpose in ('signing', 'attendance'):
            for change in ('deleted', 'purpose'):
                with self.subTest(purpose=purpose, change=change):
                    self._assert_stale_qr_authorization_rejected(purpose, change)

    def test_hmac_expires_at_final_authorization_boundary(self):
        import time
        from unittest.mock import patch
        from meetings.attendance_integrity import lock_mutable_meetings
        from meetings.crypto import generate_hmac_qr_token

        self.client.force_login(self.officer1)
        for purpose, token_purpose in (('signing', None), ('signing', 'signing'),
                                       ('attendance', 'attendance')):
            with self.subTest(purpose=purpose, token_purpose=token_purpose):
                Attendance.objects.filter(pk=self.att1.pk).update(
                    status='Attended' if purpose == 'signing' else 'Absent')
                before = list(Attendance.objects.order_by('pk').values())
                timestamp = str(int(time.time()))
                token = generate_hmac_qr_token(self.meeting.pk, timestamp, purpose=token_purpose)
                route = 'sign_meeting' if purpose == 'signing' else 'scan_attendance_qr'
                url = reverse(route, args=[self.meeting.pk]) + f'?t={timestamp}&sig={token}'

                with patch('time.time', return_value=int(timestamp)) as clock:
                    def expire_after_guard(meeting_ids):
                        lock_mutable_meetings(meeting_ids)
                        clock.return_value = int(timestamp) + 3601

                    with patch('meetings.views.lock_mutable_meetings', side_effect=expire_after_guard) as guard:
                        if purpose == 'signing':
                            response = self.client.post(url, {'annotation': 'Must not be saved'})
                        else:
                            response = self.client.post(url)
                guard.assert_called_once_with([self.meeting.pk])
                self.assertContains(response, 'Invalid or expired QR code', status_code=403)
                self.assertEqual(list(Attendance.objects.order_by('pk').values()), before)
                self.assertFalse(QRUsage.objects.exists())
                self.assertFalse(AuditLog.objects.exists())

    # 1. QR Generation & Authorization
    def test_ap_can_generate_attendance_qr_for_own_department(self):
        """AP can generate an Attendance QR code for a meeting in their department."""
        self.client.force_login(self.ap)
        url = reverse('generate_attendance_qr', args=[self.meeting.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 302)

        session = QRSession.objects.filter(meeting=self.meeting, purpose='attendance').first()
        self.assertIsNotNone(session)
        self.assertEqual(session.created_by, self.ap)
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_revoked)

        # AuditLog recorded
        audit = AuditLog.objects.filter(meeting=self.meeting, user=self.ap).last()
        self.assertIn('Generated Attendance QR', audit.action)

    def test_ap_can_generate_signing_qr_for_finished_meeting(self):
        """AP can generate a Signing QR code for a Finished meeting in their department."""
        self.client.force_login(self.ap)
        url = reverse('generate_signing_qr', args=[self.meeting.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 302)

        session = QRSession.objects.filter(meeting=self.meeting, purpose='signing').first()
        self.assertIsNotNone(session)
        self.assertEqual(session.purpose, 'signing')
        self.assertTrue(session.is_active)

        # AuditLog recorded
        audit = AuditLog.objects.filter(meeting=self.meeting, user=self.ap).last()
        self.assertIn('Generated Signing QR', audit.action)

    def test_signing_qr_blocked_on_draft_meeting(self):
        """Signing QR code cannot be generated for a Draft meeting (returns 403)."""
        self.client.force_login(self.ap)
        url = reverse('generate_signing_qr', args=[self.draft_meeting.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertFalse(QRSession.objects.filter(meeting=self.draft_meeting, purpose='signing').exists())

    def test_attendance_qr_allowed_on_draft_meeting(self):
        """Attendance QR code can be generated for a Draft meeting."""
        self.client.force_login(self.ap)
        url = reverse('generate_attendance_qr', args=[self.draft_meeting.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(QRSession.objects.filter(meeting=self.draft_meeting, purpose='attendance').exists())

    def test_other_dept_ap_cannot_generate_qr(self):
        """AP from another department cannot generate QR codes (returns 403)."""
        self.client.force_login(self.other_ap)
        # Attendance QR
        r1 = self.client.post(reverse('generate_attendance_qr', args=[self.meeting.id]))
        self.assertEqual(r1.status_code, 403)
        # Signing QR
        r2 = self.client.post(reverse('generate_signing_qr', args=[self.meeting.id]))
        self.assertEqual(r2.status_code, 403)

    def test_global_admin_can_generate_qr_across_departments(self):
        """Global Admin can generate QR codes for any department's meeting."""
        self.client.force_login(self.admin)
        r = self.client.post(reverse('generate_attendance_qr', args=[self.meeting.id]))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(QRSession.objects.filter(meeting=self.meeting, purpose='attendance').exists())

    def test_officer_cannot_generate_qr(self):
        """Officers cannot access QR generation endpoints (returns 403)."""
        self.client.force_login(self.officer1)
        r1 = self.client.post(reverse('generate_attendance_qr', args=[self.meeting.id]))
        self.assertEqual(r1.status_code, 403)
        r2 = self.client.post(reverse('generate_signing_qr', args=[self.meeting.id]))
        self.assertEqual(r2.status_code, 403)

    # 2. QR Display & Revocation
    def test_ap_can_view_qr_session(self):
        """AP can view QR session details and target scan link."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )
        self.client.force_login(self.ap)
        url = reverse('view_qr_session', args=[self.meeting.id, session.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Attendance')
        self.assertContains(r, session.token)
        self.assertContains(r, 'data:image/png;base64,')
        self.assertContains(r, 'data:image/png;base64,')

    def test_ap_can_revoke_qr_session(self):
        """AP can revoke an active QR session via POST, making it unusable."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )
        self.client.force_login(self.ap)
        url = reverse('revoke_qr_session', args=[self.meeting.id, session.id])

        # GET is rejected with 405 Method Not Allowed
        r_get = self.client.get(url)
        self.assertEqual(r_get.status_code, 405)

        # POST revokes session
        r_post = self.client.post(url)
        self.assertEqual(r_post.status_code, 302)

        session.refresh_from_db()
        self.assertTrue(session.is_revoked)
        self.assertFalse(session.is_active)
        self.assertIsNotNone(session.revoked_at)
        self.assertEqual(session.revoked_by, self.ap)

        # AuditLog recorded
        audit = AuditLog.objects.filter(meeting=self.meeting, user=self.ap).last()
        self.assertIn('Revoked', audit.action)

    def test_officer_cannot_revoke_qr_session(self):
        """Officers cannot revoke QR sessions (returns 403)."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )
        self.client.force_login(self.officer1)
        url = reverse('revoke_qr_session', args=[self.meeting.id, session.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        session.refresh_from_db()
        self.assertFalse(session.is_revoked)

    # 3. QR Attendance Workflow
    def test_assigned_officer_records_attendance_via_qr(self):
        """Assigned Officer scans valid Attendance QR code; status becomes Attended with timestamp."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Attendance Recorded')

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertIsNotNone(self.att1.status_updated_at)

        # QRUsage recorded
        self.assertTrue(QRUsage.objects.filter(qr_session=session, user=self.officer1).exists())

        # AuditLog recorded without sensitive secrets
        audit = AuditLog.objects.filter(meeting=self.meeting, user=self.officer1).last()
        self.assertIsNotNone(audit)
        self.assertIn('Recorded attendance via QR as Attended', audit.action)
        self.assertNotIn(session.token, audit.action)

    def test_unassigned_officer_cannot_record_qr_attendance(self):
        """Unassigned Officer attempting to scan attendance QR receives 403."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.unassigned_officer)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'not an assigned participant', r.content)

    def test_other_dept_officer_cannot_record_qr_attendance(self):
        """Officer from another department receives 403."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.other_officer)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'do not belong to this department', r.content)

    def test_expired_attendance_qr_rejected(self):
        """Expired Attendance QR token is rejected with 403."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        # Expired in past
        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() - datetime.timedelta(seconds=60),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'expired', r.content)

    def test_revoked_attendance_qr_rejected(self):
        """Revoked Attendance QR token is rejected with 403."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
            is_revoked=True,
            revoked_at=timezone.now(),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'revoked', r.content)

    def test_invalid_or_missing_token_rejected(self):
        """Missing or tampered QR token is rejected with 403."""
        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        # Missing
        r1 = self.client.post(url)
        self.assertEqual(r1.status_code, 403)
        # Tampered
        r2 = self.client.post(f"{url}?token=completely_fake_token_123")
        self.assertEqual(r2.status_code, 403)

    def test_repeated_attendance_scan_does_not_duplicate_event_or_audit(self):
        """Repeated scan by same officer does not create duplicate record or duplicate audit event."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])

        # 1st scan -> fresh recording
        r1 = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r1.status_code, 200)
        audit_count_after_first = AuditLog.objects.filter(meeting=self.meeting).count()

        # 2nd scan -> already recorded notification
        r2 = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r2.status_code, 200)
        self.assertContains(r2, 'already recorded')

        # Audit count remains identical
        self.assertEqual(AuditLog.objects.filter(meeting=self.meeting).count(), audit_count_after_first)

    def test_qr_attendance_cannot_overwrite_signed_attendance(self):
        """An officer who already signed the document cannot have their attendance modified via QR."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Attended'
        self.att1.has_signed = True
        self.att1.cryptographic_signature = 'deadbeefcafe'
        self.att1.signed_at = timezone.now()
        self.att1.save()

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?token={session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'already digitally signed', r.content)

        # Signature remains unchanged
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.cryptographic_signature, 'deadbeefcafe')
        self.assertTrue(self.att1.has_signed)

    def test_multiple_assigned_officers_can_scan_same_qr_session(self):
        """Multiple officers can scan the same attendance QR code; one scan does not invalidate the session."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        # Officer 1 scans
        self.client.force_login(self.officer1)
        r1 = self.client.post(f"{reverse('scan_attendance_qr', args=[self.meeting.id])}?token={session.token}")
        self.assertEqual(r1.status_code, 200)

        # Officer 2 scans with same token
        self.client.force_login(self.officer2)
        r2 = self.client.post(f"{reverse('scan_attendance_qr', args=[self.meeting.id])}?token={session.token}")
        self.assertEqual(r2.status_code, 200)

        self.att1.refresh_from_db()
        self.att2.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertEqual(self.att2.status, 'Attended')
        self.assertEqual(QRUsage.objects.filter(qr_session=session).count(), 2)

    # 4. Purpose Separation
    def test_attendance_token_cannot_authorize_signing(self):
        """An Attendance QR token cannot be used to sign a document (returns 403)."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Attended'
        self.att1.save()

        att_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        # Attempt to access signing page with attendance token
        r_get = self.client.get(f"{reverse('sign_meeting', args=[self.meeting.id])}?token={att_session.token}")
        self.assertEqual(r_get.status_code, 403)
        self.assertIn(b'Attendance QR tokens cannot be used for signing', r_get.content)

        # Attempt to post signature with attendance token
        r_post = self.client.post(f"{reverse('sign_meeting', args=[self.meeting.id])}?token={att_session.token}", {
            'annotation': 'Malicious attempt',
            'token': att_session.token,
        })
        self.assertEqual(r_post.status_code, 403)
        self.assertIn(b'Attendance QR tokens cannot be used for signing', r_post.content)

        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)

    def test_signing_token_cannot_record_attendance(self):
        """A Signing QR token cannot be used to record attendance (returns 403)."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        r = self.client.post(f"{reverse('scan_attendance_qr', args=[self.meeting.id])}?token={sig_session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'Signing QR tokens cannot be used to record attendance', r.content)

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    # 5. QR Signing Workflow
    def test_eligible_attended_officer_signs_with_qr_token(self):
        """Eligible officer marked Attended scans Signing QR and completes ECDSA signature."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token, verify_document_signature
        from meetings.views import _build_signing_payload

        self.att1.status = 'Attended'
        self.att1.status_updated_at = timezone.now()
        self.att1.save()

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        sign_url = reverse('sign_meeting', args=[self.meeting.id])

        # GET signing page with token
        r_get = self.client.get(f"{sign_url}?token={sig_session.token}")
        self.assertEqual(r_get.status_code, 200)
        self.assertContains(r_get, 'Submit Digital Signature')

        # POST signature with annotation
        annotation_text = 'Approved and concurred via QR signing.'
        r_post = self.client.post(f"{sign_url}?token={sig_session.token}", {
            'annotation': annotation_text,
            'token': sig_session.token,
        })
        self.assertEqual(r_post.status_code, 302)

        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertEqual(self.att1.annotation, annotation_text)
        self.assertIsNotNone(self.att1.cryptographic_signature)

        # Cryptographically verify signature
        payload = _build_signing_payload(self.meeting, annotation_text)
        self.assertTrue(
            verify_document_signature(
                self.officer1.public_key,
                payload,
                self.att1.cryptographic_signature,
            )
        )

        # QRUsage recorded
        self.assertTrue(QRUsage.objects.filter(qr_session=sig_session, user=self.officer1).exists())

    def test_eligible_late_officer_signs_with_qr_token(self):
        """Eligible officer marked Late can sign with Signing QR token."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Late'
        self.att1.status_updated_at = timezone.now()
        self.att1.save()

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        sign_url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.post(f"{sign_url}?token={sig_session.token}", {
            'annotation': 'Late attendance remarks',
            'token': sig_session.token,
        })
        self.assertEqual(r.status_code, 302)
        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)

    def test_absent_officer_cannot_sign_with_qr_token(self):
        """Absent Officer receives HTTP 403 when attempting to sign via QR."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Absent'
        self.att1.save()

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        sign_url = reverse('sign_meeting', args=[self.meeting.id])
        r_get = self.client.get(f"{sign_url}?token={sig_session.token}")
        self.assertEqual(r_get.status_code, 403)
        self.assertIn(b'Attended or Late', r_get.content)

        r_post = self.client.post(f"{sign_url}?token={sig_session.token}", {
            'annotation': 'Attempt',
            'token': sig_session.token,
        })
        self.assertEqual(r_post.status_code, 403)
        self.att1.refresh_from_db()
        self.assertFalse(self.att1.has_signed)

    def test_revoked_signing_qr_rejected(self):
        """Revoked Signing QR token is rejected with 403."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Attended'
        self.att1.save()

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
            is_revoked=True,
            revoked_at=timezone.now(),
        )

        self.client.force_login(self.officer1)
        sign_url = reverse('sign_meeting', args=[self.meeting.id])
        r = self.client.get(f"{sign_url}?token={sig_session.token}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'revoked', r.content)

    def test_multiple_officers_can_sign_with_same_signing_qr(self):
        """Multiple assigned, attended officers can each sign using the same Signing QR session."""
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        self.att1.status = 'Attended'
        self.att1.save()
        self.att2.status = 'Attended'
        self.att2.save()

        sig_session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='signing',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        sign_url = reverse('sign_meeting', args=[self.meeting.id])

        # Officer 1 signs
        self.client.force_login(self.officer1)
        r1 = self.client.post(f"{sign_url}?token={sig_session.token}", {
            'annotation': 'Officer 1 remarks',
            'token': sig_session.token,
        })
        self.assertEqual(r1.status_code, 302)

        # Officer 2 signs with same token
        self.client.force_login(self.officer2)
        r2 = self.client.post(f"{sign_url}?token={sig_session.token}", {
            'annotation': 'Officer 2 remarks',
            'token': sig_session.token,
        })
        self.assertEqual(r2.status_code, 302)

        self.att1.refresh_from_db()
        self.att2.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertTrue(self.att2.has_signed)
        self.assertEqual(QRUsage.objects.filter(qr_session=sig_session).count(), 2)

    def test_projector_qr_view_generates_and_displays_signing_qr_session(self):
        """AP accessing projector_qr_view generates/retrieves active signing QRSession and renders it."""
        self.client.force_login(self.ap)
        url = reverse('projector_qr_view', args=[self.meeting.id])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'meetings/qr_projector.html')
        self.assertContains(r, 'Digital Signing QR')

        session = QRSession.objects.filter(meeting=self.meeting, purpose='signing').first()
        self.assertIsNotNone(session)
        self.assertContains(r, session.token)

    # 6. HMAC Purpose-Separation Tests (Targeted Security Correction)
    def test_hmac_attendance_purpose_token_accepted_for_attendance(self):
        """Valid HMAC token with attendance purpose is accepted to record attendance."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, ts, purpose='attendance')

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={ts}&sig={sig}&purpose=attendance")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Attendance Recorded')

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertIsNotNone(self.att1.status_updated_at)

    def test_hmac_signing_purpose_token_rejected_for_attendance(self):
        """HMAC token with signing purpose is rejected by attendance scanning (returns 403)."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, ts, purpose='signing')

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])

        # With explicit purpose=signing param
        r1 = self.client.post(f"{url}?t={ts}&sig={sig}&purpose=signing")
        self.assertEqual(r1.status_code, 403)
        self.assertIn(b'Signing QR tokens cannot be used to record attendance', r1.content)

        # Without purpose param (sig mismatch against attendance purpose)
        r2 = self.client.post(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r2.status_code, 403)
        self.assertIn(b'Invalid or expired QR code', r2.content)

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    def test_hmac_purposeless_legacy_token_rejected_for_attendance(self):
        """Purpose-less legacy HMAC signing token is rejected by attendance scanning (returns 403)."""
        import time
        from meetings.crypto import generate_hmac_qr_token

        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, ts)

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])
        r = self.client.post(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b'Invalid or expired QR code', r.content)

        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Absent')

    def test_hmac_purposeless_legacy_token_accepted_for_signing_workflow(self):
        """Purpose-less legacy HMAC token from Batch 05 remains accepted by the signing path,
        subject to meeting-status, assignment, and attendance requirements."""
        import time
        from django.utils import timezone
        from meetings.crypto import generate_hmac_qr_token

        self.att1.status = 'Attended'
        self.att1.status_updated_at = timezone.now()
        self.att1.save()

        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(self.meeting.id, ts)

        self.client.force_login(self.officer1)
        url = reverse('sign_meeting', args=[self.meeting.id])

        # GET signing page succeeds with legacy purpose-less token
        r_get = self.client.get(f"{url}?t={ts}&sig={sig}")
        self.assertEqual(r_get.status_code, 200)
        self.assertContains(r_get, 'Submit Digital Signature')

        # POST signature succeeds with legacy purpose-less token
        r_post = self.client.post(f"{url}?t={ts}&sig={sig}", {
            'annotation': 'Signed via legacy purpose-less HMAC token',
            't': ts,
            'sig': sig,
        })
        self.assertEqual(r_post.status_code, 302)

        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertEqual(self.att1.annotation, 'Signed via legacy purpose-less HMAC token')
        self.assertIsNotNone(self.att1.cryptographic_signature)

    # 7. Concurrency Regression Tests (Batch 07 Fix)
    def test_concurrent_duplicate_attendance_scan_race_prevention(self):
        """Regression test for F2/F9: Two competing scans by the same Officer cannot both succeed.

        Simulates a race condition where Request 1 has passed pre-flight checks and entered
        scan_attendance_qr, but before its QRUsage record is written, a concurrent Request 2
        completes the scan entirely (recording attendance, QRUsage, and AuditLog).

        Demonstrates that:
          1. The losing request detects existing QRUsage and sets already_recorded=True.
          2. No duplicate QRUsage row is created (unique_together enforced).
          3. No duplicate AuditLog row is created (exactly 1 audit event for this scan).
          4. Attendance remains Attended with unchanged status_updated_at.
          5. Response returns 200 with 'already recorded' message.
        """
        from unittest.mock import patch
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])

        original_get_or_create = QRUsage.objects.get_or_create

        def simulate_race_get_or_create(*args, **kwargs):
            # Concurrent Request 2 wins the race immediately before Request 1's get_or_create:
            # 1. Create the unique QRUsage row
            original_get_or_create(*args, **kwargs)
            # 2. Update attendance
            Attendance.objects.filter(pk=self.att1.pk, has_signed=False).update(
                status='Attended',
                status_updated_at=timezone.now(),
            )
            # 3. Create the single legitimate AuditLog entry
            AuditLog.objects.create(
                department=self.meeting.department,
                meeting=self.meeting,
                user=self.officer1,
                action="Recorded attendance via QR as Attended"
            )
            # Now Request 1 executes its get_or_create: it finds the existing row and returns (obj, False)
            return original_get_or_create(*args, **kwargs)

        with patch('meetings.views.QRUsage.objects.get_or_create', side_effect=simulate_race_get_or_create):
            r = self.client.post(f"{url}?token={session.token}")
            self.assertEqual(r.status_code, 200)
            self.assertContains(r, 'already recorded')

        # Assertions on database consistency:
        # Exactly one QRUsage record exists for this officer and QR session
        self.assertEqual(QRUsage.objects.filter(qr_session=session, user=self.officer1).count(), 1)

        # Exactly one AuditLog entry exists for this attendance scan (no duplicate log!)
        audit_entries = AuditLog.objects.filter(
            meeting=self.meeting,
            user=self.officer1,
            action="Recorded attendance via QR as Attended"
        )
        self.assertEqual(audit_entries.count(), 1)

        # Attendance remains consistent and unsigned
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Attended')
        self.assertFalse(self.att1.has_signed)

    def test_concurrent_attendance_scan_integrity_error_handled_safely(self):
        """Regression test for F2/F9: Low-level database IntegrityError from concurrent INSERT
        is safely caught and rendered as an already_recorded response without duplicating state."""
        from unittest.mock import patch
        from django.db import IntegrityError
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])

        # Simulate concurrent request completing scan first
        QRUsage.objects.create(qr_session=session, user=self.officer1)
        self.att1.status = 'Attended'
        self.att1.status_updated_at = timezone.now()
        self.att1.save()
        AuditLog.objects.create(
            department=self.meeting.department,
            meeting=self.meeting,
            user=self.officer1,
            action="Recorded attendance via QR as Attended"
        )
        initial_audit_count = AuditLog.objects.filter(meeting=self.meeting, user=self.officer1).count()

        # When competing request raises IntegrityError on race
        with patch('meetings.views.QRUsage.objects.get_or_create', side_effect=IntegrityError("UNIQUE constraint failed")):
            r = self.client.post(f"{url}?token={session.token}")
            self.assertEqual(r.status_code, 200)
            self.assertContains(r, 'already recorded')

        # No duplicate QRUsage or AuditLog created
        self.assertEqual(QRUsage.objects.filter(qr_session=session, user=self.officer1).count(), 1)
        self.assertEqual(AuditLog.objects.filter(meeting=self.meeting, user=self.officer1).count(), initial_audit_count)

    def test_concurrent_digital_signing_blocks_attendance_scan_and_preserves_signature(self):
        """Regression test for F2/F9: If an Officer signs concurrently between the pre-flight check
        and the atomic database update, scan_attendance_qr aborts, rolls back, returns 403,
        and does NOT overwrite the cryptographic signature or annotation."""
        from unittest.mock import patch
        from django.utils import timezone
        import datetime
        from meetings.crypto import generate_qr_session_token

        session = QRSession.objects.create(
            meeting=self.meeting,
            purpose='attendance',
            token=generate_qr_session_token(),
            created_by=self.ap,
            expires_at=timezone.now() + datetime.timedelta(seconds=3600),
        )

        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.id])

        original_filter = Attendance.objects.filter

        def simulate_concurrent_signing(*args, **kwargs):
            if kwargs.get('has_signed') is False and kwargs.get('pk') == self.att1.pk:
                # Concurrent request completes signing right before conditional attendance update
                original_filter(pk=self.att1.pk).update(
                    has_signed=True,
                    cryptographic_signature='concurrent_winner_ecdsa_sig',
                    annotation='Signed concurrently during attendance scan',
                    signed_at=timezone.now(),
                )
            return original_filter(*args, **kwargs)

        with patch('meetings.views.Attendance.objects.filter', side_effect=simulate_concurrent_signing):
            r = self.client.post(f"{url}?token={session.token}")
            self.assertEqual(r.status_code, 403)
            self.assertIn(b'already digitally signed', r.content)

        # Signature, annotation, and signed_at are strictly preserved
        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertEqual(self.att1.cryptographic_signature, 'concurrent_winner_ecdsa_sig')
        self.assertEqual(self.att1.annotation, 'Signed concurrently during attendance scan')

        # No QRUsage or attendance audit log was committed (transaction rolled back)
        self.assertFalse(QRUsage.objects.filter(qr_session=session, user=self.officer1).exists())
        self.assertFalse(
            AuditLog.objects.filter(
                meeting=self.meeting,
                user=self.officer1,
                action="Recorded attendance via QR as Attended"
            ).exists()
        )



class Batch09ArchivalAuditTests(TestCase):
    def setUp(self):
        self.department = Department.objects.create(name='Archival audit')
        self.meeting = Meeting.objects.create(
            department=self.department, title='Archive test', status='Finished'
        )

    def test_archive_logs_once_with_system_metadata(self):
        self.meeting.status = 'Archived'
        self.meeting.save(update_fields=['status', 'updated_at'])
        event = AuditLog.objects.get(meeting=self.meeting)
        self.assertEqual(event.event_type, 'meeting.archived')
        self.assertEqual(event.action, 'Archived document')
        self.assertIsNone(event.user)
        self.assertEqual(event.metadata['source'], 'system')
        self.assertEqual(event.metadata['reason'], 'No request actor available')
        self.assertEqual(event.metadata['meeting_id'], self.meeting.pk)
        self.meeting.save()
        self.assertEqual(AuditLog.objects.filter(meeting=self.meeting).count(), 1)

    def test_stale_instance_uses_persisted_previous_state(self):
        stale = Meeting.objects.get(pk=self.meeting.pk)
        self.meeting.status = 'Archived'
        self.meeting.save()
        stale.status = 'Archived'
        stale.save()
        self.assertEqual(AuditLog.objects.filter(meeting=self.meeting).count(), 1)

    def test_draft_archive_rejected_without_event(self):
        from django.core.exceptions import ValidationError

        draft = Meeting.objects.create(department=self.department, title='Draft')
        draft.status = 'Archived'
        with self.assertRaises(ValidationError):
            draft.save()
        draft.refresh_from_db()
        self.assertEqual(draft.status, 'Draft')
        self.assertFalse(AuditLog.objects.exists())

    def test_ordinary_save_and_excluded_status_do_not_log(self):
        self.meeting.save()
        self.meeting.status = 'Archived'
        self.meeting.save(update_fields=['updated_at'])
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.status, 'Finished')
        self.assertFalse(AuditLog.objects.exists())

    def test_audit_failure_rolls_back_archive(self):
        from unittest.mock import patch
        from django.db.models.query import QuerySet

        self.meeting.status = 'Archived'
        with patch.object(QuerySet, 'create', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):
                self.meeting.save()
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.status, 'Finished')
        self.assertFalse(AuditLog.objects.exists())

    def test_creation_in_archived_state_is_not_a_transition(self):
        Meeting.objects.create(department=self.department, title='Existing archive', status='Archived')
        self.assertFalse(AuditLog.objects.exists())

    def test_outer_rollback_removes_archive_and_event(self):
        from django.db import transaction

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.meeting.status = 'Archived'
                self.meeting.save()
                raise RuntimeError('outer rollback')
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.status, 'Finished')
        self.assertFalse(AuditLog.objects.exists())

    def test_legacy_defaults_remain_readable_and_independent(self):
        first = AuditLog.objects.create(
            department=self.department, meeting=self.meeting, action='Old event'
        )
        second = AuditLog.objects.create(
            department=self.department, meeting=self.meeting, action='Other old event'
        )
        self.assertEqual(first.event_type, 'legacy')
        first.metadata['source'] = 'system'
        self.assertEqual(second.metadata, {})


class Batch08VerificationQRTests(TestCase):
    """Batch 08: Individual Signature Verification QR System Tests.

    Validates individual proof-of-signature QR generation, secure token storage,
    token decryption for owner display, regeneration/invalidation, revocation,
    database UniqueConstraint for one active QR per Attendance,
    public read-only single-signature verification without authentication,
    privacy guarantees (generic responses on revoked/unsupported tokens,
    no leakage of other attendees, full minutes, or annotations),
    cryptographic signature integrity (canonical vs legacy), tampering detection,
    and strict isolation from Batch 07 attendance/signing sessions.
    """

    def setUp(self):
        signature_storage(self)
        from django.utils import timezone
        from meetings.crypto import (
            generate_ecdsa_keypair,
            encrypt_private_key,
            sign_document_data,
            build_canonical_signing_payload,
            build_legacy_signing_payload,
        )

        self.client = Client()
        self.dept = Department.objects.create(name='Computer Science', contact_email='cs@example.com')
        self.other_dept = Department.objects.create(name='Mathematics', contact_email='math@example.com')

        # Global Admin
        self.global_admin = User.objects.create_user(
            username='admin_batch08', password='password123', is_admin=True
        )

        # Department APs
        self.ap_cs = User.objects.create_user(username='ap_cs_user', password='password123')
        Membership.objects.create(user=self.ap_cs, department=self.dept, role='AP')

        self.ap_math = User.objects.create_user(username='ap_math_user', password='password123')
        Membership.objects.create(user=self.ap_math, department=self.other_dept, role='AP')

        # Officers
        # Officer 1: Signed with canonical meeting-bound signature
        self.officer1 = User.objects.create_user(
            username='officer1_cs', first_name='Alice', last_name='Smith', password='password123'
        )
        Membership.objects.create(user=self.officer1, department=self.dept, role='O')
        priv1, pub1 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer1.pk).update(
            private_key=encrypt_private_key(priv1), public_key=pub1
        )
        self.officer1.refresh_from_db()
        self.priv1_raw = priv1

        # Officer 2: Signed with legacy signature (not meeting-bound)
        self.officer2 = User.objects.create_user(
            username='officer2_cs', first_name='Bob', last_name='Jones', password='password123'
        )
        Membership.objects.create(user=self.officer2, department=self.dept, role='O')
        priv2, pub2 = generate_ecdsa_keypair()
        User.objects.filter(pk=self.officer2.pk).update(
            private_key=encrypt_private_key(priv2), public_key=pub2
        )
        self.officer2.refresh_from_db()
        self.priv2_raw = priv2

        # Officer 3: Assigned participant who has NOT signed yet
        self.officer3 = User.objects.create_user(
            username='officer3_cs', first_name='Charlie', last_name='Brown', password='password123'
        )
        Membership.objects.create(user=self.officer3, department=self.dept, role='O')

        # Officer from another department
        self.officer_math = User.objects.create_user(username='officer_math', password='password123')
        Membership.objects.create(user=self.officer_math, department=self.other_dept, role='O')
        complete_onboarding(self.ap_cs, self.ap_math, self.officer1, self.officer2,
                            self.officer3, self.officer_math)

        # Finalized Meeting (Finished)
        self.finished_meeting = Meeting.objects.create(
            department=self.dept,
            title='Curriculum Committee Final Meeting',
            minutes_content='Finalized minutes: Approved new AI curriculum syllabus.',
            status='Draft'
        )
        self.finished_meeting.status = 'Finished'
        self.finished_meeting.save()

        # Archived Meeting (transitions Draft -> Finished -> Archived)
        self.archived_meeting = Meeting.objects.create(
            department=self.dept,
            title='Archived Annual Report Meeting',
            minutes_content='Annual report archived content.',
            status='Draft'
        )
        self.archived_meeting.status = 'Finished'
        self.archived_meeting.save()
        self.archived_meeting.status = 'Archived'
        self.archived_meeting.save()

        # Draft Meeting
        self.draft_meeting = Meeting.objects.create(
            department=self.dept,
            title='Draft Curriculum Brainstorming',
            minutes_content='Draft notes: Discussion ongoing.',
            status='Draft'
        )

        time_now = timezone.now()

        # Attendee 1: Canonical signature on Finished meeting
        self.ann1 = "Approved curriculum revisions."
        canonical_payload = build_canonical_signing_payload(
            self.finished_meeting.id,
            self.dept.id,
            self.finished_meeting.title,
            self.finished_meeting.minutes_content,
            self.ann1,
        )
        sig1 = sign_document_data(self.officer1.private_key, canonical_payload)
        self.att1 = Attendance.objects.create(
            meeting=self.finished_meeting,
            user=self.officer1,
            status='Attended',
            has_signed=True,
            cryptographic_signature=sig1,
            annotation=self.ann1,
            signed_at=time_now
        )

        # Attendee 2: Legacy signature on Finished meeting
        self.ann2 = "Legacy note agreement."
        legacy_payload = build_legacy_signing_payload(
            self.finished_meeting.minutes_content,
            self.ann2,
        )
        sig2 = sign_document_data(self.officer2.private_key, legacy_payload)
        self.att2 = Attendance.objects.create(
            meeting=self.finished_meeting,
            user=self.officer2,
            status='Late',
            has_signed=True,
            cryptographic_signature=sig2,
            annotation=self.ann2,
            signed_at=time_now
        )

        # Attendee 3: Unsigned on Finished meeting
        self.att3 = Attendance.objects.create(
            meeting=self.finished_meeting,
            user=self.officer3,
            status='Attended',
            has_signed=False,
            cryptographic_signature=None,
            annotation='',
            signed_at=None
        )

        # Attendee 1 on Archived meeting (signed)
        canonical_payload_arch = build_canonical_signing_payload(
            self.archived_meeting.id,
            self.dept.id,
            self.archived_meeting.title,
            self.archived_meeting.minutes_content,
            '',
        )
        sig1_arch = sign_document_data(self.officer1.private_key, canonical_payload_arch)
        self.att1_arch = Attendance.objects.create(
            meeting=self.archived_meeting,
            user=self.officer1,
            status='Attended',
            has_signed=True,
            cryptographic_signature=sig1_arch,
            annotation='',
            signed_at=time_now
        )

        # Attendee 1 on Draft meeting
        self.att1_draft = Attendance.objects.create(
            meeting=self.draft_meeting,
            user=self.officer1,
            status='Attended',
            has_signed=True,
            cryptographic_signature='abc123',
            annotation='',
            signed_at=time_now
        )

    def _privacy_verification_url(self, attendance):
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token
        self.client.force_login(attendance.user)
        response = self.client.post(reverse('my_signature_verification_qr', args=[attendance.meeting_id]))
        self.assertEqual(response.status_code, 302)
        qr = VerificationQR.objects.get(attendance=attendance, is_revoked=False)
        return reverse('verify_individual_signature') + '?token=' + decrypt_verification_token(qr.encrypted_token)

    def test_public_signer_names_are_private_for_valid_and_invalid_signatures(self):
        names = (('Alice', 'Smith', 'Alice Smith'), ('Alice', '', 'Alice'),
                 ('', 'Smith', 'Smith'), ('', '', 'Name not provided'),
                 ('  \t', '\n  ', 'Name not provided'))
        anonymous = Client()
        for attendance, legacy in ((self.att1, False), (self.att2, True), (self.att1_arch, False)):
            url = self._privacy_verification_url(attendance)
            original_signature = attendance.cryptographic_signature
            username = f'PRIVATE_SIGNER_USERNAME_NEVER_PUBLIC_{attendance.user_id}'
            for valid in (True, False):
                Attendance.objects.filter(pk=attendance.pk).update(
                    cryptographic_signature=original_signature if valid else 'invalid-signature')
                for first, last, expected in names:
                    with self.subTest(meeting=attendance.meeting.status, legacy=legacy,
                                      valid=valid, first=first, last=last):
                        User.objects.filter(pk=attendance.user_id).update(
                            username=username, first_name=first, last_name=last)
                        response = anonymous.get(url)
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.context['signer_display'], expected)
                        self.assertNotIn(username, response.context['signer_display'])
                        self.assertContains(response, expected)
                        self.assertNotContains(response, username)
                        self.assertEqual(response.context['status'], 'valid' if valid else 'invalid')
                        self.assertEqual(response.context['sig_result']['valid'], valid)
                        if valid:
                            self.assertEqual(response.context['sig_result']['is_legacy'], legacy)
                            self.assertEqual(response.context['sig_result']['meeting_bound'], not legacy)

    def test_missing_name_unknown_and_revoked_tokens_stay_generic(self):
        username = 'PRIVATE_MISSING_NAME_SIGNER_USERNAME'
        User.objects.filter(pk=self.officer1.pk).update(username=username, first_name='', last_name='')
        url = self._privacy_verification_url(self.att1)
        self.client.post(reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.pk]))
        anonymous = Client()
        for target, expected_status in ((url, 200),
                (reverse('verify_individual_signature') + '?token=unknown-privacy-token', 404)):
            response = anonymous.get(target)
            self.assertEqual(response.status_code, expected_status)
            self.assertIsNone(response.context.get('signer_display'))
            self.assertNotContains(response, username, status_code=expected_status)
            self.assertNotContains(response, 'Name not provided', status_code=expected_status)
            self.assertNotContains(response, self.finished_meeting.title, status_code=expected_status)

    def test_01_signed_officer_can_generate_own_qr(self):
        """1. A signed Officer can generate their own personal verification QR via POST."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        resp = self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp.status_code, 302)

        # Follow redirect to display page
        resp_get = self.client.get(resp.url)
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn('qr_image_b64', resp_get.context)
        self.assertIsNotNone(resp_get.context['qr_image_b64'])
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 1)

    def test_02_unsigned_officer_cannot_generate_qr(self):
        """2. An unsigned Officer cannot generate a verification QR (403 Forbidden)."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer3)
        resp_get = self.client.get(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp_get.status_code, 403)

        resp_post = self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp_post.status_code, 403)

        self.assertEqual(VerificationQR.objects.filter(attendance=self.att3).count(), 0)

    def test_03_officer_cannot_access_another_officers_qr(self):
        """3. An Officer cannot access another Officer's verification QR (URL is scoped to user)."""
        from meetings.models import VerificationQR

        # Officer 1 generates QR
        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 1)

        # Officer 2 logs in and requests the endpoint
        self.client.force_login(self.officer2)
        resp = self.client.get(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp.status_code, 200)
        # Context must contain Officer 2's attendance, NOT Officer 1's
        self.assertEqual(resp.context['attendance'], self.att2)
        self.assertNotEqual(resp.context['attendance'], self.att1)

    def test_04_qr_tied_to_exactly_one_attendance(self):
        """4. VerificationQR is tied to exactly one Attendance record and resolves meeting/signer."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)

        self.assertEqual(qr.attendance, self.att1)
        self.assertEqual(qr.meeting, self.finished_meeting)
        self.assertEqual(qr.signer, self.officer1)

    def test_05_get_does_not_create_or_modify_qr_records(self):
        """5. GET requests are strictly read-only and never create or modify QR records."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        # Officer 1 has signed, but has not generated QR
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 0)

        # GET request
        resp = self.client.get(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.context['verification_qr'])
        self.assertIsNone(resp.context['qr_image_b64'])

        # DB must still have 0 records
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 0)

    def test_06_post_generates_qr(self):
        """6. POST explicitly generates the verification QR."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        resp = self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp.status_code, 302)

        qr = VerificationQR.objects.filter(attendance=self.att1).first()
        self.assertIsNotNone(qr)
        self.assertFalse(qr.is_revoked)
        raw_token = decrypt_verification_token(qr.encrypted_token)
        self.assertTrue(bool(raw_token))

    def test_07_regeneration_revokes_previous_qr_and_creates_new_one(self):
        """7. Regeneration invalidates previous active QR and creates a new one."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        # First POST generates QR 1
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr1 = VerificationQR.objects.get(attendance=self.att1)
        token1 = decrypt_verification_token(qr1.encrypted_token)

        # Second POST regenerates QR 2
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        all_qrs = VerificationQR.objects.filter(attendance=self.att1)
        self.assertEqual(all_qrs.count(), 2)

        old_qr = all_qrs.get(is_revoked=True)
        new_qr = all_qrs.get(is_revoked=False)
        self.assertEqual(old_qr.id, qr1.id)
        token2 = decrypt_verification_token(new_qr.encrypted_token)
        self.assertNotEqual(token1, token2)

    def test_08_unique_active_qr_constraint(self):
        """8. Database UniqueConstraint prevents multiple active QR records for one Attendance."""
        from django.db import IntegrityError
        from meetings.models import VerificationQR
        from meetings.crypto import hash_verification_token, encrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1, is_revoked=False).count(), 1)

        # Direct DB attempt to create a second non-revoked QR for the same attendance must fail
        with self.assertRaises(IntegrityError):
            VerificationQR.objects.create(
                attendance=self.att1,
                token_hash=hash_verification_token('another_secret_token_123'),
                encrypted_token=encrypt_verification_token('another_secret_token_123'),
                is_revoked=False,
            )

    def test_09_only_signing_officer_can_revoke_their_qr(self):
        """9. Only the signing Officer can revoke their own QR."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        self.assertFalse(qr.is_revoked)

        # Officer 2 attempts to revoke Officer 1's QR (Officer 2's session only has Officer 2's attendance)
        self.client.force_login(self.officer2)
        resp_o2 = self.client.post(reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.id]))
        # Officer 2 has no active QR, so redirects with info message without touching Officer 1's QR
        qr.refresh_from_db()
        self.assertFalse(qr.is_revoked)

        # Officer 1 revokes their own QR
        self.client.force_login(self.officer1)
        resp_o1 = self.client.post(reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp_o1.status_code, 302)
        qr.refresh_from_db()
        self.assertTrue(qr.is_revoked)
        self.assertEqual(qr.revoked_by, self.officer1)

    def test_10_revoking_qr_does_not_affect_underlying_signature(self):
        """10. Revoking a QR does not delete or modify the Attendance cryptographic signature."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.client.post(reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.id]))

        self.att1.refresh_from_db()
        self.assertTrue(self.att1.has_signed)
        self.assertIsNotNone(self.att1.cryptographic_signature)
        self.assertIsNotNone(self.att1.signed_at)

    def test_11_draft_meetings_cannot_generate_verification_qr(self):
        """11. Draft meetings cannot generate or view verification QR codes."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        resp_get = self.client.get(reverse('my_signature_verification_qr', args=[self.draft_meeting.id]))
        self.assertEqual(resp_get.status_code, 403)

        resp_post = self.client.post(reverse('my_signature_verification_qr', args=[self.draft_meeting.id]))
        self.assertEqual(resp_post.status_code, 403)
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1_draft).count(), 0)

    def test_12_finished_and_archived_meetings_are_supported(self):
        """12. Both Finished and Archived meetings are supported."""
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        # Finished
        resp_fin = self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        self.assertEqual(resp_fin.status_code, 302)
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 1)

        # Archived
        resp_arch = self.client.post(reverse('my_signature_verification_qr', args=[self.archived_meeting.id]))
        self.assertEqual(resp_arch.status_code, 302)
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1_arch).count(), 1)

    def test_13_unknown_and_revoked_tokens_produce_safe_generic_responses(self):
        """13. Unknown and revoked tokens return generic responses without leaking meeting or signer info."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        # 1. Unknown token -> 404, generic error
        anon = Client()
        resp_unk = anon.get(f"{reverse('verify_individual_signature')}?token=non_existent_token_999")
        self.assertEqual(resp_unk.status_code, 404)
        self.assertEqual(resp_unk.context['status'], 'invalid')
        self.assertNotIn('Alice Smith', resp_unk.content.decode('utf-8'))
        self.assertNotIn(self.finished_meeting.title, resp_unk.content.decode('utf-8'))

        # 2. Revoked token -> 200, generic revoked status, NO meeting title or signer exposed!
        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        raw_token = decrypt_verification_token(qr.encrypted_token)
        self.client.post(reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.id]))

        resp_rev = anon.get(f"{reverse('verify_individual_signature')}?token={raw_token}")
        self.assertEqual(resp_rev.status_code, 200)
        self.assertEqual(resp_rev.context['status'], 'revoked')
        content_rev = resp_rev.content.decode('utf-8')
        self.assertIn('Verification QR Code Revoked', content_rev)
        self.assertNotIn('Alice Smith', content_rev)
        self.assertNotIn(self.finished_meeting.title, content_rev)

    def test_14_unsupported_meeting_statuses_do_not_expose_info(self):
        """14. Unsupported meeting statuses do not expose meeting or signer information."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        raw_token = decrypt_verification_token(qr.encrypted_token)

        # Simulate meeting transition to unsupported status
        Meeting.objects.filter(pk=self.finished_meeting.pk).update(status='Draft')

        anon = Client()
        resp = anon.get(f"{reverse('verify_individual_signature')}?token={raw_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['status'], 'unsupported')
        content = resp.content.decode('utf-8')
        self.assertIn('Unsupported Document Status', content)
        self.assertNotIn('Alice Smith', content)
        self.assertNotIn(self.finished_meeting.title, content)

    def test_15_valid_canonical_signatures_verify_successfully(self):
        """15. Valid canonical signatures verify successfully on the public endpoint."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        token = decrypt_verification_token(qr.encrypted_token)

        anon = Client()
        resp = anon.get(f"{reverse('verify_individual_signature')}?token={token}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['status'], 'valid')
        self.assertTrue(resp.context['sig_result']['valid'])
        self.assertTrue(resp.context['sig_result']['meeting_bound'])
        self.assertFalse(resp.context['sig_result']['is_legacy'])

        content = resp.content.decode('utf-8')
        self.assertIn('Verified (Canonical)', content)
        self.assertIn('Alice Smith', content)
        self.assertIn(self.finished_meeting.title, content)

    def test_16_valid_legacy_signatures_verify_with_clear_legacy_notice(self):
        """16. Valid legacy signatures verify with a clear legacy notice."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer2)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att2)
        token = decrypt_verification_token(qr.encrypted_token)

        anon = Client()
        resp = anon.get(f"{reverse('verify_individual_signature')}?token={token}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['status'], 'valid')
        self.assertTrue(resp.context['sig_result']['valid'])
        self.assertFalse(resp.context['sig_result']['meeting_bound'])
        self.assertTrue(resp.context['sig_result']['is_legacy'])

        content = resp.content.decode('utf-8')
        self.assertIn('Verified (Legacy)', content)
        self.assertIn('Legacy format notice', content)
        self.assertIn('Bob Jones', content)

    def test_17_tampered_signatures_or_content_produce_invalid_result(self):
        """17. Tampered signatures or document content produce an invalid verification result."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        token = decrypt_verification_token(qr.encrypted_token)

        # Alter document minutes content
        Meeting.objects.filter(pk=self.finished_meeting.pk).update(
            minutes_content="Tampered minutes text after signing."
        )

        anon = Client()
        resp = anon.get(f"{reverse('verify_individual_signature')}?token={token}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['status'], 'invalid')
        self.assertFalse(resp.context['sig_result']['valid'])
        self.assertIn('Integrity Warning: Invalid Signature', resp.content.decode('utf-8'))

    def test_18_public_verification_exposes_no_other_signers_records_or_secrets(self):
        """18. Public verification exposes no other signers, attendance records, minutes, or annotations."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        token = decrypt_verification_token(qr.encrypted_token)

        anon = Client()
        resp = anon.get(f"{reverse('verify_individual_signature')}?token={token}")
        content = resp.content.decode('utf-8')

        # Allowed fields
        self.assertIn('Alice Smith', content)
        self.assertIn(self.finished_meeting.title, content)
        self.assertIn(self.dept.name, content)

        # Forbidden fields
        self.assertNotIn('Bob Jones', content)
        self.assertNotIn('officer2_cs', content)
        self.assertNotIn('Charlie Brown', content)
        self.assertNotIn('officer3_cs', content)
        self.assertNotIn('Finalized minutes: Approved new AI curriculum syllabus.', content)
        self.assertNotIn(self.ann1, content)
        self.assertNotIn(self.ann2, content)
        self.assertNotIn(qr.token_hash, content)
        self.assertNotIn(qr.encrypted_token, content)

    def test_19_public_verification_does_not_mutate_db_or_create_logs(self):
        """19. Public verification does not create scan logs or modify database records."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        token = decrypt_verification_token(qr.encrypted_token)

        anon = Client()
        audit_before = AuditLog.objects.count()
        qr_count_before = VerificationQR.objects.count()
        att_count_before = Attendance.objects.count()

        resp = anon.get(f"{reverse('verify_individual_signature')}?token={token}")
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(AuditLog.objects.count(), audit_before)
        self.assertEqual(VerificationQR.objects.count(), qr_count_before)
        self.assertEqual(Attendance.objects.count(), att_count_before)

    def test_20_batch07_qr_attendance_and_signing_unaffected(self):
        """20. Batch 07 QR attendance and signing workflows remain unaffected."""
        from meetings.models import VerificationQR
        from meetings.crypto import decrypt_verification_token

        self.client.force_login(self.officer1)
        self.client.post(reverse('my_signature_verification_qr', args=[self.finished_meeting.id]))
        qr = VerificationQR.objects.get(attendance=self.att1)
        token = decrypt_verification_token(qr.encrypted_token)

        # Verification token rejected by Batch 07 attendance scanner
        self.client.force_login(self.officer3)
        resp_scan = self.client.post(f"{reverse('scan_attendance_qr', args=[self.finished_meeting.id])}?token={token}")
        self.assertEqual(resp_scan.status_code, 403)

        # Verification token rejected by Batch 07 signing endpoint
        resp_sign = self.client.get(f"{reverse('sign_meeting', args=[self.finished_meeting.id])}?token={token}")
        self.assertEqual(resp_sign.status_code, 403)

        # No Batch 07 records created
        self.assertEqual(QRSession.objects.filter(meeting=self.finished_meeting).count(), 0)
        self.assertEqual(QRUsage.objects.count(), 0)

    def test_21_canonical_and_legacy_signing_payload_consistency(self):
        """21. Cryptographic payload builders are deterministic and compatible with Batch 05."""
        from meetings.crypto import build_canonical_signing_payload, build_legacy_signing_payload

        p1 = build_canonical_signing_payload(1, 2, "Test Title", "Test Minutes", "Test Ann")
        expected_canonical = (
            "meeting_id:1\n"
            "department_id:2\n"
            "title:Test Title\n"
            "Test Minutes\n"
            "---ANNOTATION---\n"
            "Test Ann"
        )
        self.assertEqual(p1, expected_canonical)

        p2 = build_legacy_signing_payload("Test Minutes", "Test Ann")
        expected_legacy = (
            "Test Minutes\n"
            "---ANNOTATION---\n"
            "Test Ann"
        )
        self.assertEqual(p2, expected_legacy)

    def test_owner_qr_rejects_unsupported_methods(self):
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        url = reverse('my_signature_verification_qr', args=[self.finished_meeting.id])
        for method in ('PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            with self.subTest(method=method):
                response = self.client.generic(method, url)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response['Allow'], 'GET, POST')
        self.assertFalse(VerificationQR.objects.exists())

    def test_public_verification_rejects_unsupported_methods(self):
        url = reverse('verify_individual_signature')
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            with self.subTest(method=method):
                response = self.client.generic(method, url)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response['Allow'], 'GET')

    def test_generation_uniqueness_conflict_rolls_back_revocation(self):
        from unittest.mock import patch
        from django.db import IntegrityError
        from meetings.models import VerificationQR

        self.client.force_login(self.officer1)
        url = reverse('my_signature_verification_qr', args=[self.finished_meeting.id])
        self.client.post(url)
        qr = VerificationQR.objects.get(attendance=self.att1)
        signature = self.att1.cryptographic_signature
        signed_at = self.att1.signed_at
        with patch('meetings.views.VerificationQR.objects.create', side_effect=IntegrityError('unique conflict')):
            response = self.client.post(url)
        self.assertRedirects(response, url)
        qr.refresh_from_db()
        self.assertFalse(qr.is_revoked)
        self.assertIsNone(qr.revoked_at)
        self.assertIsNone(qr.revoked_by)
        self.assertEqual(VerificationQR.objects.filter(attendance=self.att1).count(), 1)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.cryptographic_signature, signature)
        self.assertEqual(self.att1.signed_at, signed_at)


class Batch09StructuredAuditTests(TestCase):
    setUp = Batch04DraftEditingReviewFinalizationTests.setUp

    def test_retention_and_legacy_defaults(self):
        safe_department = Department.objects.create(name='Audit retention safe department')
        event = AuditLog.objects.create(meeting=self.draft_meeting, department=safe_department,
                                        user=self.officer, action='Legacy')
        other = AuditLog(action='Another')
        event.metadata['x'] = 1
        self.assertEqual(other.metadata, {})
        event.refresh_from_db()
        self.assertEqual(event.event_type, 'legacy')
        self.assertEqual(event.metadata, {})
        self.officer.delete()
        event.refresh_from_db()
        self.assertIsNone(event.user_id)
        self.draft_meeting.delete()
        event.refresh_from_db()
        self.assertIsNone(event.meeting_id)
        safe_department.delete()
        event.refresh_from_db()
        self.assertIsNone(event.department_id)

    def test_edit_fields_and_noop(self):
        self.client.force_login(self.ap_user)
        url = reverse('edit_meeting', args=[self.draft_meeting.pk])
        data = {'title': self.draft_meeting.title, 'minutes_content': self.draft_meeting.minutes_content}
        self.client.post(url, data)
        self.assertFalse(AuditLog.objects.exists())
        data['minutes_content'] = 'Private revised minutes'
        self.client.post(url, data)
        event = AuditLog.objects.get(event_type='meeting.edited')
        self.assertEqual(event.metadata['changed_fields'], ['minutes_content'])
        self.assertNotIn(data['minutes_content'], str(event.metadata))
        self.client.post(url, data)
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_assignment_deltas_and_noop(self):
        self.client.force_login(self.ap_user)
        url = reverse('assign_participants', args=[self.draft_meeting.pk])
        self.client.post(url, {'participants': [self.officer.pk]})
        event = AuditLog.objects.get(event_type='meeting.participants_changed')
        self.assertEqual(event.metadata['added_ids'], [self.officer.pk])
        self.client.post(url, {'participants': [self.officer.pk]})
        self.assertEqual(AuditLog.objects.count(), 1)
        self.client.post(url, {'participants': []})
        self.assertEqual(AuditLog.objects.latest('pk').metadata['removed_ids'], [self.officer.pk])

    def test_creation_and_finalization(self):
        self.client.force_login(self.ap_user)
        response = self.client.post(reverse('create_meeting_dept', args=[self.dept.pk]),
                                    {'title': 'New', 'minutes_content': 'Private'})
        self.assertEqual(response.status_code, 302)
        event = AuditLog.objects.get(event_type='meeting.created')
        self.assertEqual(event.user, self.ap_user)
        url = reverse('finalize_meeting', args=[event.meeting_id])
        self.client.post(url)
        self.client.post(url)
        self.assertEqual(AuditLog.objects.filter(event_type='meeting.finalized').count(), 1)

    def test_attendance_transitions_and_noop(self):
        attendance = Attendance.objects.create(meeting=self.finished_meeting, user=self.officer)
        self.client.force_login(self.ap_user)
        url = reverse('update_attendance_status', args=[self.finished_meeting.pk, attendance.pk])
        previous = 'Absent'
        for status in ('Attended', 'Late', 'Absent'):
            self.client.post(url, {'status': status})
            event = AuditLog.objects.latest('pk')
            self.assertEqual(event.metadata['previous_status'], previous)
            self.assertEqual(event.metadata['new_status'], status)
            self.assertEqual(event.metadata['officer_id'], self.officer.pk)
            previous = status
        self.client.post(url, {'status': 'Absent'})
        self.assertEqual(AuditLog.objects.count(), 3)

    def test_audit_failure_rolls_back_manual_attendance_and_qr_generation(self):
        from unittest.mock import patch
        attendance = Attendance.objects.create(meeting=self.finished_meeting, user=self.officer)
        self.client.force_login(self.ap_user)
        with patch('meetings.views.AuditLog.objects.create', side_effect=RuntimeError('failed audit')):
            with self.assertRaises(RuntimeError):
                self.client.post(reverse('update_attendance_status', args=[self.finished_meeting.pk, attendance.pk]), {'status': 'Late'})
            with self.assertRaises(RuntimeError):
                self.client.post(reverse('generate_attendance_qr', args=[self.finished_meeting.pk]))
        attendance.refresh_from_db()
        self.assertEqual(attendance.status, 'Absent')
        self.assertFalse(QRSession.objects.exists())

    def test_history_permissions_and_methods(self):
        url = reverse('document_history', args=[self.draft_meeting.pk])
        self.assertEqual(self.client.get(url).status_code, 302)
        for user, expected in ((self.global_admin, 200), (self.ap_user, 200),
                               (self.other_ap, 403), (self.officer, 403)):
            self.client.force_login(user)
            self.assertEqual(self.client.get(url).status_code, expected)
        self.client.force_login(self.ap_user)
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            response = self.client.generic(method, url)
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response['Allow'], 'GET')

    def test_history_empty_order_pagination_and_escaping(self):
        self.client.force_login(self.ap_user)
        url = reverse('document_history', args=[self.draft_meeting.pk])
        self.assertContains(self.client.get(url), 'No document history recorded.')
        events = [AuditLog.objects.create(meeting=self.draft_meeting, department=self.dept,
                  action='<script>unsafe</script>', metadata={'source': '<b>system</b>',
                  'private_key': 'HIDDEN-SECRET'}) for i in range(26)]
        from django.utils import timezone
        AuditLog.objects.filter(pk__in=[e.pk for e in events]).update(timestamp=timezone.now())
        response = self.client.get(url)
        self.assertEqual([e.pk for e in response.context['page_obj']], [e.pk for e in reversed(events[1:])])
        self.assertContains(response, '&lt;script&gt;unsafe&lt;/script&gt;')
        self.assertContains(response, '&lt;b&gt;system&lt;/b&gt;')
        self.assertNotContains(response, 'HIDDEN-SECRET')
        self.assertEqual(len(self.client.get(url+'?page=2').context['page_obj']), 1)

    def test_audit_admin_is_readonly(self):
        from django.contrib import admin
        from django.test import RequestFactory
        model_admin = admin.site._registry[AuditLog]
        request = RequestFactory().get('/admin/')
        request.user = self.global_admin
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_change_permission(request))
        self.assertFalse(model_admin.has_delete_permission(request))
        self.assertNotIn('delete_selected', model_admin.get_actions(request))


class Batch09SignatureAndQRTests(TestCase):
    setUp = Batch08VerificationQRTests.setUp

    def test_verification_qr_events_and_conflict(self):
        from meetings.models import VerificationQR
        from unittest.mock import patch
        from django.db import IntegrityError
        self.client.force_login(self.officer1)
        url = reverse('my_signature_verification_qr', args=[self.finished_meeting.pk])
        self.client.post(url)
        first = VerificationQR.objects.get(attendance=self.att1)
        self.assertEqual(AuditLog.objects.get(event_type='verification_qr.generated').event_type, 'verification_qr.generated')
        self.client.post(url)
        event = AuditLog.objects.latest('pk')
        self.assertEqual(event.event_type, 'verification_qr.regenerated')
        self.assertEqual(event.metadata['previous_qr_id'], first.pk)
        replacement = VerificationQR.objects.get(attendance=self.att1, is_revoked=False)
        self.assertEqual(event.metadata['replacement_qr_id'], replacement.pk)
        with patch('meetings.views.VerificationQR.objects.create', side_effect=IntegrityError('conflict')):
            self.client.post(url)
        self.assertEqual(AuditLog.objects.filter(event_type__startswith='verification_qr.').count(), 2)
        replacement.refresh_from_db()
        self.assertFalse(replacement.is_revoked)
        revoke = reverse('revoke_my_signature_verification_qr', args=[self.finished_meeting.pk])
        self.client.post(revoke)
        self.client.post(revoke)
        self.assertEqual(AuditLog.objects.filter(event_type__startswith='verification_qr.').count(), 3)
        self.assertEqual(AuditLog.objects.latest('pk').event_type, 'verification_qr.revoked')
        for event in AuditLog.objects.all():
            self.assertNotIn(replacement.encrypted_token, str(event.metadata))


class Batch09SigningMetadataTests(TestCase):
    setUp = Batch06AttendanceAndAnnotationTests.setUp

    def test_signing_metadata_and_duplicate(self):
        self.client.force_login(self.officer1)
        attendance = Attendance.objects.get(meeting=self.meeting, user=self.officer1)
        attendance.status = 'Attended'
        attendance.save()
        import time
        from meetings.crypto import generate_hmac_qr_token
        timestamp = str(int(time.time()))
        token = generate_hmac_qr_token(self.meeting.pk, timestamp)
        url = reverse('sign_meeting', args=[self.meeting.pk]) + f'?t={timestamp}&sig={token}'
        response = self.client.post(url, {'annotation': 'PRIVATE ANNOTATION'})
        self.assertEqual(response.status_code, 302)
        event = AuditLog.objects.get(event_type='signature.created')
        self.assertTrue(event.metadata['annotation_included'])
        self.assertIn('signed_at', event.metadata)
        self.assertNotIn('PRIVATE ANNOTATION', str(event.metadata))
        self.client.post(url, {'annotation': 'Again'})
        self.assertEqual(AuditLog.objects.filter(event_type='signature.created').count(), 1)


class Batch09SessionAuditTests(TestCase):
    setUp = Batch07QRAttendanceAndSigningTests.setUp

    def test_session_generation_reuse_revocation_and_scan(self):
        self.client.force_login(self.ap)
        self.client.post(reverse('generate_attendance_qr', args=[self.meeting.pk]))
        session = QRSession.objects.get(purpose='attendance')
        event = AuditLog.objects.get(event_type='qr.generated')
        self.assertEqual(event.metadata['qr_session_id'], session.pk)
        self.assertEqual(event.metadata['purpose'], 'attendance')
        self.assertNotIn(session.token, str(event.metadata))
        self.client.force_login(self.officer1)
        self.client.post(reverse('scan_attendance_qr', args=[self.meeting.pk]), {'token': session.token})
        event = AuditLog.objects.get(event_type='attendance.changed')
        self.assertEqual(event.metadata['method'], 'qr')
        self.assertEqual(event.metadata['previous_status'], 'Absent')
        self.assertEqual(event.metadata['new_status'], 'Attended')
        self.client.force_login(self.ap)
        revoke = reverse('revoke_qr_session', args=[self.meeting.pk, session.pk])
        self.client.post(revoke)
        self.client.post(revoke)
        self.assertEqual(AuditLog.objects.filter(event_type='qr.revoked').count(), 1)
        self.client.post(reverse('projector_qr_view', args=[self.meeting.pk]))
        self.client.post(reverse('projector_qr_view', args=[self.meeting.pk]))
        self.assertEqual(AuditLog.objects.filter(event_type='qr.generated').count(), 2)


class QRRequestMethodTests(TestCase):
    setUp = Batch07QRAttendanceAndSigningTests.setUp

    def test_scan_get_rejects_invalid_authorization_without_changes(self):
        from datetime import timedelta
        from django.utils import timezone
        self.client.force_login(self.officer1)
        url = reverse('scan_attendance_qr', args=[self.meeting.pk])
        before = list(Attendance.objects.values())
        for state in ('invalid', 'expired', 'revoked', 'purpose', 'unassigned', 'department', 'archived', 'signed'):
            with self.subTest(state=state):
                session = QRSession.objects.create(meeting=self.meeting, purpose='signing' if state == 'purpose' else 'attendance',
                    token=state, created_by=self.ap, is_revoked=state == 'revoked',
                    expires_at=timezone.now() + timedelta(hours=-1 if state == 'expired' else 1))
                user = self.unassigned_officer if state == 'unassigned' else self.other_officer if state == 'department' else self.officer1
                self.client.force_login(user)
                if state == 'archived':
                    Meeting.objects.filter(pk=self.meeting.pk).update(status='Archived')
                if state == 'signed':
                    Attendance.objects.filter(pk=self.att1.pk).update(has_signed=True)
                snapshot = list(Attendance.objects.values())
                self.assertEqual(self.client.get(url, {'token': 'missing' if state == 'invalid' else session.token}).status_code, 403)
                self.assertEqual(list(Attendance.objects.values()), snapshot)
                self.assertFalse(QRUsage.objects.exists())
                self.assertFalse(AuditLog.objects.exists())
                Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished')
                Attendance.objects.filter(pk=self.att1.pk).update(has_signed=False)
        self.assertEqual(list(Attendance.objects.values()), before)

    def test_generation_get_is_read_only_and_projector_post_reuses(self):
        from unittest.mock import patch
        self.client.force_login(self.ap)
        with patch('meetings.views.lock_mutable_meetings', side_effect=AssertionError('GET write guard')):
            for route in ('generate_attendance_qr', 'generate_signing_qr'):
                self.assertEqual(self.client.get(reverse(route, args=[self.meeting.pk])).status_code, 405)
            url = reverse('projector_qr_view', args=[self.meeting.pk])
            self.assertContains(self.client.get(url), 'Generate Signing QR')
        self.assertFalse(QRSession.objects.exists())
        self.assertFalse(AuditLog.objects.exists())
        self.assertEqual(self.client.post(url).status_code, 200)
        session = QRSession.objects.get()
        events = list(AuditLog.objects.values())
        for method in (self.client.get, self.client.post, self.client.get):
            self.assertContains(method(url), session.token)
            self.assertEqual(QRSession.objects.count(), 1)
            self.assertEqual(list(AuditLog.objects.values()), events)

    def test_scan_get_confirmation_and_csrf_post_for_session_and_hmac(self):
        from datetime import timedelta
        import time
        from django.test import Client
        from django.utils import timezone
        from meetings.crypto import generate_hmac_qr_token
        from unittest.mock import patch

        session = QRSession.objects.create(meeting=self.meeting, purpose='attendance',
            token='confirmation-token', created_by=self.ap,
            expires_at=timezone.now() + timedelta(hours=1))
        timestamp = str(int(time.time()))
        variants = ({'token': session.token}, {'t': timestamp, 'purpose': 'attendance',
            'sig': generate_hmac_qr_token(self.meeting.pk, timestamp, purpose='attendance')})
        for user, params in zip((self.officer1, self.officer2), variants):
            with self.subTest(params=params):
                client = Client(enforce_csrf_checks=True)
                client.force_login(user)
                url = reverse('scan_attendance_qr', args=[self.meeting.pk])
                before = list(Attendance.objects.values())
                usages = QRUsage.objects.count()
                audits = AuditLog.objects.count()
                with patch('meetings.views.lock_mutable_meetings', side_effect=AssertionError('GET write guard')):
                    response = client.get(url, params)
                self.assertContains(response, 'Confirm attendance')
                self.assertEqual(list(Attendance.objects.values()), before)
                self.assertEqual(client.post(url, params).status_code, 403)
                self.assertEqual(list(Attendance.objects.values()), before)
                self.assertEqual(QRUsage.objects.count(), usages)
                self.assertEqual(AuditLog.objects.count(), audits)
                params = {**params, 'csrfmiddlewaretoken': client.cookies['csrftoken'].value}
                self.assertEqual(client.post(url, params).status_code, 200)
                self.assertEqual(Attendance.objects.get(meeting=self.meeting, user=user).status, 'Attended')

    def test_generation_posts_require_csrf(self):
        from django.test import Client
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.ap)
        client.get(reverse('projector_qr_view', args=[self.meeting.pk]))
        for route in ('generate_attendance_qr', 'generate_signing_qr', 'projector_qr_view'):
            with self.subTest(route=route):
                url = reverse(route, args=[self.meeting.pk])
                sessions = QRSession.objects.count()
                audits = AuditLog.objects.count()
                self.assertEqual(client.post(url).status_code, 403)
                self.assertEqual(QRSession.objects.count(), sessions)
                self.assertEqual(AuditLog.objects.count(), audits)
                response = client.post(url, {'csrfmiddlewaretoken': client.cookies['csrftoken'].value})
                self.assertEqual(response.status_code, 200 if route == 'projector_qr_view' else 302)

    def test_scan_audit_failure_rolls_back(self):
        from datetime import timedelta
        from django.utils import timezone
        from unittest.mock import patch
        session = QRSession.objects.create(meeting=self.meeting, purpose='attendance',
            token='rollback-token', created_by=self.ap,
            expires_at=timezone.now() + timedelta(hours=1))
        self.client.force_login(self.officer1)
        before = list(Attendance.objects.values())
        with patch('meetings.views.AuditLog.objects.create', side_effect=RuntimeError('audit failure')):
            with self.assertRaises(RuntimeError):
                self.client.post(reverse('scan_attendance_qr', args=[self.meeting.pk]), {'token': session.token})
        self.assertEqual(list(Attendance.objects.values()), before)
        self.assertFalse(QRUsage.objects.exists())
        self.assertFalse(AuditLog.objects.exists())


class QRGenerationLifecycleTests(TestCase):
    setUp = Batch07QRAttendanceAndSigningTests.setUp
    routes = ('projector_qr_view', 'generate_attendance_qr', 'generate_signing_qr')

    def test_lifecycle_changes_before_guard_reject_without_generation(self):
        from unittest.mock import patch
        from meetings.attendance_integrity import lock_mutable_meetings

        self.client.force_login(self.ap)
        for route in self.routes:
            # Draft also exercises the fresh Finished check after a successful guard.
            statuses = ('Archived',) if route == 'generate_attendance_qr' else ('Archived', 'Draft')
            for status in statuses:
                with self.subTest(route=route, status=status):
                    Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished')

                    def change_then_guard(meeting_ids):
                        Meeting.objects.filter(pk=self.meeting.pk).update(status=status)
                        lock_mutable_meetings(meeting_ids)

                    with patch('meetings.views.lock_mutable_meetings', side_effect=change_then_guard) as guard:
                        response = self.client.post(reverse(route, args=[self.meeting.pk]))
                    guard.assert_called_once_with([self.meeting.pk])
                    self.assertEqual(response.status_code, 403)
                    self.assertFalse(QRSession.objects.exists())
                    self.assertFalse(AuditLog.objects.filter(event_type='qr.generated').exists())

    def test_projector_reuse_revalidates_lifecycle_before_lookup(self):
        from unittest.mock import patch
        from meetings.attendance_integrity import lock_mutable_meetings

        self.client.force_login(self.ap)
        url = reverse('projector_qr_view', args=[self.meeting.pk])
        self.assertEqual(self.client.post(url).status_code, 200)
        sessions = list(QRSession.objects.values())
        audits = list(AuditLog.objects.values())
        for status in ('Archived', 'Draft'):
            with self.subTest(status=status):
                Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished')

                def change_then_guard(meeting_ids):
                    Meeting.objects.filter(pk=self.meeting.pk).update(status=status)
                    lock_mutable_meetings(meeting_ids)

                with patch('meetings.views.lock_mutable_meetings', side_effect=change_then_guard), patch(
                    'meetings.views.QRSession.objects.filter', side_effect=AssertionError('premature lookup')
                ):
                    self.assertEqual(self.client.post(url).status_code, 403)
                self.assertEqual(list(QRSession.objects.values()), sessions)
                self.assertEqual(list(AuditLog.objects.values()), audits)

    def test_archived_rejected_including_existing_projector_session(self):
        self.client.force_login(self.ap)
        self.client.post(reverse('projector_qr_view', args=[self.meeting.pk]))
        sessions = list(QRSession.objects.values())
        audits = list(AuditLog.objects.values())
        Meeting.objects.filter(pk=self.meeting.pk).update(status='Archived')
        for route in self.routes:
            with self.subTest(route=route):
                self.assertEqual(self.client.post(reverse(route, args=[self.meeting.pk])).status_code, 403)
                self.assertEqual(list(QRSession.objects.values()), sessions)
                self.assertEqual(list(AuditLog.objects.values()), audits)

    def test_signing_and_projector_audit_failure_rolls_back_session(self):
        from unittest.mock import patch

        self.client.force_login(self.ap)
        for route in ('generate_signing_qr', 'projector_qr_view'):
            with self.subTest(route=route):
                with patch('meetings.views.AuditLog.objects.create', side_effect=RuntimeError('audit failure')):
                    with self.assertRaises(RuntimeError):
                        self.client.post(reverse(route, args=[self.meeting.pk]))
                self.assertFalse(QRSession.objects.exists())
                self.assertFalse(AuditLog.objects.exists())

    def test_guard_and_fresh_status_precede_session_and_audit_operations(self):
        from unittest.mock import patch
        from meetings.attendance_integrity import lock_mutable_meetings

        self.client.force_login(self.ap)
        original_refresh = Meeting.refresh_from_db
        original_filter = QRSession.objects.filter
        original_create = QRSession.objects.create
        original_audit = AuditLog.objects.create
        for route in self.routes:
            with self.subTest(route=route):
                events = []

                def guard(meeting_ids):
                    lock_mutable_meetings(meeting_ids)
                    events.append('guard')

                def refresh(instance, *args, **kwargs):
                    result = original_refresh(instance, *args, **kwargs)
                    events.append('refresh')
                    return result

                def lookup(*args, **kwargs):
                    self.assertEqual(events[:2], ['guard', 'refresh'])
                    events.append('lookup')
                    return original_filter(*args, **kwargs)

                def create(*args, **kwargs):
                    self.assertEqual(events[:2], ['guard', 'refresh'])
                    events.append('create')
                    return original_create(*args, **kwargs)

                def audit(*args, **kwargs):
                    self.assertIn('create', events)
                    events.append('audit')
                    return original_audit(*args, **kwargs)

                with patch('meetings.views.lock_mutable_meetings', side_effect=guard), patch.object(
                    Meeting, 'refresh_from_db', refresh
                ), patch('meetings.views.QRSession.objects.filter', side_effect=lookup), patch(
                    'meetings.views.QRSession.objects.create', side_effect=create
                ), patch('meetings.views.AuditLog.objects.create', side_effect=audit):
                    response = self.client.post(reverse(route, args=[self.meeting.pk]))
                self.assertEqual(response.status_code, 200 if route == 'projector_qr_view' else 302)
                self.assertEqual(events[-2:], ['create', 'audit'])
                if route == 'projector_qr_view':
                    self.assertEqual(events, ['guard', 'refresh', 'lookup', 'create', 'audit'])


class Batch09MeetingAdminAuditTests(TestCase):
    def test_meeting_admin_and_attendance_admin_events(self):
        from django.contrib import admin
        from django.test import RequestFactory
        from types import SimpleNamespace
        department = Department.objects.create(name='Admin audit')
        actor = User.objects.create_user(username='admin_audit_actor', is_admin=True)
        officer = User.objects.create_user(username='admin_audit_officer')
        request = RequestFactory().post('/admin/')
        request.user = actor
        form = SimpleNamespace(changed_data=['title'])
        meeting = Meeting(department=department, title='Initial')
        model_admin = admin.site._registry[Meeting]
        model_admin.save_model(request, meeting, form, False)
        self.assertEqual(AuditLog.objects.get(event_type='meeting.created').user, actor)
        meeting.title = 'Changed'
        model_admin.save_model(request, meeting, form, True)
        model_admin.save_model(request, meeting, form, True)
        self.assertEqual(AuditLog.objects.filter(event_type='meeting.edited').count(), 1)
        attendance = Attendance.objects.create(meeting=meeting, user=officer)
        attendance.status = 'Late'
        admin.site._registry[Attendance].save_model(request, attendance, form, True)
        event = AuditLog.objects.get(event_type='attendance.changed')
        self.assertEqual(event.metadata['previous_status'], 'Absent')
        self.assertEqual(event.metadata['new_status'], 'Late')
        self.assertEqual(event.user, actor)


    def test_audit_admin_queryset_scopes_ap_and_officer(self):
        from django.contrib import admin
        from django.test import RequestFactory
        department = Department.objects.create(name='Scoped admin department')
        other = Department.objects.create(name='Other admin department')
        actor = User.objects.create_user(username='scoped_admin_actor')
        Membership.objects.create(user=actor, department=department, role='AP')
        own = AuditLog.objects.create(department=department, action='Own department')
        AuditLog.objects.create(department=other, action='Other department')
        request = RequestFactory().get('/admin/')
        request.user = actor
        model_admin = admin.site._registry[AuditLog]
        self.assertEqual(list(model_admin.get_queryset(request)), [own])
        self.assertNotIn('department', model_admin.get_list_filter(request))
        Membership.objects.filter(user=actor).update(role='O')
        self.assertFalse(model_admin.get_queryset(request).exists())


class Batch09AuditCorrectionAdminTests(TestCase):
    def setUp(self):
        from django.contrib import admin
        from django.test import RequestFactory
        from types import SimpleNamespace
        self.department = Department.objects.create(name='Corrections')
        self.other_department = Department.objects.create(name='Other corrections')
        self.actor = User.objects.create_user(username='correction_admin')
        self.officer = User.objects.create_user(username='correction_officer')
        self.other_officer = User.objects.create_user(username='other_correction_officer')
        self.meeting = Meeting.objects.create(department=self.department, title='First')
        self.other_meeting = Meeting.objects.create(department=self.other_department, title='Second')
        self.request = RequestFactory().post('/admin/')
        self.request.user = self.actor
        self.form = SimpleNamespace(changed_data=[])
        self.model_admin = admin.site._registry[Attendance]

    def test_creation_and_noop(self):
        attendance = Attendance(meeting=self.meeting, user=self.officer)
        self.model_admin.save_model(self.request, attendance, self.form, False)
        event = AuditLog.objects.get()
        self.assertEqual(event.event_type, 'attendance.created')
        self.assertEqual(event.user, self.actor)
        self.assertEqual(event.target_id, str(attendance.pk))
        self.assertEqual(event.meeting, self.meeting)
        self.assertEqual(event.department, self.department)
        self.assertIsNone(event.metadata['previous_officer_id'])
        self.assertEqual(event.metadata['new_officer_id'], self.officer.pk)
        self.model_admin.save_model(self.request, attendance, self.form, True)
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_reassignment_and_status_are_one_event(self):
        attendance = Attendance.objects.create(meeting=self.meeting, user=self.officer)
        attendance.meeting = self.other_meeting
        attendance.user = self.other_officer
        attendance.status = 'Late'
        self.model_admin.save_model(self.request, attendance, self.form, True)
        event = AuditLog.objects.get()
        self.assertEqual(event.event_type, 'attendance.reassigned')
        self.assertEqual(event.user, self.actor)
        self.assertEqual(event.meeting, self.other_meeting)
        for key, expected in {'previous_meeting_id': self.meeting.pk,
                              'new_meeting_id': self.other_meeting.pk,
                              'previous_officer_id': self.officer.pk,
                              'new_officer_id': self.other_officer.pk,
                              'previous_department_id': self.department.pk,
                              'new_department_id': self.other_department.pk,
                              'previous_status': 'Absent', 'new_status': 'Late'}.items():
            self.assertEqual(event.metadata[key], expected)

    def test_delete_and_repeated_delete(self):
        attendance = Attendance.objects.create(meeting=self.meeting, user=self.officer)
        self.model_admin.delete_model(self.request, attendance)
        self.model_admin.delete_model(self.request, attendance)
        event = AuditLog.objects.get()
        self.assertEqual(event.event_type, 'attendance.deleted')
        self.assertEqual(event.metadata['previous_officer_id'], self.officer.pk)
        self.assertIsNone(event.metadata['new_officer_id'])
        self.assertEqual(event.user, self.actor)
        self.assertFalse(Attendance.objects.exists())

    def test_bulk_delete_logs_each_record(self):
        for user in (self.officer, self.other_officer):
            Attendance.objects.create(meeting=self.meeting, user=user)
        self.model_admin.delete_queryset(self.request, Attendance.objects.all())
        self.assertEqual(AuditLog.objects.filter(event_type='attendance.deleted').count(), 2)
        self.assertFalse(Attendance.objects.exists())

    def test_failure_rolls_back_create_reassign_and_delete(self):
        from unittest.mock import patch
        attendance = Attendance.objects.create(meeting=self.meeting, user=self.officer)
        with patch('meetings.admin.AuditLog.objects.create', side_effect=RuntimeError('audit failure')):
            with self.assertRaises(RuntimeError):
                self.model_admin.save_model(self.request, Attendance(meeting=self.meeting, user=self.other_officer), self.form, False)
            attendance.user = self.other_officer
            with self.assertRaises(RuntimeError):
                self.model_admin.save_model(self.request, attendance, self.form, True)
            with self.assertRaises(RuntimeError):
                self.model_admin.delete_queryset(self.request, Attendance.objects.all())
        attendance.refresh_from_db()
        self.assertEqual(attendance.user, self.officer)
        self.assertEqual(Attendance.objects.count(), 1)
        self.assertFalse(AuditLog.objects.exists())

    def test_duplicate_assignment_fails_without_event(self):
        from django.db import IntegrityError, transaction
        Attendance.objects.create(meeting=self.meeting, user=self.officer)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.model_admin.save_model(self.request, Attendance(meeting=self.meeting, user=self.officer), self.form, False)
        self.assertFalse(AuditLog.objects.exists())

    def test_department_only_edit_and_noop(self):
        from django.contrib import admin
        self.meeting.department = self.other_department
        model_admin = admin.site._registry[Meeting]
        model_admin.save_model(self.request, self.meeting, self.form, True)
        model_admin.save_model(self.request, self.meeting, self.form, True)
        event = AuditLog.objects.get()
        self.assertEqual(event.metadata['changed_fields'], ['department'])
        self.assertEqual(event.metadata['previous_department_id'], self.department.pk)
        self.assertEqual(event.metadata['new_department_id'], self.other_department.pk)
        self.assertEqual(event.user, self.actor)
        self.assertEqual(event.meeting, self.meeting)


class Batch09QRCorrectionTests(TestCase):
    setUp = Batch07QRAttendanceAndSigningTests.setUp

    def scan(self):
        from meetings.crypto import generate_qr_session_token
        from django.utils import timezone
        import datetime
        session = QRSession.objects.create(meeting=self.meeting, purpose='attendance',
            token=generate_qr_session_token(), created_by=self.ap,
            expires_at=timezone.now()+datetime.timedelta(hours=1))
        self.client.force_login(self.officer1)
        return reverse('scan_attendance_qr', args=[self.meeting.pk])+'?token='+session.token

    def test_fresh_persisted_status_and_duplicate(self):
        Attendance.objects.filter(pk=self.att1.pk).update(status='Late', status_updated_at=None)
        url = self.scan()
        self.assertEqual(self.client.post(url).status_code, 200)
        event = AuditLog.objects.get(event_type='attendance.changed')
        self.assertEqual(event.metadata['previous_status'], 'Late')
        self.assertEqual(event.metadata['new_status'], 'Attended')
        self.client.post(url)
        self.assertEqual(AuditLog.objects.filter(event_type='attendance.changed').count(), 1)

    def test_concurrent_status_change_is_not_overwritten(self):
        from unittest.mock import patch
        from django.utils import timezone
        original_filter = Attendance.objects.filter
        def concurrent_change(*args, **kwargs):
            if 'status_updated_at' in kwargs and kwargs.get('has_signed') is False:
                original_filter(pk=self.att1.pk).update(status='Late', status_updated_at=timezone.now())
            return original_filter(*args, **kwargs)
        url = self.scan()
        with patch('meetings.views.Attendance.objects.filter', side_effect=concurrent_change):
            self.assertEqual(self.client.post(url).status_code, 403)
        self.att1.refresh_from_db()
        self.assertEqual(self.att1.status, 'Late')
        self.assertFalse(AuditLog.objects.exists())
        self.assertFalse(QRUsage.objects.exists())

    def test_signed_attendance_rejected_without_event(self):
        url = self.scan()
        Attendance.objects.filter(pk=self.att1.pk).update(has_signed=True)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.assertFalse(AuditLog.objects.exists())
        self.assertFalse(QRUsage.objects.exists())


class Batch10PDFTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.dept = Department.objects.create(name='PDF department')
        self.other_dept = Department.objects.create(name='Other PDF department')
        self.admin = User.objects.create_user(username='pdfadmin', is_admin=True)
        self.ap = User.objects.create_user(username='pdfap')
        self.other_ap = User.objects.create_user(username='pdfotherap')
        complete_onboarding(self.ap, self.other_ap)
        self.officer = User.objects.create_user(username='PRIVATE_USERNAME', email='private@example.com', first_name='Jos\u00e9', last_name='Tan')
        Membership.objects.create(user=self.ap, department=self.dept, role='AP')
        Membership.objects.create(user=self.other_ap, department=self.other_dept, role='AP')
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        self.meeting = Meeting.objects.create(department=self.dept, title='Minutes / unsafe title',
            minutes_content='First line\nSecond line \u2014 Caf\u00e9 <img src="https://invalid.test/secret">', status='Finished')
        self.att = Attendance.objects.create(meeting=self.meeting, user=self.officer, status='Attended')
        self.url = reverse('export_meeting_pdf', args=[self.meeting.pk])

    def test_permissions_and_methods(self):
        from unittest.mock import patch
        # Reach PDF authorization; other tests retain the historical signer without a PNG.
        complete_onboarding(self.officer)
        self.assertEqual(self.client.get(self.url).status_code, 302)
        with patch('meetings.pdf.generate_meeting_pdf', return_value=b'%PDF-test'):
            for user, expected in ((self.admin, 200), (self.ap, 200), (self.other_ap, 403), (self.officer, 403)):
                self.client.force_login(user)
                self.assertEqual(self.client.get(self.url).status_code, expected)
            self.assertEqual(AuditLog.objects.filter(event_type='document.exported').count(), 2)
        self.client.force_login(self.ap)
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
            self.assertEqual(self.client.generic(method, self.url).status_code, 405)

    def test_statuses_headers_audit_and_no_mutation(self):
        from unittest.mock import patch
        self.client.force_login(self.ap)
        before = list(Meeting.objects.values())
        attendance_before = list(Attendance.objects.values())
        with patch('meetings.pdf.generate_meeting_pdf', return_value=b'%PDF-test'):
            response = self.client.get(self.url)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn(f'minutes-unsafe-title-{self.meeting.pk}.pdf', response['Content-Disposition'])
        self.assertEqual(response['Cache-Control'], 'private, no-store, max-age=0')
        event = AuditLog.objects.get(event_type='document.exported')
        self.assertEqual(event.user, self.ap)
        self.assertEqual(event.meeting, self.meeting)
        self.assertEqual(event.department, self.dept)
        self.assertEqual(event.metadata['attendee_count'], 1)
        self.assertNotIn(self.meeting.minutes_content, str(event.metadata))
        self.assertEqual(list(Meeting.objects.values()), before)
        self.assertEqual(list(Attendance.objects.values()), attendance_before)
        self.meeting.status = 'Archived'
        self.meeting.save()
        with patch('meetings.pdf.generate_meeting_pdf', return_value=b'%PDF-test'):
            self.assertEqual(self.client.get(self.url).status_code, 200)
        draft = Meeting.objects.create(department=self.dept, title='Draft')
        self.assertEqual(self.client.get(reverse('export_meeting_pdf', args=[draft.pk])).status_code, 403)
        self.assertEqual(AuditLog.objects.filter(event_type='document.exported').count(), 2)

    def test_render_and_audit_failures(self):
        from unittest.mock import patch
        self.client.force_login(self.ap)
        with patch('meetings.pdf.generate_meeting_pdf', side_effect=RuntimeError('renderer failed')):
            self.assertEqual(self.client.get(self.url).status_code, 503)
        self.assertFalse(AuditLog.objects.exists())
        with patch('meetings.pdf.generate_meeting_pdf', return_value=b'%PDF-test'):
            with patch('meetings.views.AuditLog.objects.create', side_effect=RuntimeError('audit failed')):
                with self.assertRaises(RuntimeError):
                    self.client.get(self.url)
        self.assertFalse(AuditLog.objects.exists())

    def test_snapshot_signatures_and_sensitive_exclusions(self):
        from meetings.pdf import capture_document
        from meetings.crypto import sign_document_data, build_canonical_signing_payload, build_legacy_signing_payload
        from django.template.loader import render_to_string
        from django.utils import timezone
        self.officer.refresh_from_db()
        for kind in ('canonical', 'legacy', 'invalid', 'unsigned'):
            annotation = 'Authorized annotation'
            payload = (build_canonical_signing_payload(self.meeting.pk, self.dept.pk, self.meeting.title,
                       self.meeting.minutes_content, annotation) if kind == 'canonical'
                       else build_legacy_signing_payload(self.meeting.minutes_content, annotation))
            signature = sign_document_data(self.officer.private_key, payload) if kind != 'invalid' else 'INVALID_SIGNATURE_BYTES'
            Attendance.objects.filter(pk=self.att.pk).update(has_signed=kind != 'unsigned',
                annotation=annotation, cryptographic_signature=signature, signed_at=timezone.now())
            with self.assertNumQueries(1):
                document = capture_document(self.meeting.pk)
            expected = {'canonical': 'Valid canonical ECDSA signature', 'legacy': 'Valid legacy ECDSA signature',
                        'invalid': 'Invalid signature', 'unsigned': 'Unsigned'}[kind]
            self.assertEqual(document['attendees'][0]['verification'], expected)
            html = render_to_string('pdf/final_minutes.html', {'document': document})
            self.assertIn(expected, html)
            self.assertIn('Jos\u00e9 Tan' if kind == 'unsigned' else 'Name unavailable', html)
            if kind != 'unsigned':
                self.assertIn('Visual signature unavailable', html)
            self.assertIn(annotation, html)
            self.assertIn('Second line \u2014 Caf\u00e9 &lt;img', html)
            for secret in (signature, self.officer.private_key, self.officer.public_key, self.officer.username, self.officer.email):
                self.assertNotIn(secret, html)
            self.assertFalse(self.officer.signature_image)

    def test_snapshot_is_detached_from_later_updates(self):
        from meetings.pdf import capture_document
        document = capture_document(self.meeting.pk)
        Attendance.objects.filter(pk=self.att.pk).update(status='Late', annotation='Later annotation')
        self.assertEqual(document['attendees'][0]['status'], 'Attended')
        self.assertEqual(document['attendees'][0]['annotation'], '')

    def test_resource_fetcher_denies_every_url(self):
        from meetings.pdf import deny_resource
        for url in ('https://example.com', 'file:///etc/passwd', 'data:text/plain,secret', '/local/file'):
            with self.assertRaises(ValueError):
                deny_resource(url)

    def test_real_renderer_unicode_multiline_and_pagination(self):
        from meetings.pdf import capture_document, generate_meeting_pdf, deny_resource
        from django.template.loader import render_to_string
        from weasyprint import HTML
        document = capture_document(self.meeting.pk)
        examples = ('Jos\u00e9', 'Caf\u00e9', 'M\u00fcnchen', '\u65e5\u672c\u8a9e',
                    'Pangunahing pulong  pagsusuri')
        document['minutes_content'] = ('\n'.join(examples) + '\nMultiline minutes\n') * 150
        document['attendees'] *= 70
        html = render_to_string('pdf/final_minutes.html', {'document': document})
        layout = HTML(string=html, url_fetcher=deny_resource).render()
        self.assertGreater(len(layout.pages), 3)
        pdf = generate_meeting_pdf(document)
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertGreater(len(pdf), 1000)
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path
        extractor = shutil.which('pdftotext')
        if extractor is None:
            bundled = Path('C:/Program Files/Git/ucrt64/bin/pdftotext.exe')
            self.assertTrue(bundled.is_file(), 'Unicode PDF validation requires an existing pdftotext executable.')
            extractor = str(bundled)
        # Xpdf's pdftotext (bundled with Git here) requires a real input path.
        with tempfile.TemporaryDirectory() as directory:
            pdf_path = Path(directory) / 'unicode.pdf'
            text_path = Path(directory) / 'unicode.txt'
            pdf_path.write_bytes(pdf)
            result = subprocess.run(
                [extractor, '-layout', '-enc', 'UTF-8', str(pdf_path), str(text_path)],
                capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
            extracted = text_path.read_text(encoding='utf-8')
        for example in examples:
            self.assertIn(example, extracted)
        self.assertNotIn('\ufffd', extracted)

    def test_snapshot_deletion_returns_controlled_404(self):
        from unittest.mock import patch
        self.client.force_login(self.ap)
        with patch('meetings.pdf.capture_document', side_effect=Meeting.DoesNotExist('internal detail')):
            with patch('meetings.pdf.generate_meeting_pdf') as renderer:
                response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)
        self.assertNotContains(response, 'internal detail', status_code=404)
        renderer.assert_not_called()
        self.assertFalse(AuditLog.objects.filter(event_type='document.exported').exists())
        # Only disappearance is translated into a 404; programming errors propagate.
        with patch('meetings.pdf.capture_document', side_effect=TypeError('programming error')):
            with self.assertRaises(TypeError):
                self.client.get(self.url)

    def test_real_renderer_routes_resources_through_denying_fetcher(self):
        from unittest.mock import patch
        from pathlib import Path
        from meetings.pdf import capture_document, generate_meeting_pdf, deny_resource
        urls = ('https://example.invalid/private.png', Path(__file__).resolve().as_uri(),
                'data:image/png;base64,AAAA', 'evidence:unknown')
        document = capture_document(self.meeting.pk)
        # Inject trusted test HTML to force real resource requests. Production content
        # remains escaped; no resource permissions are relaxed for this test.
        for url in urls:
            requested = []
            def recording_fetcher(resource_url, *args, **kwargs):
                requested.append(resource_url)
                return deny_resource(resource_url, *args, **kwargs)
            html = f'<html><body><img src="{url}"></body></html>'
            with self.subTest(url=url):
                with patch('meetings.pdf.render_to_string', return_value=html):
                    with patch('meetings.pdf.deny_resource', new=recording_fetcher):
                        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('Resource access attempted')) as opener:
                            from weasyprint.urls import FatalURLFetchingError
                            with self.assertRaises(FatalURLFetchingError) as error:
                                generate_meeting_pdf(document)
                self.assertIsInstance(error.exception.__cause__, ValueError)
                self.assertEqual(str(error.exception.__cause__), 'External PDF resources are disabled.')
                self.assertEqual(requested, [url])
                opener.assert_not_called()

    def test_export_links_and_officer_exclusion(self):
        complete_onboarding(self.officer)
        self.client.force_login(self.ap)
        self.assertContains(self.client.get(reverse('review_meeting', args=[self.meeting.pk])), self.url)
        self.assertContains(self.client.get(reverse('department_dashboard', args=[self.dept.pk])), self.url)
        self.client.force_login(self.officer)
        self.assertNotContains(self.client.get(reverse('department_dashboard', args=[self.dept.pk])), self.url)
