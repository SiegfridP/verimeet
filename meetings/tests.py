import time
from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import Department, User, Membership
from meetings.models import Meeting, Attendance, AuditLog
from meetings.crypto import generate_hmac_qr_token

class MeetingRoutingAndSecurityTests(TestCase):
    def setUp(self):
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
            has_signed=False
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
        """Lock meeting requires AP and redirects to department dashboard."""
        url_lock = reverse('lock_meeting', args=[self.draft_meeting.id])

        # Officer -> 403 Forbidden
        self.client.force_login(self.officer_user)
        r_forbidden = self.client.get(url_lock)
        self.assertEqual(r_forbidden.status_code, 403)

        # AP -> locks meeting and redirects to department_dashboard
        self.client.force_login(self.ap_user)
        r_lock = self.client.get(url_lock)
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

