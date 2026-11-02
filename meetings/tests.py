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



class Batch04DraftEditingReviewFinalizationTests(TestCase):
    def setUp(self):
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
        self.assertContains(r, self.draft_meeting.get_status_display())
        self.assertContains(r, self.finished_meeting.get_status_display())
        self.assertContains(r, archived_meeting.get_status_display())

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
