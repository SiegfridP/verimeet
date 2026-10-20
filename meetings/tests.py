import time
from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import Department, User
from meetings.models import Meeting
from meetings.crypto import generate_hmac_qr_token

class MeetingRoutingAndSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(name='Engineering', contact_email='eng@example.com')
        self.admin_user = User.objects.create_user(
            username='admin_eng',
            password='password123',
            department=self.dept,
            is_admin=True
        )
        self.student_user = User.objects.create_user(
            username='student_eng',
            password='password123',
            department=self.dept,
            is_admin=False
        )
        self.other_dept = Department.objects.create(name='Arts', contact_email='arts@example.com')
        self.other_user = User.objects.create_user(
            username='student_art',
            password='password123',
            department=self.other_dept,
            is_admin=False
        )

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

    def test_admin_dashboard_restrictions(self):
        """Admin dashboard allows admins and redirects regular users to student dashboard."""
        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_unauth.status_code, 302)
        self.assertTrue(r_unauth.headers['Location'].startswith('/accounts/auth/login/'))

        # Regular user -> redirected to student dashboard
        self.client.force_login(self.student_user)
        r_student = self.client.get(reverse('admin_dashboard'))
        self.assertRedirects(r_student, reverse('student_dashboard'))

        # Admin -> renders successfully
        self.client.force_login(self.admin_user)
        r_admin = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(r_admin.status_code, 200)

    def test_student_dashboard_access(self):
        """Student dashboard opens for authenticated users."""
        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(reverse('student_dashboard'))
        self.assertEqual(r_unauth.status_code, 302)
        self.assertTrue(r_unauth.headers['Location'].startswith('/accounts/auth/login/'))

        # Authenticated user -> renders successfully
        self.client.force_login(self.student_user)
        r_student = self.client.get(reverse('student_dashboard'))
        self.assertEqual(r_student.status_code, 200)

    def test_projector_qr_view_authorization(self):
        """Projector QR requires admin and Finished meeting status."""
        url_finished = reverse('projector_qr_view', args=[self.finished_meeting.id])
        url_draft = reverse('projector_qr_view', args=[self.draft_meeting.id])

        # Unauthenticated -> redirect to login
        r_unauth = self.client.get(url_finished)
        self.assertEqual(r_unauth.status_code, 302)

        # Non-admin -> 403 Forbidden
        self.client.force_login(self.student_user)
        r_student = self.client.get(url_finished)
        self.assertEqual(r_student.status_code, 403)

        # Admin with Draft meeting -> 403 Forbidden
        self.client.force_login(self.admin_user)
        r_draft = self.client.get(url_draft)
        self.assertEqual(r_draft.status_code, 403)

        # Admin with Finished meeting -> 200 OK
        r_ok = self.client.get(url_finished)
        self.assertEqual(r_ok.status_code, 200)

    def test_sign_meeting_missing_tokens(self):
        """Missing security tokens should return 403 controlled error."""
        self.client.force_login(self.student_user)
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
        self.client.force_login(self.student_user)
        base_url = reverse('sign_meeting', args=[self.finished_meeting.id])

        r = self.client.get(f"{base_url}?t=not_a_number&sig=abcdef123456")
        self.assertEqual(r.status_code, 403)

    def test_sign_meeting_expired_and_future_tokens(self):
        """Expired and future tokens should return 403."""
        self.client.force_login(self.student_user)
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
        self.client.force_login(self.student_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        r = self.client.get(f"{base_url}?t={ts}&sig=bad_signature_hex")
        self.assertEqual(r.status_code, 403)

    def test_sign_meeting_valid_token(self):
        """Valid HMAC token and signature within time limit should render the signing page."""
        self.client.force_login(self.student_user)
        meeting_id = self.finished_meeting.id
        base_url = reverse('sign_meeting', args=[meeting_id])
        ts = str(int(time.time()))
        sig = generate_hmac_qr_token(meeting_id, ts)
        r = self.client.get(f"{base_url}?t={ts}&sig={sig}")
        self.assertEqual(r.status_code, 200)
