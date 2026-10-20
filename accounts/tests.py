from django.test import TestCase, Client
from django.urls import reverse, resolve
from django.conf import settings
from accounts.models import Department, User

class RoutingAndAuthTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(name='Computer Science', contact_email='cs@example.com')
        self.user_no_dept = User.objects.create_user(username='nodept', password='password123')
        self.admin_user = User.objects.create_user(
            username='adminuser',
            password='password123',
            department=self.dept,
            is_admin=True
        )
        self.student_user = User.objects.create_user(
            username='studentuser',
            password='password123',
            department=self.dept,
            is_admin=False
        )

    def test_login_url_resolution(self):
        """LOGIN_URL setting should resolve to the allauth login URL."""
        login_url = reverse(settings.LOGIN_URL)
        self.assertEqual(login_url, '/accounts/auth/login/')

    def test_auth_login_page_renders(self):
        """The authentication page at /accounts/auth/login/ should resolve and render."""
        response = self.client.get('/accounts/auth/login/')
        self.assertEqual(response.status_code, 200)

    def test_legacy_accounts_login_redirect(self):
        """Accessing /accounts/login/ should redirect to /accounts/auth/login/."""
        response = self.client.get('/accounts/login/')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/accounts/auth/login/')

    def test_root_unauthenticated_redirect(self):
        """Unauthenticated visits to / should redirect to the valid login page."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('/accounts/auth/login/'))

    def test_root_authenticated_no_department(self):
        """Authenticated user without a department visiting / is sent to the waiting room."""
        self.client.force_login(self.user_no_dept)
        response = self.client.get('/')
        self.assertRedirects(response, reverse('waiting_room'))

    def test_root_authenticated_admin(self):
        """Authenticated admin visiting / is sent to the admin dashboard."""
        self.client.force_login(self.admin_user)
        response = self.client.get('/')
        self.assertRedirects(response, reverse('admin_dashboard'))

    def test_root_authenticated_student(self):
        """Authenticated student visiting / is sent to the student dashboard."""
        self.client.force_login(self.student_user)
        response = self.client.get('/')
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_routing_view_destinations(self):
        """Verify role-based routing from /accounts/route/."""
        # No department -> waiting room
        self.client.force_login(self.user_no_dept)
        r1 = self.client.get(reverse('routing_view'))
        self.assertRedirects(r1, reverse('waiting_room'))

        # Admin -> admin dashboard
        self.client.force_login(self.admin_user)
        r2 = self.client.get(reverse('routing_view'))
        self.assertRedirects(r2, reverse('admin_dashboard'))

        # Student -> student dashboard
        self.client.force_login(self.student_user)
        r3 = self.client.get(reverse('routing_view'))
        self.assertRedirects(r3, reverse('student_dashboard'))

    def test_waiting_room_renders_content(self):
        """Waiting room page displays successfully with explanatory content."""
        self.client.force_login(self.user_no_dept)
        response = self.client.get(reverse('waiting_room'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Waiting Room')
        self.assertGreater(len(response.content.strip()), 0)

    def test_waiting_room_redirects_assigned_user(self):
        """User with assigned department is redirected away from waiting room without loops."""
        self.client.force_login(self.student_user)
        response = self.client.get(reverse('waiting_room'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], reverse('routing_view'))
        
        # Follow the entire redirection chain to ensure no infinite loop
        chain_response = self.client.get(reverse('waiting_room'), follow=True)
        self.assertEqual(chain_response.status_code, 200)
        self.assertEqual(chain_response.redirect_chain, [
            (reverse('routing_view'), 302),
            (reverse('student_dashboard'), 302)
        ])

    def test_google_oauth_urls(self):
        """Google OAuth login and callback URLs are properly registered and consistent."""
        self.assertEqual(reverse('google_login'), '/accounts/auth/google/login/')
        self.assertEqual(reverse('google_callback'), '/accounts/auth/google/login/callback/')

    def test_logout_clears_session_and_redirects(self):
        """Logout terminates session and redirects to valid destination."""
        self.client.force_login(self.student_user)
        self.assertIn('_auth_user_id', self.client.session)

        response = self.client.post(reverse('account_logout'))
        self.assertEqual(response.status_code, 302)
        # Session should be cleared
        self.assertNotIn('_auth_user_id', self.client.session)
        # Follow redirect should reach login page
        follow_response = self.client.get(response.headers['Location'])
        self.assertEqual(follow_response.status_code, 302)
        self.assertTrue(follow_response.headers['Location'].startswith('/accounts/auth/login/'))
