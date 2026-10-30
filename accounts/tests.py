from django.test import TestCase, Client
from django.urls import reverse, resolve
from django.conf import settings
from accounts.models import Department, User, Membership, Invitation, RoleElevationRequest

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
        self.officer_user = User.objects.create_user(
            username='officeruser',
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

    def test_root_authenticated_officer(self):
        """Authenticated officer visiting / is sent to their department dashboard."""
        self.client.force_login(self.officer_user)
        response = self.client.get('/')
        self.assertRedirects(response, reverse('department_dashboard', args=[self.dept.id]))

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

        # Officer -> department dashboard
        self.client.force_login(self.officer_user)
        r3 = self.client.get(reverse('routing_view'))
        self.assertRedirects(r3, reverse('department_dashboard', args=[self.dept.id]))

    def test_waiting_room_renders_content(self):
        """Waiting room page displays successfully with explanatory content."""
        self.client.force_login(self.user_no_dept)
        response = self.client.get(reverse('waiting_room'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Waiting Room')
        self.assertGreater(len(response.content.strip()), 0)

    def test_waiting_room_redirects_assigned_user(self):
        """User with assigned department is redirected away from waiting room without loops."""
        self.client.force_login(self.officer_user)
        response = self.client.get(reverse('waiting_room'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], reverse('routing_view'))
        
        # Follow the entire redirection chain to ensure no infinite loop
        chain_response = self.client.get(reverse('waiting_room'), follow=True)
        self.assertEqual(chain_response.status_code, 200)
        self.assertEqual(chain_response.redirect_chain, [
            (reverse('routing_view'), 302),
            (reverse('department_dashboard', args=[self.dept.id]), 302)
        ])

    def test_google_oauth_urls(self):
        """Google OAuth login and callback URLs are properly registered and consistent."""
        self.assertEqual(reverse('google_login'), '/accounts/auth/google/login/')
        self.assertEqual(reverse('google_callback'), '/accounts/auth/google/login/callback/')

    def test_logout_clears_session_and_redirects(self):
        """Logout terminates session and redirects to valid destination."""
        self.client.force_login(self.officer_user)
        self.assertIn('_auth_user_id', self.client.session)

        response = self.client.post(reverse('account_logout'))
        self.assertEqual(response.status_code, 302)
        # Session should be cleared
        self.assertNotIn('_auth_user_id', self.client.session)
        # Follow redirect should reach login page
        follow_response = self.client.get(response.headers['Location'])
        self.assertEqual(follow_response.status_code, 302)
        self.assertTrue(follow_response.headers['Location'].startswith('/accounts/auth/login/'))


class MultiDepartmentAndRBACTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept_a = Department.objects.create(name='Dept Alpha', contact_email='alpha@example.com')
        self.dept_b = Department.objects.create(name='Dept Beta', contact_email='beta@example.com')

        self.global_admin = User.objects.create_user(
            username='global_admin',
            password='password123',
            is_admin=True
        )
        self.ap_user_a = User.objects.create_user(
            username='ap_user_a',
            password='password123'
        )
        Membership.objects.create(user=self.ap_user_a, department=self.dept_a, role='AP')

        self.multi_user = User.objects.create_user(
            username='multi_user',
            password='password123'
        )
        Membership.objects.create(user=self.multi_user, department=self.dept_a, role='AP')
        Membership.objects.create(user=self.multi_user, department=self.dept_b, role='O')

        self.regular_officer = User.objects.create_user(
            username='officer_b',
            password='password123'
        )
        Membership.objects.create(user=self.regular_officer, department=self.dept_b, role='O')

    def test_multi_department_membership_roles(self):
        """User can have different roles in different departments."""
        self.client.force_login(self.multi_user)

        # Department A: Authorized Personnel panel renders
        r_a = self.client.get(reverse('department_dashboard', args=[self.dept_a.id]))
        self.assertEqual(r_a.status_code, 200)
        self.assertContains(r_a, 'Authorized Personnel Dashboard')

        # Department B: Officer member panel renders
        r_b = self.client.get(reverse('department_dashboard', args=[self.dept_b.id]))
        self.assertEqual(r_b.status_code, 200)
        self.assertContains(r_b, 'Officer Dashboard')

    def test_tenant_isolation_invitations(self):
        """Authorized Personnel in Dept A cannot invite members to Dept B."""
        self.client.force_login(self.ap_user_a)

        # Authorized in Dept A
        r_a = self.client.get(reverse('invite_member', args=[self.dept_a.id]))
        self.assertEqual(r_a.status_code, 200)

        # Forbidden in Dept B
        r_b = self.client.get(reverse('invite_member', args=[self.dept_b.id]))
        self.assertEqual(r_b.status_code, 403)

    def test_ordinary_officer_cannot_invite_or_request_elevation(self):
        """Ordinary Officer cannot issue invitations or request elevation."""
        self.client.force_login(self.regular_officer)

        r_inv = self.client.get(reverse('invite_member', args=[self.dept_b.id]))
        self.assertEqual(r_inv.status_code, 403)

        r_elev = self.client.get(reverse('request_authorized_personnel', args=[self.dept_b.id]))
        self.assertEqual(r_elev.status_code, 403)

    def test_invitation_creation_and_acceptance_roles(self):
        """Invitations grant Officer role upon acceptance."""
        from accounts.models import Invitation
        self.client.force_login(self.ap_user_a)

        # Send Officer invitation
        post_data = {'email': 'officer_new@example.com', 'role': 'O'}
        r = self.client.post(reverse('invite_member', args=[self.dept_a.id]), data=post_data)
        self.assertEqual(r.status_code, 302)

        inv = Invitation.objects.get(email='officer_new@example.com')
        self.assertEqual(inv.role, 'O')

        # Accept as a new user
        new_user = User.objects.create_user(username='new_officer', password='password123')
        self.client.force_login(new_user)
        r_accept = self.client.get(reverse('accept_invitation', args=[inv.token]))
        self.assertEqual(r_accept.status_code, 302)

        m = Membership.objects.get(user=new_user, department=self.dept_a)
        self.assertEqual(m.role, 'O')

    def test_invitation_token_uniqueness(self):
        """Multiple invitations created independently must receive distinct tokens."""
        from accounts.models import Invitation
        self.client.force_login(self.ap_user_a)

        inv1 = Invitation.objects.create(email='user1@example.com', department=self.dept_a, inviter=self.ap_user_a)
        inv2 = Invitation.objects.create(email='user2@example.com', department=self.dept_a, inviter=self.ap_user_a)
        inv3 = Invitation.objects.create(email='user3@example.com', department=self.dept_a, inviter=self.ap_user_a)

        self.assertNotEqual(inv1.token, inv2.token)
        self.assertNotEqual(inv2.token, inv3.token)
        self.assertNotEqual(inv1.token, inv3.token)

    def test_invitation_acceptance_preserves_ap_role(self):
        """An existing Authorized Personnel accepting an invitation is not downgraded to Officer."""
        from accounts.models import Invitation
        inv = Invitation.objects.create(email='ap_new@example.com', department=self.dept_a, inviter=self.ap_user_a)

        self.client.force_login(self.ap_user_a)
        r = self.client.get(reverse('accept_invitation', args=[inv.token]))
        self.assertEqual(r.status_code, 302)

        m = Membership.objects.get(user=self.ap_user_a, department=self.dept_a)
        self.assertEqual(m.role, 'AP')

    def test_legacy_invitation_role_s_mapped_to_officer(self):
        """Legacy invitation with role 'S' is safely mapped to canonical Officer ('O')."""
        from accounts.models import Invitation
        inv = Invitation.objects.create(email='legacy@example.com', department=self.dept_a, inviter=self.ap_user_a, role='S')
        new_user = User.objects.create_user(username='legacy_user', password='password123')
        self.client.force_login(new_user)

        r = self.client.get(reverse('accept_invitation', args=[inv.token]))
        self.assertEqual(r.status_code, 302)

        m = Membership.objects.get(user=new_user, department=self.dept_a)
        self.assertEqual(m.role, 'O')

    def test_global_admin_elevation_approval_flow(self):
        """Global Admin can review and approve elevation requests from admin dashboard."""
        from accounts.models import RoleElevationRequest
        # Create an elevation request for regular_officer in Dept B
        req = RoleElevationRequest.objects.create(
            department=self.dept_b,
            target_user=self.regular_officer,
            requester=self.global_admin,
            note='Promote to AP'
        )

        # Non-admin cannot approve
        self.client.force_login(self.regular_officer)
        r_fail = self.client.post(reverse('admin_dashboard'), data={'request_id': req.id, 'action': 'approve'})
        self.assertEqual(r_fail.status_code, 403)

        # Global Admin approves
        self.client.force_login(self.global_admin)
        r_approve = self.client.post(reverse('admin_dashboard'), data={'request_id': req.id, 'action': 'approve'})
        self.assertEqual(r_approve.status_code, 302)

        req.refresh_from_db()
        self.assertEqual(req.status, 'A')
        m = Membership.objects.get(user=self.regular_officer, department=self.dept_b)
        self.assertEqual(m.role, 'AP')

    def test_global_admin_elevation_rejection_flow(self):
        """Global Admin can reject elevation requests without modifying user role."""
        from accounts.models import RoleElevationRequest
        req = RoleElevationRequest.objects.create(
            department=self.dept_b,
            target_user=self.regular_officer,
            requester=self.global_admin,
            note='Reject test'
        )
        self.client.force_login(self.global_admin)
        r_rej = self.client.post(reverse('admin_dashboard'), data={'request_id': req.id, 'action': 'reject'})
        self.assertEqual(r_rej.status_code, 302)

        req.refresh_from_db()
        self.assertEqual(req.status, 'R')
        # Role remains unchanged
        m = Membership.objects.get(user=self.regular_officer, department=self.dept_b)
        self.assertEqual(m.role, 'O')
