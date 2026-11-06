from django.test import TestCase, Client
from django.urls import reverse, resolve
from django.conf import settings
from allauth.account.models import EmailAddress
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
        EmailAddress.objects.create(user=new_user, email=inv.email, verified=True)
        r_accept = self.client.post(reverse('accept_invitation', args=[inv.token]))
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
        EmailAddress.objects.create(user=self.ap_user_a, email=inv.email, verified=True)
        r = self.client.post(reverse('accept_invitation', args=[inv.token]))
        self.assertEqual(r.status_code, 302)

        m = Membership.objects.get(user=self.ap_user_a, department=self.dept_a)
        self.assertEqual(m.role, 'AP')

    def test_legacy_invitation_role_s_mapped_to_officer(self):
        """Legacy invitation with role 'S' is safely mapped to canonical Officer ('O')."""
        from accounts.models import Invitation
        inv = Invitation.objects.create(email='legacy@example.com', department=self.dept_a, inviter=self.ap_user_a, role='S')
        new_user = User.objects.create_user(username='legacy_user', password='password123')
        self.client.force_login(new_user)

        EmailAddress.objects.create(user=new_user, email=inv.email, verified=True)
        r = self.client.post(reverse('accept_invitation', args=[inv.token]))
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


class Batch09AdministrativeAuditTests(TestCase):
    def setUp(self):
        from django.test import RequestFactory
        from types import SimpleNamespace
        self.actor = User.objects.create_user(username='audit_admin', is_admin=True)
        self.department = Department.objects.create(name='Audit department')
        self.target = User.objects.create_user(username='audit_target')
        self.request = RequestFactory().post('/admin/')
        self.request.user = self.actor
        self.form = SimpleNamespace(changed_data=['name'])

    def test_department_admin_create_update_delete(self):
        from django.contrib import admin
        from meetings.models import AuditLog
        model_admin = admin.site._registry[Department]
        department = Department(name='New department')
        model_admin.save_model(self.request, department, self.form, False)
        event = AuditLog.objects.get(event_type='department.created')
        self.assertEqual(event.user, self.actor)
        target_id = str(department.pk)
        department.name = 'Updated'
        model_admin.save_model(self.request, department, self.form, True)
        self.assertEqual(AuditLog.objects.get(event_type='department.updated').metadata['changed_fields'], ['name'])
        model_admin.delete_model(self.request, department)
        event = AuditLog.objects.get(event_type='department.deleted')
        self.assertEqual(event.target_id, target_id)
        self.assertIsNone(event.department_id)

    def test_role_grant_noop_and_attribution(self):
        from .audit import grant_ap
        from meetings.models import AuditLog
        from django.db import transaction
        Membership.objects.create(user=self.target, department=self.department, role='O')
        with transaction.atomic():
            grant_ap(self.actor, self.target, self.department)
            grant_ap(self.actor, self.target, self.department)
        event = AuditLog.objects.get()
        self.assertEqual(event.user, self.actor)
        self.assertEqual(event.department, self.department)
        self.assertEqual(event.metadata['previous_role'], 'O')
        self.assertEqual(event.metadata['new_role'], 'AP')

    def test_invitation_replacement_and_acceptance(self):
        from meetings.models import AuditLog
        self.client.force_login(self.actor)
        url = reverse('invite_member', args=[self.department.pk])
        for i in range(2):
            self.assertEqual(self.client.post(url, {'email': 'invite@example.com', 'role': 'O'}).status_code, 302)
        self.assertEqual(AuditLog.objects.filter(event_type='invitation.created').count(), 2)
        self.assertEqual(AuditLog.objects.filter(event_type='invitation.revoked').count(), 1)
        invitation = Invitation.objects.get(accepted=False)
        self.client.force_login(self.target)
        EmailAddress.objects.create(user=self.target, email=invitation.email, verified=True)
        self.client.post(reverse('accept_invitation', args=[invitation.token]))
        event = AuditLog.objects.get(event_type='membership.added')
        self.assertEqual(event.user, self.target)
        self.assertEqual(event.metadata['user_id'], self.target.pk)
        self.assertNotIn(invitation.token, str(list(AuditLog.objects.values())))

    def test_user_admin_activation_role_and_membership(self):
        from django.contrib import admin
        from meetings.models import AuditLog
        model_admin = admin.site._registry[User]
        self.target.is_active = False
        self.target.is_admin = True
        self.target.department = self.department
        model_admin.save_model(self.request, self.target, self.form, True)
        self.assertEqual(AuditLog.objects.get(event_type='user.activation_changed').user, self.actor)
        self.assertEqual(AuditLog.objects.get(event_type='user.role_changed').metadata['new_role'], 'Global Admin')
        self.assertEqual(AuditLog.objects.filter(event_type='membership.added').count(), 1)
        model_admin.delete_model(self.request, self.target)
        self.assertEqual(AuditLog.objects.get(event_type='membership.removed').user, self.actor)

    def test_audit_failure_rolls_back_department_admin_save(self):
        from django.contrib import admin
        from unittest.mock import patch
        department = Department(name='Rollback department')
        with patch('accounts.audit.AuditLog.objects.create', side_effect=RuntimeError('audit failure')):
            with self.assertRaises(RuntimeError):
                admin.site._registry[Department].save_model(self.request, department, self.form, False)
        self.assertFalse(Department.objects.filter(name='Rollback department').exists())
