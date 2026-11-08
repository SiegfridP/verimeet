"""Activity checks at the guarded edit/finalization mutation boundary."""
from unittest.mock import patch

from django.db import transaction
from django.db.models.query import QuerySet
from django.test import TestCase
from django.urls import reverse

from accounts.models import Department, Membership, User
from accounts.test_fixtures import complete_onboarding, signature_storage
from .models import AuditLog, HistoricalRoster, Meeting
from .roster import lock_departments


class DepartmentMutationTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.department = Department.objects.create(name='Mutation department')
        self.ap = User.objects.create_user(username='mutation-ap')
        Membership.objects.create(user=self.ap, department=self.department, role='AP')
        complete_onboarding(self.ap)
        self.admin = User.objects.create_user(username='mutation-admin', is_admin=True)
        self.meeting = Meeting.objects.create(department=self.department, title='Original', minutes_content='Original minutes')

    def post(self, route):
        return self.client.post(reverse(route, args=[self.meeting.pk]),
                                {'title': 'Changed', 'minutes_content': 'Changed minutes'})

    def assert_unchanged(self):
        self.meeting.refresh_from_db()
        self.assertEqual(self.meeting.status, 'Draft')
        self.assertEqual(self.meeting.title, 'Original')
        self.assertEqual(self.meeting.minutes_content, 'Original minutes')
        self.assertFalse(HistoricalRoster.objects.filter(meeting=self.meeting).exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_inactive_department_rejects_ap_and_global_admin(self):
        Department.objects.filter(pk=self.department.pk).update(is_active=False)
        for actor in (self.ap, self.admin):
            self.client.force_login(actor)
            for route in ('edit_meeting', 'finalize_meeting', 'lock_meeting'):
                with self.subTest(actor=actor.username, route=route):
                    self.assertEqual(self.post(route).status_code, 403)
                    self.assert_unchanged()

    def test_active_department_preserves_edit_and_finalization(self):
        for actor in (self.ap, self.admin):
            self.client.force_login(actor)
            for route in ('finalize_meeting', 'lock_meeting'):
                with self.subTest(actor=actor.username, route=route), transaction.atomic():
                    self.assertEqual(self.post('edit_meeting').status_code, 302)
                    self.meeting.refresh_from_db()
                    self.assertEqual(self.meeting.title, 'Changed')
                    self.assertEqual(self.meeting.minutes_content, 'Changed minutes')
                    self.assertEqual(self.post(route).status_code, 302)
                    self.meeting.refresh_from_db()
                    self.assertEqual(self.meeting.status, 'Finished')
                    self.assertTrue(HistoricalRoster.objects.filter(meeting=self.meeting).exists())
                    self.assertEqual(AuditLog.objects.filter(event_type='meeting.edited').count(), 1)
                    self.assertEqual(AuditLog.objects.filter(event_type='meeting.finalized').count(), 1)
                    transaction.set_rollback(True)

    def test_deactivation_before_guard_is_revalidated(self):
        for actor in (self.ap, self.admin):
            self.client.force_login(actor)
            for route in ('edit_meeting', 'finalize_meeting', 'lock_meeting'):
                with self.subTest(actor=actor.username, route=route), transaction.atomic():
                    def deactivate_then_guard(ids):
                        Department.objects.filter(pk=self.department.pk).update(is_active=False)
                        lock_departments(ids)

                    with patch('meetings.roster.lock_departments', side_effect=deactivate_then_guard) as guard:
                        self.assertEqual(self.post(route).status_code, 403)
                    guard.assert_called_once_with([self.department.pk])
                    self.assert_unchanged()
                    transaction.set_rollback(True)

    def test_department_guard_precedes_meeting_lock(self):
        self.client.force_login(self.ap)
        for route in ('edit_meeting', 'finalize_meeting', 'lock_meeting'):
            with self.subTest(route=route), transaction.atomic():
                events = []
                original = QuerySet.select_for_update

                def guard(ids, using='default'):
                    lock_departments(ids, using)
                    events.append('department')

                def lock(queryset, *args, **kwargs):
                    if queryset.model is Meeting:
                        events.append('meeting')
                    return original(queryset, *args, **kwargs)

                with patch('meetings.roster.lock_departments', side_effect=guard), patch.object(QuerySet, 'select_for_update', lock):
                    self.assertEqual(self.post(route).status_code, 302)
                self.assertEqual(events[:2], ['department', 'meeting'])
                transaction.set_rollback(True)
