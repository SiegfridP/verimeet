from django.test import TestCase
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django.db.models.deletion import ProtectedError
from accounts.models import User, Department, Membership
from .models import Meeting, Attendance, HistoricalRoster


class RosterIntegrityTests(TestCase):
    def setUp(self):
        self.department=Department.objects.create(name='Integrity department')
        self.user=User.objects.create_user(username='identity',first_name='Original',last_name='Name')
        Membership.objects.create(user=self.user,department=self.department)
        self.meeting=Meeting.objects.create(department=self.department,title='Record')
        self.attendance=Attendance.objects.create(meeting=self.meeting,user=self.user)

    def finalize(self):
        self.meeting.status='Finished';self.meeting.save()

    def test_finished_deletion_all_origins_and_draft_deletion(self):
        draft=Meeting.objects.create(department=self.department,title='Draft')
        Attendance.objects.create(meeting=draft,user=self.user).delete()
        self.assertFalse(Attendance.objects.filter(meeting=draft).exists())
        self.finalize()
        for operation in (lambda:self.attendance.delete(),lambda:Attendance.objects.filter(pk=self.attendance.pk).delete(),
                          lambda:self.user.delete(),lambda:self.meeting.delete(),lambda:self.department.delete()):
            with self.assertRaises((PermissionDenied,ProtectedError)), transaction.atomic():operation()
            self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())
        self.meeting.status='Archived';self.meeting.save()
        with self.assertRaises(PermissionDenied),transaction.atomic():self.attendance.delete()

    def test_snapshot_ordinary_mutation_paths_are_rejected(self):
        self.finalize();snapshot=self.meeting.historical_roster
        for operation in (lambda:snapshot.save(), lambda:HistoricalRoster.objects.update(entries=[]),
                          lambda:HistoricalRoster.objects.bulk_update([snapshot],['entries']),
                          lambda:HistoricalRoster.objects.bulk_create([HistoricalRoster(meeting=self.meeting)]),
                          lambda:HistoricalRoster(meeting=self.meeting).save(),lambda:snapshot.delete(),
                          lambda:HistoricalRoster.objects.all().delete()):
            with self.assertRaises((PermissionDenied,ProtectedError)),transaction.atomic():operation()

    def test_direct_finalization_and_rollback(self):
        with self.assertRaises(RuntimeError),transaction.atomic():
            self.finalize()
            raise RuntimeError('rollback')
        self.meeting.refresh_from_db();self.assertEqual(self.meeting.status,'Draft')
        self.assertFalse(HistoricalRoster.objects.exists())
        self.finalize();self.assertTrue(HistoricalRoster.objects.exists())

    def test_name_updates_and_bulk_restriction(self):
        self.user.first_name='Updated';self.user.save(update_fields=['first_name'])
        User.objects.filter(pk=self.user.pk).update(last_name='Updated')
        self.finalize()
        self.assertEqual(self.meeting.historical_roster.entries[0]['name'],'Updated Updated')
        with self.assertRaises(PermissionDenied):User.objects.bulk_update([self.user],['first_name'])

    def test_signed_draft_evidence_remains_protected(self):
        self.attendance.has_signed=True
        self.attendance.cryptographic_signature='retained-evidence'
        self.attendance.save(update_fields=['has_signed','cryptographic_signature'])
        with self.assertRaises(PermissionDenied),transaction.atomic():
            self.attendance.delete()
        self.assertTrue(Attendance.objects.filter(pk=self.attendance.pk).exists())

    def test_department_delete_page_handles_protected_roster_without_server_error(self):
        from django.urls import reverse
        from .models import AuditLog
        admin=User.objects.create_user(username='deletion-admin',is_admin=True)
        self.finalize()
        self.client.force_login(admin)
        response=self.client.post(reverse('delete_department',args=[self.department.pk]))
        self.assertEqual(response.status_code,400)
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        self.assertTrue(HistoricalRoster.objects.filter(meeting=self.meeting).exists())
        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())
