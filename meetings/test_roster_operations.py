from unittest.mock import patch
from django.test import TransactionTestCase
from django.db import transaction, connection
from django.core.exceptions import PermissionDenied
from django.db.models.query import QuerySet
from accounts.models import User, Department, Membership
from .models import Meeting, HistoricalRoster
from .roster import lock_departments, lock_user_scope


class RosterOperationTests(TransactionTestCase):
    def setUp(self):
        self.department=Department.objects.create(name='Operations')
        self.user=User.objects.create_user(username='operation-user',first_name='Original',last_name='Name')
        Membership.objects.create(user=self.user,department=self.department)

    def test_nested_rollback_and_reused_atomic_have_no_bookkeeping(self):
        scope=transaction.atomic()
        for index in range(2):
            with scope:
                try:
                    with transaction.atomic():
                        lock_departments([self.department.pk])
                        raise ValueError('savepoint rollback')
                except ValueError:
                    pass
                meeting=Meeting.objects.create(department=self.department,title=str(index))
                meeting.status='Finished';meeting.save()
                self.assertEqual(len(meeting.historical_roster.entries),1)
        self.assertEqual(HistoricalRoster.objects.count(),2)
        self.assertFalse(hasattr(connection,'_roster_lock_state'))

    def test_stale_full_save_rechecks_persisted_names_under_guard(self):
        from . import roster
        User.objects.filter(pk=self.user.pk).update(first_name='Changed')
        seen=[]
        original=roster.lock_profile_names
        def guarded(users,using='default',extra_departments=()):
            result=original(users,using,extra_departments)
            seen.append(result.get().first_name)
            return result
        with patch.object(roster,'lock_profile_names',side_effect=guarded):
            self.user.save()
        self.assertEqual(seen,['Changed'])
        self.user.refresh_from_db();self.assertEqual(self.user.first_name,'Original')

    def test_mutable_filter_does_not_expand_frozen_targets(self):
        other=User.objects.create_user(username='other',first_name='Other')
        original=lock_user_scope
        def interleave(ids,using='default',extra_departments=()):
            QuerySet.update(User.objects.filter(pk=other.pk),first_name='Original')
            return original(ids,using,extra_departments)
        with patch('meetings.roster.lock_user_scope',side_effect=interleave):
            User.objects.filter(first_name='Original').update(last_name='Frozen target')
        self.user.refresh_from_db();other.refresh_from_db()
        self.assertEqual(self.user.last_name,'Frozen target')
        self.assertEqual(other.last_name,'')

    def test_scope_expansion_fails_without_partial_name_write(self):
        other=Department.objects.create(name='Expanded')
        from . import roster
        original=roster.user_department_scope
        calls=[]
        def expanding(ids,using='default'):
            calls.append(True)
            scope=original(ids,using)
            return scope if len(calls)==1 else scope | {other.pk}
        with patch.object(roster,'user_department_scope',side_effect=expanding):
            with self.assertRaises(PermissionDenied):
                User.objects.filter(pk=self.user.pk).update(first_name='Must not persist')
        self.user.refresh_from_db();self.assertEqual(self.user.first_name,'Original')

    def test_membership_removal_guards_legacy_department(self):
        legacy=Department.objects.create(name='Legacy')
        self.user.department=legacy;self.user.save(update_fields=['department'])
        from . import roster
        original=roster.lock_departments
        guarded=[]
        def record(ids,using='default'):
            guarded.extend(ids);return original(ids,using)
        with patch.object(roster,'lock_departments',side_effect=record):
            Membership.objects.filter(user=self.user).delete()
        self.assertIn(legacy.pk,guarded)
        meeting=Meeting.objects.create(department=legacy,title='Legacy capture',status='Finished')
        self.assertTrue(meeting.historical_roster.entries[0]['member'])

    def test_new_users_with_and_without_explicit_primary_keys_and_legacy_department(self):
        from . import roster
        original=roster.lock_departments
        for index, (explicit, legacy) in enumerate(((False,False),(True,False),(False,True),(True,True))):
            with self.subTest(explicit=explicit,legacy=legacy):
                data={'username':f'creation-{index}'}
                if explicit: data['pk']=10000+index
                if legacy: data['department']=self.department
                with patch.object(roster,'lock_departments',wraps=original) as guard:
                    user=User(**data)
                    self.assertTrue(user._state.adding)
                    user.save()
                self.assertFalse(user._state.adding)
                user.refresh_from_db()
                self.assertTrue(user.public_key)
                self.assertTrue(user.private_key)
                if explicit:self.assertEqual(user.pk,10000+index)
                if legacy:self.assertTrue(any(self.department.pk in call.args[0] for call in guard.call_args_list))
                else:guard.assert_not_called()
                self.assertFalse(Membership.objects.filter(user=user).exists())

    def test_explicit_primary_key_creation_cannot_overwrite_account(self):
        from django.db import IntegrityError
        duplicate=User(pk=self.user.pk,username='overwrite',first_name='Unsafe')
        with self.assertRaises(IntegrityError),transaction.atomic():duplicate.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.username,'operation-user')
        self.assertEqual(self.user.first_name,'Original')

    def test_role_changes_and_same_department_replacement_are_detected(self):
        from . import roster
        membership=Membership.objects.get(user=self.user)
        for mutation in ('role','replacement','active'):
            with self.subTest(mutation=mutation):
                original=roster.lock_departments
                def interleave(ids,using='default'):
                    original(ids,using)
                    if mutation=='role':
                        Membership.objects.filter(pk=membership.pk).update(role='AP')
                    elif mutation=='replacement':
                        # Simulate replacement identity without changing Department IDs.
                        Membership.objects.filter(pk=membership.pk).update(id=membership.pk+10000)
                    else:
                        QuerySet.update(User.objects.filter(pk=self.user.pk),is_active=False)
                with patch.object(roster,'lock_departments',side_effect=interleave):
                    with self.assertRaises(PermissionDenied),transaction.atomic():
                        lock_user_scope([self.user.pk])
                self.assertEqual(Membership.objects.get(pk=membership.pk).role,'O')
                self.user.refresh_from_db();self.assertTrue(self.user.is_active)

    def test_supported_role_replacement_and_finalization_order(self):
        membership=Membership.objects.get(user=self.user)
        membership.role='AP';membership.save(update_fields=['role'])
        membership.delete()
        Membership.objects.create(user=self.user,department=self.department,role='AP')
        meeting=Meeting.objects.create(department=self.department,title='Role capture',status='Finished')
        self.assertEqual(meeting.historical_roster.entries[0]['role'],'AP')
        Membership.objects.filter(user=self.user).delete()
        Membership.objects.create(user=self.user,department=self.department,role='O')
        meeting.historical_roster.refresh_from_db()
        self.assertEqual(meeting.historical_roster.entries[0]['role'],'AP')
