"""Existing workflow contracts for participants whose PNG requirement is satisfied.

The real validation and enforcement paths are exercised in test_onboarding.
"""
from unittest.mock import patch
from . import test_batch12, test_central_dashboard, test_dashboard_context
from meetings import tests as meeting_tests


class CompletedSignature:
    def setUp(self):
        guard = patch('accounts.signatures.signature_valid', return_value=True)
        guard.start()
        self.addCleanup(guard.stop)
        super().setUp()


class InvitationCompatibility(CompletedSignature, test_batch12.Batch12Tests):
    pass


class CentralCompatibility(CompletedSignature, test_central_dashboard.CentralDashboardTests):
    pass


class ContextCompatibility(CompletedSignature, test_dashboard_context.DashboardContextTests):
    pass


class SigningCompatibility(CompletedSignature, meeting_tests.Batch05SigningWorkflowTests):
    pass


class IntegrityCompatibility(CompletedSignature, meeting_tests.Batch05DocumentIntegrityTests):
    pass
