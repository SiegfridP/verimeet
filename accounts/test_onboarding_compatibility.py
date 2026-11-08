"""Repeat existing workflow contracts using their real onboarding fixtures."""
from . import test_batch12, test_central_dashboard, test_dashboard_context
from meetings import tests as meeting_tests


class InvitationCompatibility(test_batch12.Batch12Tests):
    pass


class CentralCompatibility(test_central_dashboard.CentralDashboardTests):
    pass


class ContextCompatibility(test_dashboard_context.DashboardContextTests):
    pass


class SigningCompatibility(meeting_tests.Batch05SigningWorkflowTests):
    pass


class IntegrityCompatibility(meeting_tests.Batch05DocumentIntegrityTests):
    pass
