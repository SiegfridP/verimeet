"""Standalone local PostgreSQL tests. Does not import core.settings or dotenv."""
import os
from base64 import urlsafe_b64encode
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'isolated-postgresql-tests-only-not-for-deployment'
DEBUG = False
ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']
AUTH_USER_MODEL = 'accounts.User'
INSTALLED_APPS = [
    'django.contrib.admin', 'django.contrib.auth', 'django.contrib.contenttypes',
    'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles',
    'accounts', 'meetings', 'allauth', 'allauth.account', 'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware', 'accounts.middleware.OnboardingMiddleware',
]
TEMPLATES = [{'BACKEND':'django.template.backends.django.DjangoTemplates', 'APP_DIRS':True,
              'OPTIONS':{'context_processors':[
                  'django.template.context_processors.request',
                  'django.contrib.auth.context_processors.auth',
                  'django.contrib.messages.context_processors.messages']}}]
ROOT_URLCONF = 'core.urls'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'UTC'
STATIC_URL = '/static/'
MEDIA_URL = '/media/'
STORAGES = {'default':{'BACKEND':'django.core.files.storage.InMemoryStorage'},
            'staticfiles':{'BACKEND':'django.contrib.staticfiles.storage.StaticFilesStorage'}}
MAILERS = {'default':{'BACKEND':'django.core.mail.backends.locmem.EmailBackend'}}
EMAIL_PRODUCTION = False
APPLICATION_ORIGIN = ''
RESEND_API_KEY = ''
SOCIALACCOUNT_PROVIDERS = {'google':{'APP':{'client_id':'local-test', 'secret':'local-test', 'key':''}}}
LOGIN_REDIRECT_URL = '/accounts/route/'
LOGOUT_REDIRECT_URL = '/'
LOGIN_URL = 'account_login'
ACCOUNT_ADAPTER = 'accounts.adapter.InvitationAccountAdapter'
SOCIALACCOUNT_ADAPTER = 'accounts.adapter.OnboardingSocialAdapter'
ACCOUNT_EMAIL_SUBJECT_PREFIX = ''
PRODUCTION = False
DURABLE_EVIDENCE = False
EVIDENCE_BACKEND = 'database'
EVIDENCE_ENDPOINT = EVIDENCE_BUCKET = EVIDENCE_ACCESS_KEY_ID = EVIDENCE_SECRET_ACCESS_KEY = ''
SIGNATURE_RETENTION_DAYS = 90
# App signing helpers currently consume this environment variable directly.
os.environ['SIGNING_KEY_ENCRYPTION_KEY'] = urlsafe_b64encode(b'0' * 32).decode()
DATABASES = {
    'default':{
        'ENGINE':'django.db.backends.postgresql',
        'HOST':'127.0.0.1', 'PORT':'5432',
        'NAME':'verimeet_concurrency_test', 'USER':'verimeet_test_user1',
        'PASSWORD':os.environ.get('VERIMEET_PG_TEST_PASSWORD', ''),
        'ATOMIC_REQUESTS':False, 'AUTOCOMMIT':True, 'CONN_MAX_AGE':0,
        'OPTIONS':{'connect_timeout':5, 'sslmode':'disable',
                   'options':'-c lock_timeout=5000 -c statement_timeout=30000'},
        'TEST':{'NAME':'verimeet_concurrency_test'},
    },
    # Existing alias-isolation regressions use a separate in-memory database.
    'deletion_test':{'ENGINE':'django.db.backends.sqlite3',
                     'NAME':'file:memorydb_deletion_test?mode=memory&cache=shared',
                     'ATOMIC_REQUESTS':False,
                     'TEST':{'NAME':'file:memorydb_deletion_test?mode=memory&cache=shared'}},
}
DEPARTMENT_DELETION_SESSION_AFFINITY = {'default':'direct'}
TEST_RUNNER = 'accounts.run_postgres_department_tests.DisposableDatabaseRunner'

# Installed at settings import: management commands cannot bypass runner consent.
from accounts.run_postgres_department_tests import install_guards
install_guards()
