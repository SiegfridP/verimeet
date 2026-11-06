# Invitation delivery and verification

The default console backend writes email to development output; it does not deliver
to an inbox. Do not retain or share that output: invitation links are bearer secrets.

For SMTP, configure the variables illustrated in `.env.example` in your private
deployment environment. Set `EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend`,
`DEFAULT_FROM_EMAIL` to an authorized sender, and the host, port, username and password
provided by your mail operator. Choose TLS or SSL, never both. Restart the application.
Do not commit credentials. The same backend handles Allauth verification email.

Invitation acceptance requires a matching verified Allauth EmailAddress, including
secondary addresses. Login itself does not globally require email verification.
Invitation GET is confirmation only; acceptance requires a CSRF-protected POST.
If authentication or verification happens in another browser, reopen the original
invitation link, log in, and confirm. No authentication step renews the seven-day expiry.

Sending is synchronous with a 20-second SMTP timeout. A reported send failure rolls
back the replacement and preserves its predecessor. Backend success means submission,
not confirmed inbox receipt. SMTP and database commits cannot be one distributed
transaction: ambiguous transport failures or a later commit failure can still leave
an undelivered message or an unusable link. Retry through the authorized invitation form.

Tests use local in-memory mail storage. Live SMTP delivery and Google provider interaction
must be validated separately in a configured deployment; do not infer either from unit tests.
