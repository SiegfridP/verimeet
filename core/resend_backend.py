"""HTTPS submission backend; provider acceptance is not inbox delivery."""
import json
from urllib.request import Request, build_opener, HTTPRedirectHandler
from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urlopen(request, timeout):
    return build_opener(NoRedirect).open(request, timeout=timeout)


class EmailBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        sent = 0
        for message in email_messages:
            try:
                if message.attachments:
                    raise ValueError('Attachments are unsupported by this backend.')
                payload = {'from': message.from_email, 'to': message.to,
                           'subject': message.subject, 'text': message.body}
                for field in ('cc', 'bcc', 'reply_to'):
                    if getattr(message, field):
                        payload[field] = getattr(message, field)
                for alternative in getattr(message, 'alternatives', []):
                    if alternative[1] == 'text/html':
                        payload['html'] = alternative[0]
                request = Request('https://api.resend.com/emails',
                                  data=json.dumps(payload).encode(), method='POST',
                                  headers={'Authorization': 'Bearer ' + settings.RESEND_API_KEY,
                                           'Content-Type': 'application/json',
                                           'User-Agent': 'VeriMeet'})
                with urlopen(request, timeout=settings.RESEND_TIMEOUT) as response:
                    result = json.loads(response.read(65536))
                    if response.status != 200 or not isinstance(result.get('id'), str) or not result['id']:
                        raise ValueError('Submission not accepted.')
                sent += 1
            except Exception:
                if not self.fail_silently:
                    raise RuntimeError('Email provider submission failed.') from None
        return sent
