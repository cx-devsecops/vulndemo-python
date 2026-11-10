import base64
import json
import os
import pickle
from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase

from app.models import User
from app.views import userController


class _Exploit:
    """Pickle payload that would run a command if it were ever deserialized."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


class RememberMeCookieTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _login_get(self, cookie_value):
        request = self.factory.get('/login')
        request.session = {}
        request.COOKIES['user'] = cookie_value
        with mock.patch.object(userController, 'redirect',
                               side_effect=lambda to, *a, **k: HttpResponse(status=302)) as redirect_mock, \
                mock.patch.object(userController, 'render',
                                  side_effect=lambda *a, **k: HttpResponse('login')) as render_mock:
            response = userController.login(request)
        return request, response, redirect_mock, render_mock

    def test_json_cookie_round_trip_logs_user_in(self):
        cookie_response = userController.updateInResponse(User(username='alice'), HttpResponse())
        cookie = cookie_response.cookies['user'].value

        request, _, redirect_mock, _ = self._login_get(cookie)

        self.assertEqual(request.session['username'], 'alice')
        redirect_mock.assert_called_once_with('feed')

    def test_cookie_contains_only_json_data(self):
        response = userController.updateInResponse(User(username='bob'), HttpResponse())
        decoded = base64.b64decode(response.cookies['user'].value)
        self.assertEqual(json.loads(decoded), {'username': 'bob'})

    def test_malicious_pickle_cookie_is_not_deserialized(self):
        cookie = base64.b64encode(pickle.dumps(_Exploit())).decode('ASCII')

        with mock.patch('os.system') as system_mock, \
                mock.patch('pickle.loads') as loads_mock:
            request, _, redirect_mock, render_mock = self._login_get(cookie)

        loads_mock.assert_not_called()
        system_mock.assert_not_called()
        self.assertNotIn('username', request.session)
        redirect_mock.assert_not_called()
        render_mock.assert_called_once()

    def test_malformed_cookies_are_rejected(self):
        bad_values = [
            '!!!not-base64!!!',
            base64.b64encode(b'not json').decode('ASCII'),
            base64.b64encode(b'[1, 2, 3]').decode('ASCII'),
            base64.b64encode(json.dumps({'username': 123}).encode()).decode('ASCII'),
            base64.b64encode(json.dumps({}).encode()).decode('ASCII'),
        ]
        for value in bad_values:
            with self.subTest(cookie=value):
                request, _, redirect_mock, _ = self._login_get(value)
                self.assertNotIn('username', request.session)
                redirect_mock.assert_not_called()
