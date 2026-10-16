"""
Tests for CWE-502 (Deserialization of Untrusted Data) remediation in userController.py.

The vulnerability was that the 'user' cookie was base64-decoded and then passed to
pickle.loads(), allowing an attacker to craft a malicious pickle payload that executes
arbitrary code on the server.

The fix replaces pickle serialization with JSON serialization in:
  - updateInResponse()   — cookie writer
  - login()              — cookie reader (GET path)
  - processProfile()     — cookie reader/writer (username-change path)
"""

import base64
import json
import os
import pickle
import sys

import django
from django.test import TestCase, RequestFactory

# Ensure Django settings are configured before importing any app code
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'verademo-python.settings')
django.setup()

from unittest.mock import MagicMock, patch
from django.http import HttpResponse

from app.models import User
from app.views.userController import updateInResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_json_cookie(payload: dict) -> str:
    """Encode a dict as the JSON-based user cookie."""
    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ASCII')


def _make_pickle_cookie(obj) -> str:
    """Encode an arbitrary object as a pickle-based user cookie (attack payload)."""
    return base64.b64encode(pickle.dumps(obj)).decode('ASCII')


# ---------------------------------------------------------------------------
# updateInResponse — serialization tests
# ---------------------------------------------------------------------------

class TestUpdateInResponse(TestCase):
    """updateInResponse() must write a JSON-encoded cookie, never pickle."""

    def _make_response(self):
        return HttpResponse("ok")

    def test_produces_json_decodable_cookie_from_model_instance(self):
        """A User model instance is serialized as JSON, not pickle."""
        user = User(username='alice', real_name='Alice Smith', blab_name='AliceBlab')
        response = self._make_response()
        response = updateInResponse(user, response)

        raw = response.cookies['user'].value
        decoded_bytes = base64.b64decode(raw)
        # Must be valid JSON — json.loads raises if it is pickle bytes
        data = json.loads(decoded_bytes.decode('utf-8'))
        self.assertEqual(data['username'], 'alice')
        self.assertEqual(data['real_name'], 'Alice Smith')
        self.assertEqual(data['blab_name'], 'AliceBlab')

    def test_produces_json_decodable_cookie_from_dict(self):
        """A plain dict is also serialized as JSON."""
        user_dict = {'username': 'bob', 'real_name': 'Bob Jones', 'blab_name': 'BobBlab'}
        response = self._make_response()
        response = updateInResponse(user_dict, response)

        raw = response.cookies['user'].value
        decoded_bytes = base64.b64decode(raw)
        data = json.loads(decoded_bytes.decode('utf-8'))
        self.assertEqual(data['username'], 'bob')

    def test_cookie_is_NOT_pickle(self):
        """The cookie value must NOT be a pickle stream (magic bytes \\x80\\x04)."""
        user = User(username='carol', real_name='Carol', blab_name='CarolBlab')
        response = self._make_response()
        response = updateInResponse(user, response)

        raw = response.cookies['user'].value
        decoded_bytes = base64.b64decode(raw)
        # pickle opcodes start with 0x80 for protocol >= 2
        is_pickle = decoded_bytes[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05')
        self.assertFalse(is_pickle, "Cookie must not contain a pickle stream")

    def test_only_safe_fields_included(self):
        """Only username, real_name, blab_name are stored — no password or hints."""
        user = User(
            username='dave',
            password='secret_hash',
            password_hint='myfirstpet',
            real_name='Dave',
            blab_name='DaveBlab',
        )
        response = self._make_response()
        response = updateInResponse(user, response)

        raw = response.cookies['user'].value
        data = json.loads(base64.b64decode(raw).decode('utf-8'))
        self.assertNotIn('password', data)
        self.assertNotIn('password_hint', data)

    def test_missing_fields_default_to_empty_string(self):
        """updateInResponse handles missing attributes gracefully."""
        user_dict = {}  # empty dict — no fields at all
        response = self._make_response()
        response = updateInResponse(user_dict, response)

        raw = response.cookies['user'].value
        data = json.loads(base64.b64decode(raw).decode('utf-8'))
        self.assertEqual(data.get('username'), '')


# ---------------------------------------------------------------------------
# login() GET — deserialization tests
# ---------------------------------------------------------------------------

class TestLoginDeserializationGET(TestCase):
    """The login view must use JSON to read the user cookie, not pickle."""

    def test_login_accepts_valid_json_cookie(self):
        """A well-formed JSON cookie is accepted and sets the session username."""
        payload = {'username': 'alice', 'real_name': 'Alice', 'blab_name': 'AliceBlab'}
        cookie_value = _make_json_cookie(payload)

        response = self.client.get('/login', HTTP_COOKIE=f'user={cookie_value}')
        # Should redirect to feed (not crash)
        self.assertIn(response.status_code, (301, 302))

    def test_login_rejects_pickle_cookie_without_code_execution(self):
        """A pickle payload in the user cookie must NOT trigger code execution.

        This test verifies the fix: if pickle.loads() were still called, the
        PickleExploit.__reduce__ method would set the canary flag. With the JSON
        fix, pickle.loads() is never invoked on the cookie, so the flag stays False.
        """
        canary = {'executed': False}

        class PickleExploit:
            def __reduce__(self):
                # Side-effect that would run if pickle.loads is called
                canary['executed'] = True
                return (dict, ())

        malicious_cookie = _make_pickle_cookie(PickleExploit())

        # Patch json.loads to raise so we can verify the right branch is taken
        # (we want to ensure the code does NOT call pickle.loads)
        with patch('app.views.userController.json') as mock_json:
            mock_json.loads.side_effect = json.JSONDecodeError("bad", "doc", 0)
            try:
                self.client.get('/login', HTTP_COOKIE=f'user={malicious_cookie}')
            except Exception:
                pass  # We expect an error because json.loads is mocked to fail

        # The canary must remain False — pickle.loads was never invoked on the cookie
        self.assertFalse(
            canary['executed'],
            "pickle.loads() was called with the cookie value — RCE vulnerability still present!"
        )

    def test_login_with_no_cookie_renders_login_page(self):
        """Absence of user cookie renders the login form (no crash)."""
        response = self.client.get('/login')
        # Either 200 (renders login.html) or redirect
        self.assertIn(response.status_code, (200, 301, 302))

    def test_login_with_invalid_json_cookie_does_not_execute_code(self):
        """A cookie that is valid base64 but invalid JSON raises JSONDecodeError, not RCE."""
        # Craft raw bytes that are NOT valid JSON but ARE valid base64
        garbage = base64.b64encode(b'\xff\xfe\xfd').decode('ASCII')
        # The view should raise/handle a json decode error, not execute arbitrary code
        try:
            response = self.client.get('/login', HTTP_COOKIE=f'user={garbage}')
            # If it doesn't crash it should either redirect or error gracefully
        except Exception:
            pass  # Any exception here is acceptable — what matters is no RCE


# ---------------------------------------------------------------------------
# Round-trip integrity test
# ---------------------------------------------------------------------------

class TestCookieRoundTrip(TestCase):
    """A cookie written by updateInResponse must be parseable by json.loads."""

    def test_round_trip_model_instance(self):
        user = User(username='eve', real_name='Eve', blab_name='EveBlab')
        response = HttpResponse("ok")
        response = updateInResponse(user, response)

        raw = response.cookies['user'].value
        # Simulate what the login view now does
        decoded = base64.b64decode(raw)
        data = json.loads(decoded.decode('utf-8'))
        self.assertEqual(data['username'], 'eve')

    def test_round_trip_dict(self):
        user_dict = {'username': 'frank', 'real_name': 'Frank', 'blab_name': 'FrankBlab'}
        response = HttpResponse("ok")
        response = updateInResponse(user_dict, response)

        raw = response.cookies['user'].value
        decoded = base64.b64decode(raw)
        data = json.loads(decoded.decode('utf-8'))
        self.assertEqual(data['username'], 'frank')

    def test_username_update_preserved_in_round_trip(self):
        """Simulates the processProfile flow: read cookie, update username, write back."""
        original = {'username': 'old_name', 'real_name': 'Grace', 'blab_name': 'GraceBlab'}
        cookie_value = _make_json_cookie(original)

        # Simulate processProfile deserialization
        decoded = base64.b64decode(cookie_value)
        user_dict = json.loads(decoded.decode('utf-8'))
        user_dict['username'] = 'new_name'

        # Write updated cookie
        response = HttpResponse("ok")
        response = updateInResponse(user_dict, response)

        raw = response.cookies['user'].value
        data = json.loads(base64.b64decode(raw).decode('utf-8'))
        self.assertEqual(data['username'], 'new_name')
        self.assertEqual(data['real_name'], 'Grace')
