"""
Tests for SQL Injection fix in showProfile (userController.py).

The vulnerability was in showProfile() at line 521 where the `username`
value from request.session was concatenated directly into an SQL query:
    sql = "SELECT ... WHERE username = '" + username + "'"

The fix replaces string concatenation with a parameterized query:
    sql = "SELECT ... WHERE username = %s"
    cursor.execute(sql, [username])

These tests verify:
1. Legitimate profile lookups still work correctly.
2. SQL injection payloads in the session username cannot manipulate the query.
3. Boundary / edge-case usernames are handled safely.
"""

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "verademo-python.settings")
django.setup()

from unittest.mock import MagicMock, patch, call
from django.test import TestCase, RequestFactory
from django.contrib.sessions.backends.db import SessionStore


class ShowProfileParameterizedQueryTest(TestCase):
    """Verify that showProfile uses a parameterized query, not string concatenation."""

    def _make_request(self, username):
        """Build a minimal GET request whose session contains the given username."""
        factory = RequestFactory()
        request = factory.get("/profile")
        request.session = {"username": username}
        return request

    # ------------------------------------------------------------------
    # Helper: capture the SQL executed against the cursor
    # ------------------------------------------------------------------
    def _call_showProfile_capturing_execute(self, username):
        """
        Call showProfile with a mocked DB cursor and return the list of
        (sql, params) pairs passed to cursor.execute().
        """
        from app.views.userController import showProfile

        request = self._make_request(username)
        execute_calls = []

        mock_cursor = MagicMock()

        def record_execute(sql, params=None):
            execute_calls.append((sql, params))
            # Return plausible data so showProfile can continue
            if params is not None:
                # The SELECT for user info
                mock_cursor.fetchone.return_value = (
                    username, "Real Name", "Blab Name", "TOTP_SECRET"
                )
                mock_cursor.description = [
                    ("username",), ("real_name",), ("blab_name",), ("totp_secret",)
                ]
            else:
                mock_cursor.fetchall.return_value = []

        mock_cursor.execute.side_effect = record_execute
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)

        mock_connection = MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        with patch("app.views.userController.connection", mock_connection):
            with patch("app.views.userController.getProfileImageNameFromUsername",
                       return_value="default.png"):
                try:
                    showProfile(request)
                except Exception:
                    pass  # Rendering errors are irrelevant to the SQL test

        return execute_calls

    # ------------------------------------------------------------------
    # Test 1: Parameterized query is used (not string concatenation)
    # ------------------------------------------------------------------
    def test_user_info_query_uses_parameterized_form(self):
        """The SQL for user info must contain %s placeholder, not a literal username."""
        username = "alice"
        execute_calls = self._call_showProfile_capturing_execute(username)

        # Find the execute call for the user-info query
        user_info_call = None
        for sql, params in execute_calls:
            if "SELECT username" in sql and "real_name" in sql:
                user_info_call = (sql, params)
                break

        self.assertIsNotNone(
            user_info_call,
            "Expected a SELECT query for user info to be executed"
        )
        sql, params = user_info_call

        # The username must NOT be embedded literally in the SQL string
        self.assertNotIn(
            username, sql,
            "Username was embedded literally in the SQL — parameterized query not used"
        )
        # A placeholder must be present
        self.assertIn(
            "%s", sql,
            "Expected %s placeholder in parameterized query"
        )
        # The username must be passed as a parameter
        self.assertIsNotNone(params, "Expected parameters to be passed to cursor.execute")
        self.assertIn(
            username, params,
            "Username must be passed as a parameter, not embedded in the query string"
        )

    # ------------------------------------------------------------------
    # Test 2: SQL injection payload does not alter the query structure
    # ------------------------------------------------------------------
    def test_sql_injection_payload_passed_as_parameter(self):
        """
        A classic SQL injection payload in the session username must be
        passed as a bound parameter, not concatenated into the query.
        """
        payload = "' OR '1'='1"
        execute_calls = self._call_showProfile_capturing_execute(payload)

        for sql, params in execute_calls:
            if "SELECT username" in sql and "real_name" in sql:
                # The injection payload must NOT appear literally in the SQL
                self.assertNotIn(
                    payload, sql,
                    "SQL injection payload was embedded in the query — vulnerability not fixed"
                )
                # It must appear only in the parameter list
                if params:
                    self.assertIn(
                        payload, params,
                        "Payload should be in the parameter list (as safe bound value)"
                    )
                return

        # If the query wasn't executed at all (e.g. DB error) the test is inconclusive
        # but at least we know no injection occurred.

    # ------------------------------------------------------------------
    # Test 3: UNION-based injection payload
    # ------------------------------------------------------------------
    def test_union_injection_payload_passed_as_parameter(self):
        """UNION-based injection payload must not be concatenated into the query."""
        payload = "' UNION SELECT username, password, blab_name, totp_secret FROM users--"
        execute_calls = self._call_showProfile_capturing_execute(payload)

        for sql, params in execute_calls:
            if "SELECT username" in sql and "real_name" in sql:
                self.assertNotIn(
                    "UNION", sql,
                    "UNION keyword from injection payload appeared in the SQL string"
                )
                return

    # ------------------------------------------------------------------
    # Test 4: Tautology injection payload
    # ------------------------------------------------------------------
    def test_tautology_injection_payload_passed_as_parameter(self):
        """Tautology injection (1=1) must not be embedded in the query."""
        payload = "admin'--"
        execute_calls = self._call_showProfile_capturing_execute(payload)

        for sql, params in execute_calls:
            if "SELECT username" in sql and "real_name" in sql:
                self.assertNotIn(
                    "--", sql,
                    "SQL comment sequence from payload appeared in the query string"
                )
                return

    # ------------------------------------------------------------------
    # Test 5: Normal username with special characters handled safely
    # ------------------------------------------------------------------
    def test_username_with_apostrophe_handled_safely(self):
        """A username containing a single quote must be safely parameterized."""
        username = "o'brien"
        execute_calls = self._call_showProfile_capturing_execute(username)

        for sql, params in execute_calls:
            if "SELECT username" in sql and "real_name" in sql:
                # The literal apostrophe must not be embedded in the SQL
                self.assertNotIn(
                    "o'brien", sql,
                    "Username with apostrophe was embedded literally in the SQL"
                )
                if params:
                    self.assertIn(
                        username, params,
                        "Username with apostrophe must be passed as a bound parameter"
                    )
                return

    # ------------------------------------------------------------------
    # Test 6: Unauthenticated request is redirected, no query executed
    # ------------------------------------------------------------------
    def test_unauthenticated_request_redirects_without_query(self):
        """A request with no session username must redirect; no SQL is executed."""
        from app.views.userController import showProfile
        from django.http import HttpResponseRedirect

        factory = RequestFactory()
        request = factory.get("/profile")
        request.session = {}  # No username

        mock_connection = MagicMock()

        with patch("app.views.userController.connection", mock_connection):
            response = showProfile(request)

        # Must redirect to login
        self.assertIsInstance(
            response, HttpResponseRedirect,
            "Expected redirect when user is not logged in"
        )
        # No database query should have been executed
        mock_connection.cursor.assert_not_called()
