"""
Tests for Second Order SQL Injection remediation (CWE-89).

These tests verify that all SQL queries in the application use Django's
parameterized query API (cursor.execute(sql, params)) rather than string
concatenation or %-formatting, thereby preventing SQL injection attacks.

Second-order SQL injection is particularly dangerous because:
  1. Attacker stores a malicious payload in the database (e.g., via registration).
  2. The application later retrieves that value and uses it in a new SQL query
     via string concatenation — executing the injected SQL.

The fix uses Django's cursor.execute(sql, [params]) throughout, which passes
user-controlled values as bind parameters, never interpolating them into the
SQL string.
"""

import hashlib
from unittest.mock import MagicMock, patch, call

import django
from django.test import TestCase, RequestFactory, override_settings
from django.db import connection


# ---------------------------------------------------------------------------
# Helper: build a minimal fake cursor that records execute() calls
# ---------------------------------------------------------------------------

class FakeCursor:
    """Mock database cursor that records all execute() calls."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.description = []
        self.rowcount = len(self.rows)
        self.execute_calls = []  # list of (sql, params) tuples

    def execute(self, sql, params=None):
        self.execute_calls.append((sql, params))

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeCursorContext:
    """Context manager that yields a FakeCursor."""

    def __init__(self, cursor):
        self.cursor = cursor

    def __enter__(self):
        return self.cursor

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Tests for ListenCommand
# ---------------------------------------------------------------------------

class ListenCommandParameterizedTest(TestCase):
    """Verify ListenCommand uses parameterized queries (no string formatting)."""

    def _make_cursor(self):
        """Return a FakeCursor that returns a blab_name for the SELECT."""
        cursor = FakeCursor(rows=[("Test Blabber",)])
        cursor.description = [("blab_name",)]
        return cursor

    def test_insert_listeners_uses_params(self):
        """INSERT INTO listeners must pass username as a parameter, not inline."""
        from app.commands.ListenCommand import ListenCommand

        cursor = self._make_cursor()
        cmd = ListenCommand(cursor, "alice")
        cmd.execute("bob")

        insert_call = cursor.execute_calls[0]
        sql, params = insert_call

        # The SQL must contain %s placeholders, not the literal values
        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql)
        self.assertNotIn("bob", sql)
        # Values must be passed as parameters
        self.assertIsNotNone(params)
        self.assertIn("bob", params)
        self.assertIn("alice", params)

    def test_select_blab_name_uses_params(self):
        """SELECT blab_name must pass blabberUsername as a parameter."""
        from app.commands.ListenCommand import ListenCommand

        cursor = self._make_cursor()
        cmd = ListenCommand(cursor, "alice")
        cmd.execute("bob")

        select_call = cursor.execute_calls[1]
        sql, params = select_call

        self.assertIn("%s", sql)
        self.assertNotIn("bob", sql)
        self.assertIsNotNone(params)
        self.assertIn("bob", params)

    def test_insert_history_uses_params(self):
        """INSERT INTO users_history must pass blabber and event as parameters."""
        from app.commands.ListenCommand import ListenCommand

        cursor = self._make_cursor()
        cmd = ListenCommand(cursor, "alice")
        cmd.execute("bob")

        history_call = cursor.execute_calls[2]
        sql, params = history_call

        # SQL must not contain literal username values
        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql)
        self.assertIsNotNone(params)
        # alice is the listener (stored as blabber in history)
        self.assertIn("alice", params)

    def test_second_order_injection_payload_in_username_is_neutralized(self):
        """
        A username containing SQL metacharacters stored in DB must be passed
        safely as a parameter — the event string ends up as a bound parameter,
        not interpolated into SQL.
        """
        from app.commands.ListenCommand import ListenCommand

        # Simulate a malicious username retrieved from the database
        malicious_username = "alice'; DROP TABLE users; --"
        cursor = self._make_cursor()
        cmd = ListenCommand(cursor, malicious_username)
        cmd.execute("bob")

        # Verify no call contains the raw SQL payload in the query string
        for sql, params in cursor.execute_calls:
            self.assertNotIn("DROP TABLE", sql,
                             "SQL payload must not appear in the query string")

        # The malicious value appears only in params (safely bound)
        history_call = cursor.execute_calls[2]
        sql, params = history_call
        self.assertIn(malicious_username, params)


# ---------------------------------------------------------------------------
# Tests for IgnoreCommand
# ---------------------------------------------------------------------------

class IgnoreCommandParameterizedTest(TestCase):
    """Verify IgnoreCommand uses parameterized queries."""

    def _make_cursor(self):
        cursor = FakeCursor(rows=[("Test Blabber",)])
        cursor.description = [("blab_name",)]
        return cursor

    def test_delete_listeners_uses_params(self):
        """DELETE FROM listeners must use bind parameters."""
        from app.commands.IgnoreCommand import IgnoreCommand

        cursor = self._make_cursor()
        cmd = IgnoreCommand(cursor, "alice")
        cmd.execute("bob")

        delete_call = cursor.execute_calls[0]
        sql, params = delete_call

        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql)
        self.assertNotIn("bob", sql)
        self.assertIsNotNone(params)
        self.assertIn("bob", params)
        self.assertIn("alice", params)

    def test_insert_history_uses_params(self):
        """INSERT INTO users_history must use bind parameters."""
        from app.commands.IgnoreCommand import IgnoreCommand

        cursor = self._make_cursor()
        cmd = IgnoreCommand(cursor, "alice")
        cmd.execute("bob")

        history_call = cursor.execute_calls[2]
        sql, params = history_call

        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql)
        self.assertIsNotNone(params)
        self.assertIn("alice", params)

    def test_second_order_injection_payload_neutralized(self):
        """Malicious blabberUsername retrieved from DB must not inject SQL."""
        from app.commands.IgnoreCommand import IgnoreCommand

        malicious_blabber = "bob\"); INSERT INTO users VALUES ('hacker','pwned','hint',NULL,NULL,NULL,NULL); --"
        cursor = self._make_cursor()
        cmd = IgnoreCommand(cursor, "alice")
        cmd.execute(malicious_blabber)

        for sql, params in cursor.execute_calls:
            self.assertNotIn("INSERT INTO users", sql,
                             "Injection payload must not appear in the SQL string")


# ---------------------------------------------------------------------------
# Tests for userController SQL queries (unit-level with mock cursor)
# ---------------------------------------------------------------------------

class UserControllerParameterizedQueryTest(TestCase):
    """Unit tests verifying userController queries use parameterized execution."""

    def _mock_connection(self, cursor):
        """Return a context-manager mock that yields the given cursor."""
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=cursor)
        ctx.__exit__ = MagicMock(return_value=False)
        conn_mock = MagicMock()
        conn_mock.cursor.return_value = ctx
        return conn_mock

    # ------------------------------------------------------------------
    # showPasswordHint
    # ------------------------------------------------------------------

    @patch("app.views.userController.connection")
    def test_password_hint_uses_parameterized_query(self, mock_conn):
        """showPasswordHint must use %s + params, never string concatenation."""
        from app.views.userController import showPasswordHint

        cursor = FakeCursor(rows=[("mysecretpassword",)])
        cursor.description = [("password_hint",)]
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.get("/password-hint", {"username": "alice"})

        showPasswordHint(request)

        self.assertEqual(len(cursor.execute_calls), 1)
        sql, params = cursor.execute_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql,
                         "Username must not be interpolated into the SQL string")
        self.assertEqual(params, ["alice"])

    @patch("app.views.userController.connection")
    def test_password_hint_injection_payload_not_in_sql(self, mock_conn):
        """SQL metacharacters in username must not reach the SQL string."""
        from app.views.userController import showPasswordHint

        malicious = "' OR '1'='1"
        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.get("/password-hint", {"username": malicious})
        showPasswordHint(request)

        sql, params = cursor.execute_calls[0]
        self.assertNotIn(malicious, sql)
        self.assertEqual(params, [malicious])

    # ------------------------------------------------------------------
    # processRegister (username duplicate check)
    # ------------------------------------------------------------------

    @patch("app.views.userController.connection")
    def test_process_register_username_check_parameterized(self, mock_conn):
        """processRegister duplicate username check must use bind params."""
        from app.views.userController import processRegister

        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.post("/register", {"username": "newuser"})

        processRegister(request)

        self.assertGreaterEqual(len(cursor.execute_calls), 1)
        sql, params = cursor.execute_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("newuser", sql)
        self.assertEqual(params, ["newuser"])

    # ------------------------------------------------------------------
    # showProfile — sqlMyEvents (the canonical second-order sink)
    # ------------------------------------------------------------------

    @patch("app.views.userController.getProfileImageNameFromUsername",
           return_value=None)
    @patch("app.views.userController.connection")
    def test_show_profile_events_query_parameterized(self, mock_conn, _img):
        """
        showProfile's users_history query must use parameterized execution.

        This is the primary second-order injection sink: username comes from
        the session (set from a DB value), and was previously concatenated
        directly into the SQL string.
        """
        from app.views.userController import showProfile

        # Cursor returns: hecklers=[], events=[], user info row
        heckler_rows = []
        event_rows = []
        user_rows = [("alice", "Alice Real", "AliceBlab", "TOTP_SECRET")]

        # We need the cursor to return different results for each execute call.
        call_count = [0]
        results_sequence = [heckler_rows, event_rows, user_rows]

        class SequencedCursor:
            execute_calls = []
            description = [
                ("username",), ("real_name",), ("blab_name",), ("totp_secret",)
            ]
            rowcount = 0

            def execute(self, sql, params=None):
                self.execute_calls.append((sql, params))

            def fetchone(self):
                idx = len(self.execute_calls) - 1
                rows = results_sequence[min(idx, len(results_sequence) - 1)]
                return rows[0] if rows else None

            def fetchall(self):
                idx = len(self.execute_calls) - 1
                return results_sequence[min(idx, len(results_sequence) - 1)]

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        seq_cursor = SequencedCursor()
        mock_conn.cursor.return_value = seq_cursor

        factory = RequestFactory()
        request = factory.get("/profile")
        request.session = {"username": "alice"}

        showProfile(request)

        # The second execute call is the users_history / events query
        # (first is hecklers, second is events, third is user info)
        self.assertGreaterEqual(len(seq_cursor.execute_calls), 2)

        # Find the users_history query
        history_calls = [
            (sql, params)
            for sql, params in seq_cursor.execute_calls
            if "users_history" in sql.lower()
        ]
        self.assertTrue(history_calls,
                        "Expected a users_history query to be executed")

        sql, params = history_calls[0]
        # Must use %s placeholder
        self.assertIn("%s", sql)
        # Username must NOT be embedded in the SQL string
        self.assertNotIn("alice", sql,
                         "Username must not be interpolated into the SQL string")
        # Must be passed as a parameter
        self.assertIsNotNone(params)
        self.assertIn("alice", params)

    @patch("app.views.userController.getProfileImageNameFromUsername",
           return_value=None)
    @patch("app.views.userController.connection")
    def test_show_profile_hecklers_query_parameterized(self, mock_conn, _img):
        """showProfile's listeners/hecklers query must use parameterized execution."""
        from app.views.userController import showProfile

        class SequencedCursor2:
            execute_calls = []
            description = [
                ("username",), ("real_name",), ("blab_name",), ("totp_secret",)
            ]
            rowcount = 0

            def execute(self, sql, params=None):
                self.execute_calls.append((sql, params))

            def fetchone(self):
                if self.execute_calls and "users" in self.execute_calls[-1][0].lower():
                    return ("alice", "Alice", "AliceBlab", "SECRET")
                return None

            def fetchall(self):
                return []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        seq_cursor = SequencedCursor2()
        mock_conn.cursor.return_value = seq_cursor

        factory = RequestFactory()
        request = factory.get("/profile")
        request.session = {"username": "alice"}

        showProfile(request)

        listener_calls = [
            (sql, params)
            for sql, params in seq_cursor.execute_calls
            if "listeners" in sql.lower()
        ]
        self.assertTrue(listener_calls)
        sql, params = listener_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("alice", sql)
        self.assertIsNotNone(params)
        self.assertIn("alice", params)

    # ------------------------------------------------------------------
    # updateUsername — batch UPDATE queries
    # ------------------------------------------------------------------

    @patch("app.views.userController.getProfileImageNameFromUsername",
           return_value=None)
    @patch("app.views.userController.transaction")
    @patch("app.views.userController.connection")
    def test_update_username_queries_parameterized(self, mock_conn,
                                                   mock_txn, _img):
        """All UPDATE queries in updateUsername must use bind parameters."""
        from app.views.userController import updateUsername

        cursor = FakeCursor()
        # transaction.atomic() context manager
        mock_txn.atomic.return_value.__enter__ = MagicMock(return_value=None)
        mock_txn.atomic.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        updateUsername("alice", "alice_new")

        self.assertGreater(len(cursor.execute_calls), 0,
                           "Expected at least one UPDATE to be executed")

        for sql, params in cursor.execute_calls:
            # Every query must use %s placeholders
            self.assertIn("%s", sql,
                          f"Query must use %s placeholders: {sql!r}")
            # Old/new usernames must not be embedded in the SQL string
            self.assertNotIn("alice_new", sql,
                             f"New username must not be in SQL: {sql!r}")
            self.assertNotIn("alice", sql,
                             f"Old username must not be in SQL: {sql!r}")
            # Values must be passed as parameters
            self.assertIsNotNone(params)
            self.assertIn("alice_new", params)
            self.assertIn("alice", params)

    def test_update_username_second_order_payload_not_in_sql(self):
        """
        A username that was stored in DB with SQL injection payload must not
        cause SQL injection when updateUsername is called.

        This exercises the second-order scenario: attacker registers with a
        username like  alice'; UPDATE users SET password='pwned' WHERE '1'='1
        and the app later calls updateUsername() with that stored value.
        """
        from unittest.mock import patch, MagicMock

        malicious_old = "alice'; UPDATE users SET password='pwned' WHERE '1'='1"
        malicious_new = "alice_new"

        cursor = FakeCursor()

        with patch("app.views.userController.transaction") as mock_txn, \
             patch("app.views.userController.connection") as mock_conn, \
             patch("app.views.userController.getProfileImageNameFromUsername",
                   return_value=None):

            mock_txn.atomic.return_value.__enter__ = MagicMock(return_value=None)
            mock_txn.atomic.return_value.__exit__ = MagicMock(return_value=False)
            mock_conn.cursor.return_value = FakeCursorContext(cursor)

            updateUsername(malicious_old, malicious_new)

        for sql, params in cursor.execute_calls:
            self.assertNotIn("UPDATE users SET password", sql,
                             "Injection payload must not appear in query string")


# ---------------------------------------------------------------------------
# Tests for processProfile UPDATE query
# ---------------------------------------------------------------------------

class ProcessProfileParameterizedTest(TestCase):
    """Verify processProfile UPDATE query is parameterized."""

    @patch("app.views.userController.connection")
    def test_update_profile_parameterized(self, mock_conn):
        """UPDATE users SET real_name/blab_name must use bind parameters."""
        from app.views.userController import processProfile

        cursor = FakeCursor(rows=[])   # fetchone returns None → success path
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.post(
            "/profile",
            {
                "username": "alice",
                "realName": "Alice Wonderland",
                "blabName": "AliceBlab",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        request.session = {"username": "alice"}

        processProfile(request)

        update_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "UPDATE users" in sql
        ]
        self.assertTrue(update_calls,
                        "Expected an UPDATE users query")
        sql, params = update_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("Alice Wonderland", sql)
        self.assertNotIn("AliceBlab", sql)
        self.assertNotIn("alice", sql)
        self.assertIsNotNone(params)
        self.assertIn("Alice Wonderland", params)
        self.assertIn("AliceBlab", params)
        self.assertIn("alice", params)

    @patch("app.views.userController.connection")
    def test_update_profile_second_order_realname_not_in_sql(self, mock_conn):
        """
        Real name stored with SQL payload must not inject SQL on profile update.

        Scenario: attacker previously set real_name to a SQL payload via a
        stored value. On profile update, that value is used again — it must be
        a bound parameter, not interpolated.
        """
        from app.views.userController import processProfile

        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        malicious_real_name = "hacker', 'hacked'); DROP TABLE users; --"
        request = factory.post(
            "/profile",
            {
                "username": "alice",
                "realName": malicious_real_name,
                "blabName": "safe",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        request.session = {"username": "alice"}

        processProfile(request)

        for sql, params in cursor.execute_calls:
            self.assertNotIn("DROP TABLE", sql,
                             "SQL payload must not appear in the query string")


# ---------------------------------------------------------------------------
# Tests for blabController SQL queries
# ---------------------------------------------------------------------------

class BlabControllerParameterizedTest(TestCase):
    """Verify blabController uses parameterized queries throughout."""

    @patch("app.views.blabController.connection")
    def test_feed_post_add_blab_parameterized(self, mock_conn):
        """INSERT INTO blabs must pass blab content as a parameter."""
        from app.views.blabController import feed

        cursor = FakeCursor()
        cursor.rowcount = 1
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.post("/feed", {"blab": "Hello World"})
        request.session = {"username": "alice"}
        request.headers  # ensure headers dict exists

        feed(request)

        insert_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "INSERT INTO blabs" in sql
        ]
        self.assertTrue(insert_calls, "Expected INSERT INTO blabs")
        sql, params = insert_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("Hello World", sql)
        self.assertNotIn("alice", sql)
        self.assertIsNotNone(params)
        self.assertIn("alice", params)
        self.assertIn("Hello World", params)

    @patch("app.views.blabController.connection")
    def test_blab_get_details_parameterized(self, mock_conn):
        """SELECT blabs/comments by blabid must use bind parameters."""
        from app.views.blabController import blab

        cursor = FakeCursor(rows=[("Content here", "SomeBlab")])
        cursor.description = [("content",), ("blab_name",)]
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.get("/blab", {"blabid": "42"})
        request.session = {"username": "alice"}

        blab(request)

        detail_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "blabs" in sql.lower() and "WHERE" in sql
        ]
        self.assertTrue(detail_calls)
        sql, params = detail_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("42", sql)
        self.assertIsNotNone(params)
        self.assertIn("42", params)

    @patch("app.views.blabController.connection")
    def test_blab_post_add_comment_parameterized(self, mock_conn):
        """INSERT INTO comments must pass all values as parameters."""
        from app.views.blabController import blab

        cursor = FakeCursor()
        cursor.rowcount = 1
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.post("/blab", {
            "blabid": "42",
            "comment": "Great post!",
        })
        request.session = {"username": "alice"}

        blab(request)

        comment_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "INSERT INTO comments" in sql
        ]
        self.assertTrue(comment_calls, "Expected INSERT INTO comments")
        sql, params = comment_calls[0]
        self.assertIn("%s", sql)
        self.assertNotIn("Great post!", sql)
        self.assertNotIn("alice", sql)
        self.assertNotIn("42", sql)
        self.assertIsNotNone(params)
        self.assertIn("alice", params)
        self.assertIn("Great post!", params)

    @patch("app.views.blabController.connection")
    def test_blabbers_sort_allowlist_rejects_injection(self, mock_conn):
        """
        ORDER BY parameter must be validated against an allowlist.
        An attempt to inject SQL via the sort parameter must be rejected.
        """
        from app.views.blabController import blabbers

        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        # Attempt ORDER BY injection
        malicious_sort = "blab_name; DROP TABLE users; --"
        request = factory.get("/blabbers", {"sort": malicious_sort})
        request.session = {"username": "alice"}

        blabbers(request)

        # The malicious sort must not appear in any executed SQL
        for sql, params in cursor.execute_calls:
            self.assertNotIn("DROP TABLE", sql,
                             "Sort injection payload must not appear in SQL")

    @patch("app.views.blabController.connection")
    def test_blabbers_sort_allowlist_accepts_valid_sort(self, mock_conn):
        """A valid sort value from the allowlist must be accepted."""
        from app.views.blabController import blabbers

        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.get("/blabbers", {"sort": "created_at DESC"})
        request.session = {"username": "alice"}

        blabbers(request)

        sort_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "ORDER BY" in sql
        ]
        self.assertTrue(sort_calls, "Expected an ORDER BY query")
        sql, _ = sort_calls[0]
        self.assertIn("created_at DESC", sql)

    @patch("app.views.blabController.connection")
    def test_blabbers_sort_defaults_to_safe_value(self, mock_conn):
        """Missing or unknown sort value must default to the safe default."""
        from app.views.blabController import blabbers

        cursor = FakeCursor(rows=[])
        mock_conn.cursor.return_value = FakeCursorContext(cursor)

        factory = RequestFactory()
        request = factory.get("/blabbers")  # no sort param
        request.session = {"username": "alice"}

        blabbers(request)

        sort_calls = [
            (sql, params)
            for sql, params in cursor.execute_calls
            if "ORDER BY" in sql
        ]
        self.assertTrue(sort_calls)
        sql, _ = sort_calls[0]
        self.assertIn("blab_name ASC", sql)


# ---------------------------------------------------------------------------
# Integration-style tests: verify no raw string interpolation remains
# ---------------------------------------------------------------------------

class NoStringInterpolationInQueriesTest(TestCase):
    """
    Regression tests that confirm the fix pattern is in place by inspecting
    the source code itself.  These tests will fail if string concatenation /
    %-formatting is re-introduced into SQL queries.
    """

    def _load_source(self, path):
        import os
        base = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        with open(os.path.join(base, path)) as f:
            return f.read()

    def _count_parameterized(self, source):
        """Count cursor.execute() calls that pass a params argument."""
        import re
        # Match:  cursor.execute(something, [... or (... or params_var
        return len(re.findall(
            r'cursor\.execute\s*\([^)]+,\s*[\[\(]', source))

    def _count_unsafe_execute(self, source):
        """
        Count cursor.execute() calls that use % or + to build the SQL.
        We look for execute calls where the argument contains % or +
        followed by a variable (simplified heuristic).
        """
        import re
        # Detect  cursor.execute(sql % ...  or  cursor.execute("..." + var
        return len(re.findall(
            r'cursor\.execute\s*\([^,)]*(?:%\s*[(\w]|\+\s*\w)', source))

    def test_listen_command_no_format_string_sql(self):
        source = self._load_source("app/commands/ListenCommand.py")
        unsafe = self._count_unsafe_execute(source)
        self.assertEqual(unsafe, 0,
                         "ListenCommand must not use %-format or + for SQL queries")

    def test_ignore_command_no_format_string_sql(self):
        source = self._load_source("app/commands/IgnoreCommand.py")
        unsafe = self._count_unsafe_execute(source)
        self.assertEqual(unsafe, 0,
                         "IgnoreCommand must not use %-format or + for SQL queries")

    def test_listen_command_has_parameterized_executes(self):
        source = self._load_source("app/commands/ListenCommand.py")
        count = self._count_parameterized(source)
        self.assertGreaterEqual(count, 3,
                                "ListenCommand should have at least 3 parameterized executes")

    def test_ignore_command_has_parameterized_executes(self):
        source = self._load_source("app/commands/IgnoreCommand.py")
        count = self._count_parameterized(source)
        self.assertGreaterEqual(count, 3,
                                "IgnoreCommand should have at least 3 parameterized executes")
