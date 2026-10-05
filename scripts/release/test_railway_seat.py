#!/usr/bin/env python3
"""Unit tests for railway_seat.py. Run: python3 scripts/release/test_railway_seat.py"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("railway_seat", Path(__file__).with_name("railway_seat.py"))
assert SPEC and SPEC.loader
seat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seat)

DIGEST_NEW = "sha256:" + "a" * 64
DIGEST_OLD = "sha256:" + "b" * 64


def deployment(identifier: str, status: str, created: str, digest: str = DIGEST_OLD) -> dict:
    return {"id": identifier, "status": status, "createdAt": created, "meta": {"imageDigest": digest}}


# Shape of `railway deployment list --json` after a stop-then-start deploy:
# the stopped previous deployment still reports SUCCESS.
AFTER_DEPLOY = [
    deployment("live", "SUCCESS", "2026-10-05T10:17:33.764Z", DIGEST_NEW),
    deployment("stopped", "SUCCESS", "2026-10-01T10:35:12.659Z", DIGEST_OLD),
    deployment("removed", "REMOVED", "2026-09-28T17:50:38.733Z"),
]


def stopped_set(*ids: str):
    return lambda identifier: identifier in ids


class SelectOldTests(unittest.TestCase):
    def test_two_success_rows_pick_the_one_not_stopped(self) -> None:
        old = seat.select_old(AFTER_DEPLOY, stopped_set("stopped"))
        self.assertEqual(old["id"], "live")
        self.assertEqual(seat.digest_of(old), DIGEST_NEW)

    def test_single_success_row(self) -> None:
        rows = [deployment("only", "SUCCESS", "2026-10-01T00:00:00Z"), deployment("x", "REMOVED", "2026-09-01T00:00:00Z")]
        self.assertEqual(seat.select_old(rows, stopped_set())["id"], "only")

    def test_two_running_rows_abort(self) -> None:
        with self.assertRaisesRegex(seat.SelectionError, "found 2"):
            seat.select_old(AFTER_DEPLOY, stopped_set())

    def test_all_stopped_aborts(self) -> None:
        with self.assertRaisesRegex(seat.SelectionError, "found 0"):
            seat.select_old(AFTER_DEPLOY, stopped_set("live", "stopped"))

    def test_stopped_lookup_only_for_success_rows(self) -> None:
        asked: list[str] = []

        def is_stopped(identifier: str) -> bool:
            asked.append(identifier)
            return identifier == "stopped"

        seat.select_old(AFTER_DEPLOY, is_stopped)
        self.assertEqual(asked, ["live", "stopped"])


class InflightAndNewTests(unittest.TestCase):
    def test_inflight_counts_non_terminal(self) -> None:
        rows = AFTER_DEPLOY + [deployment("building", "BUILDING", "2026-10-05T11:00:00Z")]
        self.assertEqual([d["id"] for d in seat.inflight(rows)], ["building"])
        self.assertEqual(seat.inflight(AFTER_DEPLOY), [])

    def test_find_new_ignores_old_and_earlier_rows(self) -> None:
        rows = [deployment("new", "DEPLOYING", "2026-10-05T10:17:33.764Z", DIGEST_NEW)] + AFTER_DEPLOY[1:]
        self.assertEqual(seat.find_new(rows, "stopped", "2026-10-05T10:17:00Z")["id"], "new")
        self.assertIsNone(seat.find_new(rows, "new", "2026-10-05T10:17:00Z"))
        self.assertIsNone(seat.find_new(rows, "stopped", "2026-10-05T10:18:00Z"))

    def test_running_after_deploy_is_exactly_the_new_one(self) -> None:
        live = seat.running(AFTER_DEPLOY, stopped_set("stopped"))
        self.assertEqual([d["id"] for d in live], ["live"])


class TokenTests(unittest.TestCase):
    def _config(self, user: dict) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"user": user}, handle)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_prefers_access_token(self) -> None:
        self.assertEqual(seat.load_token(self._config({"accessToken": "new", "token": "old"})), "new")

    def test_falls_back_to_token(self) -> None:
        self.assertEqual(seat.load_token(self._config({"token": "old"})), "old")

    def test_missing_token_aborts(self) -> None:
        with self.assertRaises(seat.SelectionError):
            seat.load_token(self._config({}))


if __name__ == "__main__":
    unittest.main()
