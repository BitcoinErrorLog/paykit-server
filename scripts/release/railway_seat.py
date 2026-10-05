#!/usr/bin/env python3
"""Railway helpers for scripts/release/deploy-seat.sh.

Railway keeps a stopped deployment at status SUCCESS, so "the live deployment"
is the SUCCESS deployment whose GraphQL `deploymentStopped` is false. Every
selection below goes through that predicate.

The Railway token is read from the CLI session (~/.railway/config.json,
`user.accessToken`, falling back to `user.token`) and is never printed.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime
from typing import Callable, Iterable

GRAPHQL_URL = "https://backboard.railway.app/graphql/v2"
# Cloudflare answers 403 (error 1010) to requests without a User-Agent.
USER_AGENT = "paykit-release/1.0"
TERMINAL_STATUSES = {"SUCCESS", "REMOVED", "FAILED", "CRASHED", "SKIPPED"}


class SelectionError(Exception):
    pass


def load_token(config_path: str | None = None) -> str:
    path = config_path or os.path.expanduser("~/.railway/config.json")
    with open(path, encoding="utf-8") as handle:
        user = json.load(handle).get("user") or {}
    token = user.get("accessToken") or user.get("token")
    if not token:
        raise SelectionError(f"no user.accessToken or user.token in {path}; run `railway login`")
    return token


def gql(query: str, token: str | None = None) -> dict:
    body = json.dumps({"query": query}).encode()
    request = urllib.request.Request(
        GRAPHQL_URL,
        data=body,
        headers={
            "Authorization": "Bearer " + (token or load_token()),
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read())
    if payload.get("errors"):
        messages = "; ".join(str(error.get("message")) for error in payload["errors"])
        raise SelectionError(f"GraphQL error: {messages}")
    return payload["data"]


def deployment_stopped(deployment_id: str) -> bool:
    data = gql('{ deployment(id: "%s") { deploymentStopped } }' % deployment_id)
    return bool(data["deployment"]["deploymentStopped"])


def stop_deployment(deployment_id: str) -> bool:
    data = gql('mutation { deploymentStop(id: "%s") }' % deployment_id)
    return data.get("deploymentStop") is True


def digest_of(deployment: dict) -> str:
    return (deployment.get("meta") or {}).get("imageDigest") or ""


def running(deployments: Iterable[dict], is_stopped: Callable[[str], bool]) -> list[dict]:
    """SUCCESS deployments that are not stopped, newest first as listed."""
    return [d for d in deployments if d.get("status") == "SUCCESS" and not is_stopped(d["id"])]


def inflight(deployments: Iterable[dict]) -> list[dict]:
    return [d for d in deployments if d.get("status") not in TERMINAL_STATUSES]


def select_old(deployments: list[dict], is_stopped: Callable[[str], bool]) -> dict:
    live = running(deployments, is_stopped)
    if len(live) != 1:
        ids = ", ".join(d["id"] for d in live) or "none"
        raise SelectionError(f"expected exactly one running SUCCESS deployment, found {len(live)} ({ids})")
    return live[0]


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def find_new(deployments: list[dict], old_id: str, since: str) -> dict | None:
    floor = _parse_time(since)
    newer = [
        d for d in deployments
        if d.get("id") != old_id and d.get("createdAt") and _parse_time(d["createdAt"]) >= floor
    ]
    return newer[0] if newer else None


def _load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: railway_seat.py <preflight|running|new|stopped|stop> ...", file=sys.stderr)
        return 2
    command, args = argv[0], argv[1:]
    try:
        if command == "preflight":
            deployments = _load(args[0])
            old = select_old(deployments, deployment_stopped)
            print(old["id"], digest_of(old) or "-", len(inflight(deployments)))
        elif command == "running":
            for deployment in running(_load(args[0]), deployment_stopped):
                print(deployment["id"], digest_of(deployment) or "-")
        elif command == "new":
            deployment = find_new(_load(args[0]), args[1], args[2])
            if deployment is None:
                print("- - -")
            else:
                print(deployment["id"], deployment.get("status", "-"), digest_of(deployment) or "-")
        elif command == "stopped":
            print("true" if deployment_stopped(args[0]) else "false")
        elif command == "stop":
            ok = stop_deployment(args[0])
            print("deploymentStop=true" if ok else "deploymentStop=false")
            return 0 if ok else 1
        else:
            print(f"unknown command: {command}", file=sys.stderr)
            return 2
    except SelectionError as error:
        print(f"ABORT {error}", file=sys.stderr)
        return 13
    except (OSError, KeyError, ValueError, IndexError) as error:
        print(f"ABORT {command} failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 13
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
