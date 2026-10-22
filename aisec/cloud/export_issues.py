"""Optional export of a finding to GitHub or Linear. aisec stays the source of truth."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def github_issue_body(finding: dict[str, Any], manifest_sha256: str, url: str) -> dict[str, str]:
    title = f"[aisec] {finding.get('severity') or 'finding'}: {finding.get('title')}"
    body = (
        f"{finding.get('body')}\n\n"
        f"aisec finding: {finding.get('id')}\n"
        f"Status: {finding.get('status')}\n"
        f"Manifest sha256: `{manifest_sha256}`\n"
        f"{url}\n"
    )
    return {"title": title, "body": body}


def export_github(finding: dict[str, Any], *, repo: str, manifest_sha256: str, url: str, token: str | None = None) -> dict[str, Any]:
    token = token or os.environ.get("GITHUB_TOKEN")
    payload = github_issue_body(finding, manifest_sha256, url)
    if not token:
        return {"dry_run": True, **payload}
    owner_repo = repo.strip()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{owner_repo}/issues",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "aisec",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub issue export failed: {exc.read().decode('utf-8', errors='replace')[:300]}") from exc
    return {"dry_run": False, "html_url": data.get("html_url"), "number": data.get("number")}


def export_linear(finding: dict[str, Any], *, team_id: str, manifest_sha256: str, url: str, api_key: str | None = None) -> dict[str, Any]:
    api_key = api_key or os.environ.get("LINEAR_API_KEY")
    payload = github_issue_body(finding, manifest_sha256, url)
    if not api_key:
        return {"dry_run": True, **payload}
    query = {
        "query": "mutation($title:String!, $description:String!, $teamId:String!){ issueCreate(input:{title:$title, description:$description, teamId:$teamId}){ success issue{ id url } } }",
        "variables": {"title": payload["title"], "description": payload["body"], "teamId": team_id},
    }
    req = urllib.request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps(query).encode("utf-8"),
        headers={"Authorization": api_key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Linear export failed: {exc.read().decode('utf-8', errors='replace')[:300]}") from exc
    issue = ((data.get("data") or {}).get("issueCreate") or {}).get("issue") or {}
    return {"dry_run": False, "html_url": issue.get("url"), "id": issue.get("id")}
