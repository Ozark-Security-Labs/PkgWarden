#!/usr/bin/env python3
"""Seed GitHub labels, milestones, and issues for PkgWarden.

Usage:
  python3 scripts/seed_github.py --repo OWNER/REPO --data github/pkgwarden_seed.json --dry-run
  python3 scripts/seed_github.py --repo OWNER/REPO --data github/pkgwarden_seed.json

Requires:
  - GitHub CLI (`gh`) installed and authenticated.
  - permission to create labels, milestones, and issues.
"""

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd, dry_run=False, check=True, capture=False):
    print("+ " + shlex.join(cmd))
    if dry_run:
        return ""
    result = subprocess.run(cmd, check=check, text=True, capture_output=capture)
    if capture:
        return result.stdout
    return ""


def gh_json(cmd, dry_run=False):
    if dry_run:
        print("+ " + shlex.join(cmd))
        return []
    try:
        out = subprocess.run(cmd, check=True, text=True, capture_output=True).stdout
        return json.loads(out) if out.strip() else []
    except subprocess.CalledProcessError as exc:
        print(exc.stderr, file=sys.stderr)
        raise


def ensure_labels(repo, labels, dry_run=False):
    print("\n== Labels ==")
    existing = set()
    if not dry_run:
        existing_data = gh_json(["gh", "label", "list", "--repo", repo, "--limit", "500", "--json", "name"], dry_run=False)
        existing = {item["name"] for item in existing_data}
    for label in labels:
        name = label["name"]
        color = label.get("color", "EDEDED")
        desc = label.get("description", "")
        if name in existing:
            run(["gh", "label", "edit", name, "--repo", repo, "--color", color, "--description", desc], dry_run=dry_run, check=False)
        else:
            run(["gh", "label", "create", name, "--repo", repo, "--color", color, "--description", desc], dry_run=dry_run, check=False)


def ensure_milestones(repo, milestones, dry_run=False):
    print("\n== Milestones ==")
    owner_repo = repo
    existing = {}
    if not dry_run:
        existing_data = gh_json(["gh", "api", f"repos/{owner_repo}/milestones", "--method", "GET", "-f", "state=all", "--paginate"], dry_run=False)
        existing = {item["title"]: item for item in existing_data}
    for m in milestones:
        title = m["title"]
        desc = m.get("description", "")
        if title in existing:
            number = str(existing[title]["number"])
            run(["gh", "api", f"repos/{owner_repo}/milestones/{number}", "--method", "PATCH", "-f", f"title={title}", "-f", f"description={desc}", "-f", "state=open"], dry_run=dry_run, check=False)
        else:
            run(["gh", "api", f"repos/{owner_repo}/milestones", "--method", "POST", "-f", f"title={title}", "-f", f"description={desc}"], dry_run=dry_run, check=False)


def issue_exists(repo, issue_id, dry_run=False):
    if dry_run:
        return False
    query = f'{issue_id} in:title repo:{repo}'
    data = gh_json(["gh", "issue", "list", "--repo", repo, "--state", "all", "--search", query, "--json", "number,title"], dry_run=False)
    return any(issue_id in item.get("title", "") for item in data)


def create_issues(repo, issues, dry_run=False):
    print("\n== Issues ==")
    for issue in issues:
        issue_id = issue["id"]
        title = issue["title"]
        if issue_exists(repo, issue_id, dry_run=dry_run):
            print(f"# skipping existing issue {issue_id}: {title}")
            continue
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".md") as f:
            f.write(issue["body"])
            body_path = f.name
        cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body-file", body_path]
        if issue.get("milestone"):
            cmd += ["--milestone", issue["milestone"]]
        for label in issue.get("labels", []):
            cmd += ["--label", label]
        run(cmd, dry_run=dry_run, check=False)
        Path(body_path).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="GitHub repo in OWNER/REPO format")
    parser.add_argument("--data", default="github/pkgwarden_seed.json", help="Path to seed JSON")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-labels", action="store_true")
    parser.add_argument("--skip-milestones", action="store_true")
    parser.add_argument("--skip-issues", action="store_true")
    args = parser.parse_args()

    data = json.loads(Path(args.data).read_text(encoding="utf-8"))

    if not args.skip_labels:
        ensure_labels(args.repo, data.get("labels", []), dry_run=args.dry_run)
    if not args.skip_milestones:
        ensure_milestones(args.repo, data.get("milestones", []), dry_run=args.dry_run)
    if not args.skip_issues:
        create_issues(args.repo, data.get("issues", []), dry_run=args.dry_run)


if __name__ == "__main__":
    main()
