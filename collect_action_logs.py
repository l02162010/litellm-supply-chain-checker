#!/usr/bin/env python3
"""Collect failed GitHub Actions logs into a local folder via gh CLI."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_FIELDS = ",".join(
    [
        "databaseId",
        "displayTitle",
        "headBranch",
        "event",
        "status",
        "conclusion",
        "workflowName",
        "createdAt",
        "url",
    ]
)
FAILED_CONCLUSIONS = {"failure", "startup_failure", "timed_out", "action_required"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Use gh CLI to find failed GitHub Actions runs and save their logs "
            "into a folder plus Markdown summaries."
        )
    )
    parser.add_argument(
        "--repo",
        help="GitHub repository in OWNER/REPO form. Defaults to origin remote.",
    )
    parser.add_argument(
        "--run-id",
        action="append",
        dest="run_ids",
        type=int,
        help="Specific Actions run ID to collect. Can be provided multiple times.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="How many recent runs to inspect when --run-id is not provided. Default: 10.",
    )
    parser.add_argument(
        "--output-dir",
        default="action-logs",
        help="Directory where logs and index files will be written. Default: action-logs",
    )
    return parser.parse_args()


def run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required command not found: {command[0]}") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(command)}\n{stderr}"
        )
    return completed.stdout


def infer_repo() -> str:
    remote = run_command(["git", "remote", "get-url", "origin"]).strip()
    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$",
        r"ssh://git@github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, remote)
        if match:
            return f"{match.group('owner')}/{match.group('repo')}"
    raise RuntimeError(
        "Could not infer OWNER/REPO from origin remote. Use --repo OWNER/REPO."
    )


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "run"


def load_runs(repo: str, run_ids: list[int] | None, limit: int) -> list[dict[str, Any]]:
    if run_ids:
        runs: list[dict[str, Any]] = []
        for run_id in run_ids:
            payload = json.loads(
                run_command(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"])
            )
            runs.append(
                {
                    "databaseId": payload["id"],
                    "displayTitle": payload["display_title"],
                    "headBranch": payload["head_branch"],
                    "event": payload["event"],
                    "status": payload["status"],
                    "conclusion": payload["conclusion"],
                    "workflowName": payload.get("name", ""),
                    "createdAt": payload["created_at"],
                    "url": payload["html_url"],
                }
            )
        return runs

    payload = run_command(
        [
            "gh",
            "run",
            "list",
            "-R",
            repo,
            "--limit",
            str(limit),
            "--json",
            RUN_FIELDS,
        ]
    )
    runs = json.loads(payload)
    return [run for run in runs if run.get("conclusion") in FAILED_CONCLUSIONS]


def load_jobs(repo: str, run_id: int) -> list[dict[str, Any]]:
    payload = json.loads(
        run_command(["gh", "api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"])
    )
    return payload.get("jobs", [])


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def relative(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def write_run_archive(output_dir: Path, repo: str, run: dict[str, Any]) -> dict[str, Any]:
    run_id = int(run["databaseId"])
    run_dir = output_dir / f"run-{run_id}-{slugify(run['displayTitle'])[:60]}"
    run_dir.mkdir(parents=True, exist_ok=True)

    jobs = load_jobs(repo, run_id)
    failed_jobs = [job for job in jobs if job.get("conclusion") in FAILED_CONCLUSIONS]

    combined_log = run_command(["gh", "run", "view", str(run_id), "-R", repo, "--log-failed"])
    combined_log_path = run_dir / "failed.log"
    write_text(combined_log_path, combined_log)

    per_job_files: list[dict[str, Any]] = []
    job_errors: list[str] = []
    for job in failed_jobs:
        job_id = int(job["id"])
        file_name = f"job-{job_id}-{slugify(job['name'])[:60]}.log"
        log_path = run_dir / file_name
        try:
            job_log = run_command(
                ["gh", "run", "view", str(run_id), "-R", repo, "--job", str(job_id), "--log"]
            )
        except RuntimeError as exc:
            job_errors.append(str(exc))
            write_text(log_path.with_suffix(".error.txt"), str(exc))
            continue
        write_text(log_path, job_log)
        per_job_files.append(
            {
                "id": job_id,
                "name": job["name"],
                "conclusion": job.get("conclusion", ""),
                "path": relative(log_path, output_dir),
            }
        )

    summary_lines = [
        f"# GitHub Actions failure log archive for run {run_id}",
        "",
        f"- Repo: `{repo}`",
        f"- Workflow: `{run.get('workflowName') or 'Unknown'}`",
        f"- Title: `{run['displayTitle']}`",
        f"- Branch: `{run['headBranch']}`",
        f"- Event: `{run['event']}`",
        f"- Status: `{run['status']}`",
        f"- Conclusion: `{run.get('conclusion')}`",
        f"- Created at: `{run['createdAt']}`",
        f"- GitHub URL: {run['url']}",
        "",
        "## Retrieval commands",
        "",
        f"- `gh run view {run_id} -R {repo} --log-failed`",
    ]
    for job in failed_jobs:
        summary_lines.append(
            f"- `gh run view {run_id} -R {repo} --job {int(job['id'])} --log`"
        )

    summary_lines.extend(
        [
            "",
            "## Saved files",
            "",
            f"- Combined failed log: `{relative(combined_log_path, output_dir)}`",
        ]
    )
    for item in per_job_files:
        summary_lines.append(
            f"- Job `{item['name']}` (`{item['id']}`): `{item['path']}`"
        )

    if failed_jobs:
        summary_lines.extend(
            [
                "",
                "## Failed jobs",
                "",
                "| Job ID | Name | Conclusion |",
                "|--------|------|------------|",
            ]
        )
        for job in failed_jobs:
            summary_lines.append(
                f"| `{int(job['id'])}` | {job['name']} | `{job.get('conclusion', '')}` |"
            )
    else:
        summary_lines.extend(["", "## Failed jobs", "", "No failed jobs were reported."])

    if job_errors:
        summary_lines.extend(["", "## Retrieval errors", ""])
        for error in job_errors:
            summary_lines.append(f"- {error}")

    summary_path = run_dir / "summary.md"
    write_text(summary_path, "\n".join(summary_lines) + "\n")

    return {
        "run_id": run_id,
        "title": run["displayTitle"],
        "workflow": run.get("workflowName") or "Unknown",
        "branch": run["headBranch"],
        "conclusion": run.get("conclusion"),
        "url": run["url"],
        "folder": relative(run_dir, output_dir),
        "summary": relative(summary_path, output_dir),
        "combined_log": relative(combined_log_path, output_dir),
        "failed_jobs": len(failed_jobs),
        "job_errors": job_errors,
    }


def write_index(output_dir: Path, repo: str, archives: list[dict[str, Any]]) -> None:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "# GitHub Actions failure logs",
        "",
        f"- Repo: `{repo}`",
        f"- Generated at: `{generated_at}`",
        "",
        "| Run ID | Workflow | Branch | Conclusion | Failed jobs | Folder |",
        "|--------|----------|--------|------------|-------------|--------|",
    ]
    for item in archives:
        lines.append(
            f"| `{item['run_id']}` | {item['workflow']} | `{item['branch']}` | "
            f"`{item['conclusion']}` | {item['failed_jobs']} | `{item['folder']}` |"
        )

    lines.extend(["", "## Summaries", ""])
    for item in archives:
        lines.append(
            f"- Run `{item['run_id']}`: `{item['summary']}` "
            f"(combined log: `{item['combined_log']}`)"
        )
        if item["job_errors"]:
            for error in item["job_errors"]:
                lines.append(f"  - retrieval error: `{error}`")

    write_text(output_dir / "index.md", "\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    repo = args.repo or infer_repo()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    runs = load_runs(repo, args.run_ids, args.limit)
    if not runs:
        raise RuntimeError("No failed runs found with the provided arguments.")

    archives = [write_run_archive(output_dir, repo, run) for run in runs]
    write_index(output_dir, repo, archives)

    print(f"Wrote {len(archives)} run archive(s) to {output_dir}")
    print(f"Index: {output_dir / 'index.md'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
