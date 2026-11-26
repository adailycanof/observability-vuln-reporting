"""vulnreport: Trivy JSON in, SLA report + metrics out."""

from __future__ import annotations

import argparse
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlparse

from vulnreport import __version__
from vulnreport.model import load_reports
from vulnreport.policy import Policy
from vulnreport.render import to_json, to_markdown, to_prometheus

EXIT_OK = 0
EXIT_BREACH = 2


def _parse_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def push_metrics(url: str, body: str, job: str = "vulnreport", timeout: float = 10) -> None:
    """PUT metrics to a Prometheus Pushgateway (replaces the job's previous group)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"pushgateway URL must be http(s): {url}")
    target = f"{url.rstrip('/')}/metrics/job/{quote(job, safe='')}"
    req = urllib.request.Request(  # noqa: S310 - scheme validated above
        target, data=body.encode(), method="PUT", headers={"Content-Type": "text/plain"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        if resp.status >= 300:
            raise RuntimeError(f"pushgateway returned HTTP {resp.status}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnreport", description=__doc__)
    p.add_argument("reports", nargs="+", type=Path, help="Trivy JSON reports (trivy -f json)")
    p.add_argument("--policy", type=Path, help="TOML with sla_days and [[accept]] entries")
    p.add_argument("--markdown", type=Path, help="write a Markdown report here ('-' = stdout)")
    p.add_argument("--json", type=Path, help="write a JSON summary here")
    p.add_argument("--metrics", type=Path, help="write Prometheus exposition format here")
    p.add_argument("--push", metavar="URL", help="push metrics to this Pushgateway")
    p.add_argument("--fail-on-breach", action="store_true", help=f"exit {EXIT_BREACH} on breach")
    p.add_argument("--now", help=argparse.SUPPRESS)  # fixed clock for tests
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = _parse_now(args.now)

    findings, artifacts = load_reports(args.reports)
    policy = Policy.load(args.policy)
    assessments = policy.assess(findings, now)
    expired = policy.expired_acceptances(now.date())

    if args.markdown:
        md = to_markdown(assessments, artifacts, expired, policy.sla_days, now)
        if str(args.markdown) == "-":
            sys.stdout.write(md)
        else:
            args.markdown.write_text(md, encoding="utf-8")
    if args.json:
        args.json.write_text(to_json(assessments, artifacts, expired, now), encoding="utf-8")

    metrics = to_prometheus(assessments, artifacts, expired, now)
    if args.metrics:
        args.metrics.write_text(metrics, encoding="utf-8")
    if args.push:
        push_metrics(args.push, metrics)

    breaches = sum(1 for a in assessments if a.breached)
    print(
        f"vulnreport: {len(findings)} findings across {len(artifacts)} artifacts, "
        f"{breaches} SLA breaches, {len(expired)} expired acceptances",
        file=sys.stderr,
    )
    return EXIT_BREACH if args.fail_on_breach and breaches else EXIT_OK
