import pytest

from vulnreport.model import load_reports
from vulnreport.policy import DEFAULT_SLA_DAYS, Policy


def assess(fixtures, now, policy_file="policy.toml"):
    findings, _ = load_reports([fixtures / "app.json"])
    policy = Policy.load(fixtures / policy_file if policy_file else None)
    return {a.finding.vuln_id: a for a in policy.assess(findings, now)}, policy


def test_critical_past_sla_is_breach(fixtures, now):
    result, _ = assess(fixtures, now)
    assert result["CVE-2026-0001"].breached
    assert result["CVE-2026-0001"].days_remaining == 7 - 55


def test_within_sla_is_not_breach(fixtures, now):
    result, _ = assess(fixtures, now)
    assert not result["CVE-2026-0002"].breached  # HIGH, 27 days old, 30-day SLA
    assert result["CVE-2026-0002"].days_remaining == 3


def test_unfixable_never_breaches(fixtures, now):
    result, _ = assess(fixtures, now)
    assert not result["CVE-2026-0003"].breached


def test_unknown_severity_has_no_sla(fixtures, now):
    result, _ = assess(fixtures, now)
    assert result["CVE-2026-0007"].sla_days is None
    assert not result["CVE-2026-0007"].breached


def test_active_acceptance_suppresses_breach(fixtures, now):
    result, _ = assess(fixtures, now)
    jinja = result["GHSA-xxxx-0006"]
    assert jinja.accepted_by is not None
    assert jinja.accepted_by.owner == "app-team"
    assert not jinja.breached


def test_expired_acceptance_does_not_suppress(fixtures, now):
    _, policy = assess(fixtures, now)
    expired = policy.expired_acceptances(now.date())
    assert [a.vuln_id for a in expired] == ["CVE-2025-9999"]


def test_acceptance_stops_working_after_expiry(fixtures, now):
    later = now.replace(year=2027, month=2)
    result, _ = assess(fixtures, later)
    assert result["GHSA-xxxx-0006"].accepted_by is None
    assert result["GHSA-xxxx-0006"].breached


def test_default_policy(fixtures, now):
    result, policy = assess(fixtures, now, policy_file=None)
    assert policy.sla_days == DEFAULT_SLA_DAYS
    assert result["GHSA-xxxx-0006"].breached


def test_policy_validation(tmp_path):
    bad = tmp_path / "p.toml"
    bad.write_text('[[accept]]\nid = "CVE-1"\n')
    with pytest.raises(ValueError, match="missing"):
        Policy.load(bad)
    bad.write_text(
        '[[accept]]\nid="CVE-1"\nartifact="*"\nreason="r"\nowner="o"\nexpires="2027-01-01"\n'
    )
    with pytest.raises(ValueError, match="TOML date"):
        Policy.load(bad)


def test_sla_override(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text("[sla_days]\nmedium = 45\n")
    assert Policy.load(p).sla_days["MEDIUM"] == 45
