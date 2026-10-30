"""Consistency checks on the monitoring stack's files (monitoring/).

promtool checks the PromQL itself (setup.sh and CI); these catch what it can't: a rule or panel
that uses a metric Netwatch doesn't export (a typo is just an empty query in Grafana), an alert
without a unit test, a dashboard pointing at a data source that isn't provisioned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from netwatch import metrics

MONITORING = Path(__file__).resolve().parent.parent / "monitoring"
RULES = MONITORING / "prometheus" / "rules" / "netwatch.yml"
RULE_TESTS = MONITORING / "prometheus" / "tests" / "netwatch.test.yml"
DASHBOARDS = sorted((MONITORING / "grafana" / "dashboards").glob("*.json"))
NETWATCH_METRIC = re.compile(r"\bnetwatch_[a-z_]+")


def _exported() -> set[str]:
    return set(re.findall(r'"(netwatch_[a-z_]+)"', Path(metrics.__file__).read_text()))


def _rules() -> list[dict[str, object]]:
    groups = yaml.safe_load(RULES.read_text())["groups"]
    return [rule for group in groups for rule in group["rules"]]


def _dashboard_exprs() -> list[str]:
    exprs = []
    for path in DASHBOARDS:
        for panel in json.loads(path.read_text())["panels"]:
            exprs += [t["expr"] for t in panel.get("targets", [])]
    return exprs


def test_rules_and_panels_only_use_metrics_netwatch_exports() -> None:
    used = set()
    for expr in [str(r["expr"]) for r in _rules()] + _dashboard_exprs():
        used |= set(NETWATCH_METRIC.findall(expr))
    assert used
    assert used <= _exported()


def test_every_alert_has_a_severity_a_summary_and_a_unit_test() -> None:
    tested = {
        case["alertname"]
        for test in yaml.safe_load(RULE_TESTS.read_text())["tests"]
        for case in test["alert_rule_test"]
        if case["exp_alerts"]
    }
    for rule in _rules():
        assert rule["labels"]["severity"] in ("warning", "critical"), rule["alert"]
        assert rule["annotations"]["summary"], rule["alert"]
        assert rule["alert"] in tested, f"{rule['alert']} has no test that makes it fire"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_dashboards_use_the_provisioned_data_source(path: Path) -> None:
    provisioned = yaml.safe_load(
        (MONITORING / "grafana" / "provisioning" / "datasources" / "prometheus.yml").read_text()
    )["datasources"][0]["uid"]
    dashboard = json.loads(path.read_text())
    assert dashboard["editable"] is False
    ids = [panel["id"] for panel in dashboard["panels"]]
    assert len(ids) == len(set(ids))
    for panel in dashboard["panels"]:
        if panel["type"] != "row":
            assert panel["datasource"]["uid"] == provisioned, panel["title"]
            assert all(t["datasource"]["uid"] == provisioned for t in panel["targets"])


def test_dashboard_uids_are_unique() -> None:
    uids = [json.loads(path.read_text())["uid"] for path in DASHBOARDS]
    assert len(DASHBOARDS) == 2
    assert len(uids) == len(set(uids))


def test_compose_pins_images_and_never_publishes_on_every_address() -> None:
    compose = yaml.safe_load((MONITORING / "compose.yaml").read_text())
    for name, service in compose["services"].items():
        image = service["image"]
        assert ":" in image and not image.endswith(":latest"), name
        for port in service.get("ports", []):
            # host_ip:host_port:container_port; without the address it would mean 0.0.0.0.
            # ${VAR:?message} is filled in from .env, and its own colon doesn't count.
            filled = re.sub(r"\$\{[^}]*\}", "HOST", port)
            assert filled.count(":") == 2, f"{name} publishes {port} on every address"
    assert compose["services"]["prometheus"]["ports"] == ["127.0.0.1:9090:9090"]
