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


def test_read_only_containers_have_a_writable_tmp() -> None:
    # Regression: with a read-only root, promtool test rules failed in setup.sh with
    # "mkdir /tmp/test_storage...: read-only file system", so setup.sh refused to start.
    compose = yaml.safe_load((MONITORING / "compose.yaml").read_text())
    for name, service in compose["services"].items():
        if service.get("read_only"):
            assert "/tmp" in service.get("tmpfs", []), name


ALERTMANAGER = MONITORING / "alertmanager"


def _receivers(config: str) -> dict[str, dict[str, object]]:
    data = yaml.safe_load((ALERTMANAGER / config).read_text())
    return {receiver["name"]: receiver for receiver in data["receivers"]}


def test_alertmanager_is_on_loopback_without_cluster_gossip() -> None:
    service = yaml.safe_load((MONITORING / "compose.yaml").read_text())["services"]["alertmanager"]
    assert service["ports"] == ["127.0.0.1:9093:9093"]
    assert "--cluster.listen-address=" in service["command"]
    assert "--config.file=/etc/alertmanager/alertmanager.yml" in service["command"]
    assert "./secrets/telegram:/run/secrets/telegram:ro" in service["volumes"]


def test_prometheus_sends_alerts_to_the_compose_alertmanager() -> None:
    config = yaml.safe_load((MONITORING / "prometheus" / "prometheus.yml").read_text())
    targets = config["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"]
    assert targets == ["alertmanager:9093"]


def test_telegram_receivers_read_their_secrets_from_files_and_send_plain_text() -> None:
    receivers = _receivers("telegram.yml")
    assert set(receivers) == {"telegram", "telegram-silent"}
    for name, receiver in receivers.items():
        (config,) = receiver["telegram_configs"]
        # Neither the token nor the chat ID is in the committed file.
        assert config["bot_token_file"] == "/run/secrets/telegram/bot_token", name
        assert config["chat_id_file"] == "/run/secrets/telegram/chat_id", name
        assert "bot_token" not in config and "chat_id" not in config, name
        assert config["parse_mode"] == "", name
        assert config["message"] == '{{ template "netwatch.telegram" . }}', name
        assert config["send_resolved"] is True, name
    assert receivers["telegram-silent"]["telegram_configs"][0]["disable_notifications"] is True
    assert "disable_notifications" not in receivers["telegram"]["telegram_configs"][0]


def test_warnings_go_to_the_silent_receiver_and_critical_alerts_buzz() -> None:
    route = yaml.safe_load((ALERTMANAGER / "telegram.yml").read_text())["route"]
    assert route["receiver"] == "telegram"
    (warnings,) = route["routes"]
    assert warnings["matchers"] == ['severity="warning"']
    assert warnings["receiver"] == "telegram-silent"
    severities = {rule["labels"]["severity"] for rule in _rules()}
    assert severities == {"warning", "critical"}  # nothing falls through unrouted


def test_the_template_alertmanager_uses_is_defined() -> None:
    template = (ALERTMANAGER / "templates" / "netwatch.tmpl").read_text()
    assert '{{ define "netwatch.telegram" -}}' in template


def test_alertmanager_without_telegram_sends_nowhere() -> None:
    assert list(_receivers("off.yml")) == ["nowhere"]
    assert _receivers("off.yml")["nowhere"] == {"name": "nowhere"}


def test_the_test_alert_command_quotes_annotations_and_closes_stdin() -> None:
    # Regression, both found on the monitoring VM on 2 November: amtool 0.34 warned that
    # summary=Test alert ... "is incompatible" with its label parser and fell back to the old one
    # (values with spaces must be double-quoted), and `docker compose exec` read the rest of the
    # commands piped into `bash -s` after setup.sh --test-alert, so they never ran.
    setup = (MONITORING / "setup.sh").read_text()
    start = setup.index("--test-alert ]")
    block = setup[start : setup.index("exit 0", start)]
    annotations = re.findall(r"--annotation=(\S.*?) \\\n", block)
    assert len(annotations) == 2
    for value in annotations:
        assert re.fullmatch(r"'[a-z]+=\"[^\"]+\"'", value), value
    assert "</dev/null" in block


def test_each_test_alert_is_a_new_alert() -> None:
    # Regression: a second setup.sh --test-alert within 4 hours sent nothing on 2 November.
    # Alertmanager's notification log had already sent a message about an alert with exactly the
    # same labels, and it repeats one only after repeat_interval.
    setup = (MONITORING / "setup.sh").read_text()
    add = next(line for line in setup.splitlines() if "alert add NetwatchTestAlert" in line)
    assert 'run="$(date' in add


def test_the_test_alert_has_a_start_and_no_link_in_its_text() -> None:
    # Regression, from the first live run on 2 November: amtool sent no start time, so
    # Alertmanager used the end time and the message said "Since 20:16" at 20:14 (and "From 20:22
    # to 20:22" when resolved); and Telegram rendered "setup.sh" in the text as a web link.
    setup = (MONITORING / "setup.sh").read_text()
    start = setup.index("--test-alert ]")
    block = setup[start : setup.index("exit 0", start)]
    assert "--start=" in block and "--end=" in block
    texts = re.findall(r"--annotation='[a-z]+=\"([^\"]+)\"'", block)
    assert len(texts) == 2
    assert not any(re.search(r"\b[\w-]+\.(sh|py|md|io|ai)\b", text) for text in texts), texts


def test_no_docker_compose_call_in_setup_reads_stdin() -> None:
    # Regression: on 2 November `docker compose run` (promtool, amtool) read the rest of a script
    # piped into `bash -s` over SSH, so the `setup.sh --test-alert` after `setup.sh` never ran;
    # `docker compose exec` had done the same to the commands after --test-alert.
    setup = (MONITORING / "setup.sh").read_text()
    calls = re.findall(r"^[ \t]*docker compose (?:run|exec)\b.*?(?<!\\)\n", setup, re.S | re.M)
    assert len(calls) == 3
    for call in calls:
        assert " -T " in call and "</dev/null" in call, call
