"""
QA-FIX-09 tests: validate OpenSearch index templates after the v2.1 mapping update.

What this verifies:
  * Both templates parse as JSON.
  * `_meta.version` was bumped to "2.1".
  * `fluent-osquery.json` now has explicit numeric/wildcard types for the
    `osquery.*` namespace fields called out in QA-04 (osquery.pid, ports,
    cid, ntime, exit_code, ...).
  * `container.image.tag` and `process.exit_code` were added.
  * `fluent-audit.json` adds `service.name`, `auditd.session` is `long`,
    `auditd.paths` is `wildcard`, `process.working_directory` is `wildcard`.
  * UID-style fields stay `keyword` (project decision per QA-04 task #7).
  * Index-template structural invariants: `priority`, `index_patterns`,
    `template.mappings.dynamic`, `dynamic_templates`.

Run from project root:
    pytest testing/test_qa_fix_09_templates.py -v
or standalone:
    python testing/test_qa_fix_09_templates.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "opensearch" / "templates"

OSQUERY_TEMPLATE = TEMPLATES_DIR / "fluent-osquery.json"
AUDIT_TEMPLATE = TEMPLATES_DIR / "fluent-audit.json"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _get(d: dict, dotted: str):
    """Resolve a dotted path through {properties: {...}} mapping trees.

    Example: _get(template_mappings, "osquery.pid") walks
        properties.osquery.properties.pid
    """
    cur = d
    parts = dotted.split(".")
    for i, part in enumerate(parts):
        if "properties" in cur and part in cur["properties"]:
            cur = cur["properties"][part]
        else:
            raise KeyError(f"missing path segment {'.'.join(parts[:i+1])!r}")
    return cur


@pytest.fixture(scope="module")
def osquery_tmpl() -> dict:
    return _load(OSQUERY_TEMPLATE)


@pytest.fixture(scope="module")
def osquery_mappings(osquery_tmpl) -> dict:
    return osquery_tmpl["template"]["mappings"]


@pytest.fixture(scope="module")
def audit_tmpl() -> dict:
    return _load(AUDIT_TEMPLATE)


@pytest.fixture(scope="module")
def audit_mappings(audit_tmpl) -> dict:
    return audit_tmpl["template"]["mappings"]


# ---------- structural invariants ----------

class TestStructuralInvariants:
    def test_osquery_top_level(self, osquery_tmpl):
        assert osquery_tmpl["index_patterns"] == ["fluent-osquery-*"]
        assert osquery_tmpl["priority"] == 200
        assert osquery_tmpl["template"]["mappings"]["dynamic"] is True
        assert "dynamic_templates" in osquery_tmpl["template"]["mappings"]

    def test_audit_top_level(self, audit_tmpl):
        assert audit_tmpl["index_patterns"] == ["fluent-audit-*"]
        assert audit_tmpl["priority"] == 200
        assert audit_tmpl["template"]["mappings"]["dynamic"] is True

    def test_osquery_dynamic_template_keeps_strings_as_keyword(self, osquery_mappings):
        dts = osquery_mappings["dynamic_templates"]
        sak = next(d["strings_as_keywords"] for d in dts if "strings_as_keywords" in d)
        assert sak["match_mapping_type"] == "string"
        assert sak["mapping"]["type"] == "keyword"

    def test_versions_bumped_to_2_1(self, osquery_tmpl, audit_tmpl):
        assert osquery_tmpl["_meta"]["version"] == "2.1", "osquery _meta.version must be 2.1"
        assert audit_tmpl["_meta"]["version"] == "2.1", "audit _meta.version must be 2.1"


# ---------- osquery: explicit numeric / wildcard fields (QA-04 core) ----------

OSQUERY_EXPECTED_TYPES = {
    # numeric — primary point of QA-04
    "osquery.pid":         "long",
    "osquery.parent":      "long",
    "osquery.tid":         "long",
    "osquery.local_port":  "integer",
    "osquery.remote_port": "integer",
    "osquery.exit_code":   "long",
    "osquery.start_time":  "long",
    "osquery.ntime":       "long",
    "osquery.duration":    "long",
    "osquery.cid":         "long",
    "osquery.fd":          "long",
    # UIDs stay keyword (project decision per QA-04 #7)
    "osquery.uid":         "keyword",
    "osquery.gid":         "keyword",
    "osquery.euid":        "keyword",
    "osquery.egid":        "keyword",
    # paths/cmdline as wildcard for glob search
    "osquery.path":         "wildcard",
    "osquery.cmdline":      "wildcard",
    "osquery.process_path": "wildcard",
    # existing osquery.result block preserved
    "osquery.result.unix_time": "long",
    "osquery.result.name":      "keyword",
}


class TestOsqueryNamespace:
    @pytest.mark.parametrize("field,expected_type", OSQUERY_EXPECTED_TYPES.items())
    def test_field_type(self, osquery_mappings, field, expected_type):
        node = _get(osquery_mappings, field)
        assert node.get("type") == expected_type, (
            f"{field} should be {expected_type!r}, got {node.get('type')!r}"
        )

    def test_result_block_preserved(self, osquery_mappings):
        result = _get(osquery_mappings, "osquery.result")
        # the whole subdoc — guards against accidental flattening
        for key in ("name", "action", "host_identifier", "unix_time", "version"):
            assert key in result["properties"], f"osquery.result.{key} missing"


# ---------- osquery: container + process additions ----------

class TestOsqueryContainerAndProcess:
    def test_container_image_tag_added(self, osquery_mappings):
        tag = _get(osquery_mappings, "container.image.tag")
        assert tag["type"] == "keyword"

    def test_container_image_name_preserved(self, osquery_mappings):
        name = _get(osquery_mappings, "container.image.name")
        assert name["type"] == "keyword"

    def test_process_exit_code_explicit(self, osquery_mappings):
        node = _get(osquery_mappings, "process.exit_code")
        assert node["type"] == "long", (
            "process.exit_code must be long to handle BPF int64 negatives"
        )

    def test_process_parent_name_and_cmdline(self, osquery_mappings):
        # added in v2.1 — UEBA cross-ref to auditd parent fields
        assert _get(osquery_mappings, "process.parent.name")["type"] == "keyword"
        assert _get(osquery_mappings, "process.parent.command_line")["type"] == "wildcard"

    def test_process_args_explicit(self, osquery_mappings):
        assert _get(osquery_mappings, "process.args")["type"] == "keyword"
        assert _get(osquery_mappings, "process.args_count")["type"] == "integer"
        assert _get(osquery_mappings, "process.working_directory")["type"] == "wildcard"


# ---------- audit: additions from Шаг 2 ----------

class TestAuditTemplate:
    def test_service_name_added(self, audit_mappings):
        node = _get(audit_mappings, "service.name")
        assert node["type"] == "keyword", "service.name needed for SERVICE_START/STOP events"

    def test_auditd_session_is_long(self, audit_mappings):
        node = _get(audit_mappings, "auditd.session")
        assert node["type"] == "long", (
            "auditd.session bumped integer→long for safety"
        )

    def test_auditd_paths_is_wildcard(self, audit_mappings):
        node = _get(audit_mappings, "auditd.paths")
        assert node["type"] == "wildcard", (
            "auditd.paths should be wildcard for glob search across multiple paths"
        )

    def test_process_working_directory_is_wildcard(self, audit_mappings):
        node = _get(audit_mappings, "process.working_directory")
        assert node["type"] == "wildcard"

    def test_process_args_count_integer(self, audit_mappings):
        node = _get(audit_mappings, "process.args_count")
        assert node["type"] == "integer"

    def test_process_title_wildcard(self, audit_mappings):
        node = _get(audit_mappings, "process.title")
        assert node["type"] == "wildcard"

    def test_constant_keyword_dataset(self, audit_mappings):
        node = _get(audit_mappings, "event.dataset")
        assert node["type"] == "constant_keyword"
        assert node["value"] == "auditd"


# ---------- regression: nothing accidentally broken in either template ----------

class TestRegressionPreserved:
    def test_osquery_ip_fields_intact(self, osquery_mappings):
        for f in ("source.ip", "destination.ip", "related.ip"):
            assert _get(osquery_mappings, f)["type"] == "ip"

    def test_osquery_ports_still_integer(self, osquery_mappings):
        for f in ("source.port", "destination.port"):
            assert _get(osquery_mappings, f)["type"] == "integer"

    def test_audit_ip_fields_intact(self, audit_mappings):
        for f in ("source.ip", "destination.ip", "related.ip"):
            assert _get(audit_mappings, f)["type"] == "ip"

    def test_audit_file_hash_intact(self, audit_mappings):
        for algo in ("md5", "sha1", "sha256"):
            assert _get(audit_mappings, f"file.hash.{algo}")["type"] == "keyword"

    def test_osquery_total_fields_limit(self, osquery_tmpl):
        assert osquery_tmpl["template"]["settings"]["index.mapping.total_fields.limit"] == 2000


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
