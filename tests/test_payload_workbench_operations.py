"""
tests/test_payload_workbench_operations.py

Correctness tests for each Payload Workbench operation's run() function —
attack-payload generation and WAF-evasion transforms. Pure-Python, no
subprocess, no Flask, no network calls, so these are safe/cheap to run on
every commit.
"""

import pytest

from backend.server_core.payload_workbench.registry import get_operation


def run(op_id: str, **params) -> dict:
    op = get_operation(op_id)
    assert op is not None, f"operation {op_id!r} not found in registry"
    return op.run(params)


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

class TestGenerateXss:
    def test_basic_returns_payloads(self):
        output = run("generate_xss", complexity="basic")["output"]
        assert len(output.splitlines()) > 0

    def test_advanced_and_bypass_differ_from_basic(self):
        basic = run("generate_xss", complexity="basic")["output"]
        advanced = run("generate_xss", complexity="advanced")["output"]
        bypass = run("generate_xss", complexity="bypass")["output"]
        assert basic != advanced != bypass

    def test_unsupported_complexity_raises(self):
        with pytest.raises(ValueError):
            run("generate_xss", complexity="not_a_real_level")

    def test_default_complexity_is_basic(self):
        assert run("generate_xss") == run("generate_xss", complexity="basic")

    def test_evasion_transforms_output(self):
        plain = run("generate_xss", complexity="basic")["output"]
        evaded = run("generate_xss", complexity="basic", evasion="html_encode")["output"]
        assert evaded != plain
        assert "<" not in evaded

    def test_evasion_none_is_identity(self):
        assert run("generate_xss", complexity="basic", evasion="none") == run("generate_xss", complexity="basic")

    def test_unsupported_evasion_raises(self):
        with pytest.raises(ValueError):
            run("generate_xss", complexity="basic", evasion="sql_comment")


class TestGenerateSqli:
    def test_time_based_returns_payloads(self):
        output = run("generate_sqli", complexity="time_based")["output"]
        assert len(output.splitlines()) > 0

    def test_unsupported_complexity_raises(self):
        with pytest.raises(ValueError):
            run("generate_sqli", complexity="bypass")

    def test_evasion_transforms_output(self):
        plain = run("generate_sqli", complexity="basic")["output"]
        evaded = run("generate_sqli", complexity="basic", evasion="sql_comment")["output"]
        assert evaded != plain

    def test_unsupported_evasion_raises(self):
        with pytest.raises(ValueError):
            run("generate_sqli", complexity="basic", evasion="html_encode")


class TestGenerateLfi:
    def test_basic_returns_payloads(self):
        output = run("generate_lfi", complexity="basic")["output"]
        assert "etc/passwd" in output


class TestGenerateCmdInjection:
    def test_basic_returns_payloads(self):
        output = run("generate_cmd_injection", complexity="basic")["output"]
        assert len(output.splitlines()) > 0


class TestGenerateXxe:
    def test_basic_returns_payloads(self):
        output = run("generate_xxe", complexity="basic")["output"]
        assert "ENTITY" in output

    def test_unsupported_complexity_raises(self):
        with pytest.raises(ValueError):
            run("generate_xxe", complexity="advanced")


class TestGenerateSsti:
    def test_basic_returns_payloads(self):
        output = run("generate_ssti", complexity="basic")["output"]
        assert "7*7" in output


class TestGenerateWafBypass:
    def test_known_vendor_returns_payloads(self):
        output = run("generate_waf_bypass", waf_name="Cloudflare")["output"]
        assert len(output.splitlines()) > 0

    def test_output_has_no_unsubstituted_marker(self):
        output = run("generate_waf_bypass", waf_name="Cloudflare")["output"]
        assert "{marker}" not in output

    def test_unknown_vendor_raises(self):
        with pytest.raises(ValueError):
            run("generate_waf_bypass", waf_name="NotARealWaf")

    def test_evasion_transforms_output(self):
        plain = run("generate_waf_bypass", waf_name="Cloudflare")["output"]
        evaded = run("generate_waf_bypass", waf_name="Cloudflare", evasion="case_mixing")["output"]
        assert evaded != plain


# ---------------------------------------------------------------------------
# evasion
# ---------------------------------------------------------------------------

class TestApplyEvasion:
    def test_case_mixing_changes_case(self):
        output = run("apply_evasion", input="<script>alert(1)</script>", technique="case_mixing")["output"]
        assert output.lower() == "<script>alert(1)</script>"
        assert output != "<script>alert(1)</script>"

    def test_none_is_identity(self):
        assert run("apply_evasion", input="unchanged", technique="none")["output"] == "unchanged"

    def test_default_technique_is_none(self):
        assert run("apply_evasion", input="unchanged") == run("apply_evasion", input="unchanged", technique="none")

    def test_unsupported_technique_raises(self):
        with pytest.raises(ValueError):
            run("apply_evasion", input="x", technique="not_a_real_technique")

    def test_html_encode(self):
        output = run("apply_evasion", input="<script>", technique="html_encode")["output"]
        assert "<" not in output
