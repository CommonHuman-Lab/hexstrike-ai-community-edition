from server_core.intelligence.tool_catalog import build_tool_catalog, validate_tool_catalog
from server_core.singletons import decision_engine


def _tools_for(target: str, objective: str):
    profile = decision_engine.analyze_target(target)
    return decision_engine.select_optimal_tools(profile, objective), profile


def test_catalog_validation_passes():
    catalog = build_tool_catalog()
    issues = validate_tool_catalog(catalog)
    assert issues == []


def test_quick_mode_precision_is_compact():
    tools, _profile = _tools_for("https://example.com", "quick")
    assert 1 <= len(tools) <= 4


def test_comprehensive_mode_allows_safer_coverage_tool_count():
    tools, _profile = _tools_for("https://example.com", "comprehensive")
    assert len(tools) <= 8
    assert len(tools) >= 5


def test_api_security_prefers_api_capabilities():
    tools, _profile = _tools_for("https://example.com/api", "api_security")
    lowered = set(tools)
    assert "arjun" in lowered or "x8" in lowered or "paramspider" in lowered
    assert "httpx" in lowered or "nuclei" in lowered


def test_network_quick_prefers_network_scanners():
    tools, _profile = _tools_for("10.10.10.10", "quick")
    lowered = set(tools)
    assert "nmap" in lowered or "nmap_advanced" in lowered or "rustscan" in lowered


def test_create_attack_chain_respects_runtime_overrides():
    profile = decision_engine.analyze_target("https://example.com/api")
    chain = decision_engine.create_attack_chain(
        profile,
        objective="api_security",
        runtime_context={
            "tool_overrides": {
                "nuclei": {"severity": "critical"},
            }
        },
    )

    nuclei_steps = [step for step in chain.steps if step.tool == "nuclei"]
    if nuclei_steps:
        assert nuclei_steps[0].parameters.get("severity") == "critical"
