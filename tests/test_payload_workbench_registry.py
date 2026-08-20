"""
tests/test_payload_workbench_registry.py

Pure-Python unit tests for server_core/payload_workbench/registry.py — the
auto-discovery registry backing the Payload Workbench attack-payload toolset.

No subprocess, no Flask, no network calls.
"""

from backend.server_core.payload_workbench.registry import (
    CATEGORIES,
    OPERATIONS,
    Operation,
    ParamSpec,
    get_operation,
    list_operations,
)


class TestDiscovery:
    def test_operations_is_non_empty(self):
        assert len(OPERATIONS) > 0

    def test_expected_categories_present(self):
        assert set(CATEGORIES) == {"generate", "evasion"}

    def test_every_operation_id_matches_its_dict_key(self):
        for op_id, op in OPERATIONS.items():
            assert op.id == op_id

    def test_every_operation_has_a_chainable_input_param(self):
        # Convention documented in registry.py: every operation must expose a
        # param literally named "input" so the recipe pipeline can feed the
        # previous step's output into it.
        for op in OPERATIONS.values():
            names = [p.name for p in op.params]
            assert "input" in names, f"{op.id} is missing an 'input' param — recipes can't chain into it"

    def test_every_operation_belongs_to_a_listed_category(self):
        for op in OPERATIONS.values():
            assert op.category in CATEGORIES

    def test_expected_operation_ids_present(self):
        expected = {
            "generate_xss", "generate_sqli", "generate_lfi", "generate_cmd_injection",
            "generate_xxe", "generate_ssti", "generate_waf_bypass", "apply_evasion",
        }
        assert expected == set(OPERATIONS.keys())


class TestGetOperation:
    def test_known_id_returns_operation(self):
        op = get_operation("generate_xss")
        assert op is not None
        assert op.id == "generate_xss"

    def test_unknown_id_returns_none(self):
        assert get_operation("does_not_exist") is None


class TestListOperations:
    def test_returns_all_operations(self):
        assert len(list_operations()) == len(OPERATIONS)

    def test_sorted_by_category_then_name(self):
        ops = list_operations()
        keys = [(op.category, op.name) for op in ops]
        assert keys == sorted(keys)


class TestParamSpecToDict:
    def test_omits_choices_when_absent(self):
        spec = ParamSpec(name="input", label="Input", type="textarea", required=True)
        d = spec.to_dict()
        assert "choices" not in d

    def test_includes_choices_when_present(self):
        spec = ParamSpec(name="technique", label="Technique", type="select", choices=["a", "b"])
        d = spec.to_dict()
        assert d["choices"] == ["a", "b"]


class TestOperationToDict:
    def test_does_not_leak_the_run_callable(self):
        op = get_operation("generate_xss")
        d = op.to_dict()
        assert "run" not in d

    def test_serializes_params(self):
        op = get_operation("apply_evasion")
        d = op.to_dict()
        assert any(p["name"] == "technique" for p in d["params"])
