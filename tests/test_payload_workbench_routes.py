"""
tests/test_payload_workbench_routes.py

Flask test-client tests for the Payload Workbench blueprint
(server_api/payload_workbench/routes.py). Operations are pure Python (no
subprocess), so these hit the real registry — only the app-level
execute_command/singleton patches from conftest.py apply.
"""

import pytest

from nyxstrike_server import app


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    app.config["NYXSTRIKE_API_TOKEN"] = None
    with app.test_client() as c:
        yield c


class TestOperationsEndpoint:
    def test_returns_success_with_categories_and_operations(self, client):
        r = client.get("/api/payload-workbench/operations")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert "generate" in body["categories"]
        assert any(op["id"] == "generate_xss" for op in body["operations"])

    def test_operations_do_not_leak_run_callable(self, client):
        r = client.get("/api/payload-workbench/operations")
        body = r.get_json()
        for op in body["operations"]:
            assert "run" not in op


class TestRunEndpoint:
    def test_success_returns_200_with_output(self, client):
        r = client.post("/api/payload-workbench/run/generate_xss", json={"complexity": "basic"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert len(body["output"]) > 0

    def test_unknown_operation_returns_200_not_404(self, client):
        # Regression: business-logic failures must stay HTTP 200 with
        # success:false — the frontend's request() helper throws a raw Error
        # for any non-2xx status, bypassing normal success-check handling.
        r = client.post("/api/payload-workbench/run/does_not_exist", json={"input": "x"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert "does_not_exist" in body["error"]

    def test_invalid_complexity_returns_200_not_400(self, client):
        r = client.post("/api/payload-workbench/run/generate_xss", json={"complexity": "not_a_real_level"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert "error" in body

    def test_missing_body_does_not_crash(self, client):
        r = client.post("/api/payload-workbench/run/generate_xss")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True


class TestRunRecipeEndpoint:
    def test_chains_output_into_next_step_input(self, client):
        r = client.post(
            "/api/payload-workbench/run-recipe",
            json={
                "steps": [
                    {"operation_id": "generate_xss", "params": {"complexity": "basic"}},
                    {"operation_id": "apply_evasion", "params": {"technique": "html_encode"}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert "&#60;" in body["output"] or "&lt;" in body["output"]
        assert len(body["steps"]) == 2

    def test_empty_steps_returns_original_input(self, client):
        r = client.post("/api/payload-workbench/run-recipe", json={"input": "unchanged", "steps": []})
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == "unchanged"

    def test_unknown_operation_mid_recipe_stops_and_reports_200(self, client):
        r = client.post(
            "/api/payload-workbench/run-recipe",
            json={
                "steps": [
                    {"operation_id": "generate_xss", "params": {"complexity": "basic"}},
                    {"operation_id": "does_not_exist", "params": {}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert len(body["steps"]) == 2
        assert "error" in body["steps"][1]

    def test_invalid_technique_mid_recipe_reports_which_step_failed(self, client):
        r = client.post(
            "/api/payload-workbench/run-recipe",
            json={
                "input": "<script>alert(1)</script>",
                "steps": [{"operation_id": "apply_evasion", "params": {"technique": "not_a_real_technique"}}],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert body["steps"][0]["operation_id"] == "apply_evasion"
        assert "error" in body["steps"][0]

    def test_continue_on_error_records_failure_and_keeps_going(self, client):
        r = client.post(
            "/api/payload-workbench/run-recipe",
            json={
                "input": "<script>alert(1)</script>",
                "continue_on_error": True,
                "steps": [
                    {"operation_id": "apply_evasion", "params": {"technique": "not_a_real_technique"}},
                    {"operation_id": "apply_evasion", "params": {"technique": "case_mixing"}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["has_errors"] is True
        assert "error" in body["steps"][0]
        # second step must have received the pre-failure value, not empty string
        assert body["steps"][1]["input"] == "<script>alert(1)</script>"


class TestSavedRecipesEndpoints:
    def _create(self, client, name="pytest-payload-workbench-recipe", steps=None):
        r = client.post(
            "/api/payload-workbench/recipes",
            json={"name": name, "steps": steps or [{"operation_id": "generate_xss", "params": {"complexity": "basic"}}]},
        )
        body = r.get_json()
        assert body["success"] is True
        return body["recipe"]

    def test_create_then_list_then_delete(self, client):
        recipe = self._create(client)
        try:
            r = client.get("/api/payload-workbench/recipes")
            body = r.get_json()
            assert body["success"] is True
            assert any(rec["recipe_id"] == recipe["recipe_id"] for rec in body["recipes"])
        finally:
            client.delete(f"/api/payload-workbench/recipes/{recipe['recipe_id']}")

        r = client.get(f"/api/payload-workbench/recipes/{recipe['recipe_id']}")
        assert r.get_json()["success"] is False

    def test_create_empty_name_returns_200_with_error(self, client):
        r = client.post("/api/payload-workbench/recipes", json={"name": "", "steps": []})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False

    def test_get_unknown_recipe_returns_200_not_404(self, client):
        r = client.get("/api/payload-workbench/recipes/does_not_exist")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False

    def test_update_renames_and_replaces_steps(self, client):
        recipe = self._create(client)
        try:
            new_steps = [{"operation_id": "apply_evasion", "params": {"technique": "case_mixing"}}]
            r = client.patch(
                f"/api/payload-workbench/recipes/{recipe['recipe_id']}",
                json={"name": "renamed", "steps": new_steps},
            )
            body = r.get_json()
            assert body["success"] is True
            assert body["recipe"]["name"] == "renamed"
            assert body["recipe"]["steps"] == new_steps
        finally:
            client.delete(f"/api/payload-workbench/recipes/{recipe['recipe_id']}")

    def test_delete_unknown_recipe_returns_200_not_404(self, client):
        r = client.delete("/api/payload-workbench/recipes/does_not_exist")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
