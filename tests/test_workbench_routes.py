"""
tests/test_workbench_routes.py

Flask test-client tests for the Workbench blueprint (server_api/workbench/routes.py).
Operations are pure Python (no subprocess), so these hit the real registry —
only the app-level execute_command/singleton patches from conftest.py apply.
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
        r = client.get("/api/workbench/operations")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert "encoding" in body["categories"]
        assert any(op["id"] == "base64" for op in body["operations"])

    def test_operations_do_not_leak_run_callable(self, client):
        r = client.get("/api/workbench/operations")
        body = r.get_json()
        for op in body["operations"]:
            assert "run" not in op


class TestRunEndpoint:
    def test_success_returns_200_with_output(self, client):
        r = client.post("/api/workbench/run/base64", json={"input": "hello", "mode": "encode"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == "aGVsbG8="

    def test_unknown_operation_returns_200_not_404(self, client):
        # Regression: business-logic failures must stay HTTP 200 with
        # success:false — the frontend's request() helper throws a raw Error
        # for any non-2xx status, bypassing normal success-check handling.
        r = client.post("/api/workbench/run/does_not_exist", json={"input": "x"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert "does_not_exist" in body["error"]

    def test_invalid_input_returns_200_not_400(self, client):
        r = client.post("/api/workbench/run/base64", json={"input": "!!!not valid!!!", "mode": "decode"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert "error" in body

    def test_missing_body_does_not_crash(self, client):
        # No JSON body -> params defaults to {} -> operations treat a missing
        # "input" as an empty string rather than raising, and fall back to
        # their default mode.
        r = client.post("/api/workbench/run/base64")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == ""


class TestRunRecipeEndpoint:
    def test_chains_output_into_next_step_input(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "hello",
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "encode"}},
                    {"operation_id": "base64", "params": {"mode": "decode"}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == "hello"
        assert len(body["steps"]) == 2

    def test_empty_steps_returns_original_input(self, client):
        r = client.post("/api/workbench/run-recipe", json={"input": "unchanged", "steps": []})
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == "unchanged"

    def test_unknown_operation_mid_recipe_stops_and_reports_200(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "hello",
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "encode"}},
                    {"operation_id": "does_not_exist", "params": {}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert len(body["steps"]) == 2
        assert body["steps"][0]["output"] == "aGVsbG8="
        assert "error" in body["steps"][1]

    def test_invalid_input_mid_recipe_reports_which_step_failed(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "not valid base64 at all!!!",
                "steps": [{"operation_id": "base64", "params": {"mode": "decode"}}],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert body["steps"][0]["operation_id"] == "base64"
        assert "error" in body["steps"][0]

    def test_trace_includes_input_field(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={"input": "hello", "steps": [{"operation_id": "rot13", "params": {}}]},
        )
        body = r.get_json()
        assert body["steps"][0]["input"] == "hello"

    def test_continue_on_error_false_still_aborts(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "not valid base64 at all!!!",
                "continue_on_error": False,
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "decode"}},
                    {"operation_id": "rot13", "params": {}},
                ],
            },
        )
        body = r.get_json()
        assert body["success"] is False
        assert len(body["steps"]) == 1

    def test_continue_on_error_records_failure_and_keeps_going(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "not valid base64 at all!!!",
                "continue_on_error": True,
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "decode"}},
                    {"operation_id": "rot13", "params": {}},
                ],
            },
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["has_errors"] is True
        assert "error" in body["steps"][0]
        # rot13 must have received the pre-failure value ("not valid base64 at all!!!"), not empty string
        assert body["steps"][1]["input"] == "not valid base64 at all!!!"
        assert body["output"] == body["steps"][1]["output"]

    def test_stop_after_step_index_returns_partial_trace(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "hello",
                "stop_after_step_index": 0,
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "encode"}},
                    {"operation_id": "rot13", "params": {}},
                ],
            },
        )
        body = r.get_json()
        assert body["success"] is True
        assert len(body["steps"]) == 1
        assert body["output"] == "aGVsbG8="

    def test_step_input_overrides_replaces_only_that_step(self, client):
        r = client.post(
            "/api/workbench/run-recipe",
            json={
                "input": "hello",
                "step_input_overrides": {"1": "OVERRIDDEN"},
                "steps": [
                    {"operation_id": "base64", "params": {"mode": "encode"}},
                    {"operation_id": "rot13", "params": {}},
                ],
            },
        )
        body = r.get_json()
        assert body["success"] is True
        assert body["steps"][1]["input"] == "OVERRIDDEN"
        assert body["output"] != "hello"


class TestDecloakEndpoint:
    def test_returns_success_with_chain(self, client):
        r = client.post(
            "/api/workbench/decloak",
            json={"input": "564739775532566a636d56305132396b5a513d3d"},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == "TopSecretCode"
        assert len(body["steps"]) == 2

    def test_missing_body_does_not_crash(self, client):
        r = client.post("/api/workbench/decloak")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["output"] == ""


class TestSavedRecipesEndpoints:
    def _create(self, client, name="pytest-workbench-recipe", steps=None):
        r = client.post(
            "/api/workbench/recipes",
            json={"name": name, "steps": steps or [{"operation_id": "base64", "params": {"mode": "encode"}}]},
        )
        body = r.get_json()
        assert body["success"] is True
        return body["recipe"]

    def test_create_then_list_then_delete(self, client):
        recipe = self._create(client)
        try:
            r = client.get("/api/workbench/recipes")
            body = r.get_json()
            assert body["success"] is True
            assert any(rec["recipe_id"] == recipe["recipe_id"] for rec in body["recipes"])
        finally:
            client.delete(f"/api/workbench/recipes/{recipe['recipe_id']}")

        r = client.get(f"/api/workbench/recipes/{recipe['recipe_id']}")
        assert r.get_json()["success"] is False

    def test_create_empty_name_returns_200_with_error(self, client):
        r = client.post("/api/workbench/recipes", json={"name": "", "steps": []})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False

    def test_get_unknown_recipe_returns_200_not_404(self, client):
        r = client.get("/api/workbench/recipes/does_not_exist")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False

    def test_update_renames_and_replaces_steps(self, client):
        recipe = self._create(client)
        try:
            new_steps = [{"operation_id": "rot13", "params": {}}]
            r = client.patch(
                f"/api/workbench/recipes/{recipe['recipe_id']}",
                json={"name": "renamed", "steps": new_steps},
            )
            body = r.get_json()
            assert body["success"] is True
            assert body["recipe"]["name"] == "renamed"
            assert body["recipe"]["steps"] == new_steps
        finally:
            client.delete(f"/api/workbench/recipes/{recipe['recipe_id']}")

    def test_delete_unknown_recipe_returns_200_not_404(self, client):
        r = client.delete("/api/workbench/recipes/does_not_exist")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
