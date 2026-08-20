from flask import Blueprint, jsonify, request

from backend.server_core.singletons import db
from backend.server_core.payload_workbench.registry import CATEGORIES, get_operation, list_operations

api_payload_workbench_bp = Blueprint("api_payload_workbench", __name__)


@api_payload_workbench_bp.route("/api/payload-workbench/operations", methods=["GET"])
def payload_workbench_operations():
    return jsonify(
        {
            "success": True,
            "categories": CATEGORIES,
            "operations": [op.to_dict() for op in list_operations()],
        }
    )


@api_payload_workbench_bp.route("/api/payload-workbench/run/<operation_id>", methods=["POST"])
def payload_workbench_run(operation_id: str):
    op = get_operation(operation_id)
    if op is None:
        return jsonify({"success": False, "error": f"Unknown operation: {operation_id}"})

    params = request.get_json(silent=True) or {}
    try:
        result = op.run(params)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)})
    except Exception as e:
        return jsonify({"success": False, "error": f"Operation failed: {e}"})

    return jsonify({"success": True, **result})


@api_payload_workbench_bp.route("/api/payload-workbench/run-recipe", methods=["POST"])
def payload_workbench_run_recipe():
    body = request.get_json(silent=True) or {}
    current = body.get("input", "")
    current_mime = None
    continue_on_error = bool(body.get("continue_on_error", False))
    stop_after = body.get("stop_after_step_index")
    overrides = body.get("step_input_overrides") or {}
    step_results = []
    has_errors = False

    steps = body.get("steps") or []
    if stop_after is not None:
        steps = steps[: int(stop_after) + 1]

    def record_failure(operation_id, name, step_input, error):
        entry = {"operation_id": operation_id, "input": step_input, "error": error}
        if name is not None:
            entry["name"] = name
        step_results.append(entry)

    for i, step in enumerate(steps):
        operation_id = step.get("operation_id")
        op = get_operation(operation_id)
        step_input = overrides.get(str(i), current)

        if op is None:
            error = f"Unknown operation: {operation_id}"
            record_failure(operation_id, None, step_input, error)
            if not continue_on_error:
                return jsonify({"success": False, "error": error, "steps": step_results})
            has_errors = True
            continue

        params = dict(step.get("params") or {})
        params["input"] = step_input
        try:
            result = op.run(params)
        except ValueError as e:
            record_failure(operation_id, op.name, step_input, str(e))
            if not continue_on_error:
                return jsonify({"success": False, "error": str(e), "steps": step_results})
            has_errors = True
            continue
        except Exception as e:
            error = f"Operation failed: {e}"
            record_failure(operation_id, op.name, step_input, error)
            if not continue_on_error:
                return jsonify({"success": False, "error": error, "steps": step_results})
            has_errors = True
            continue

        current = result.get("output", "")
        current_mime = result.get("output_mime")
        entry = {"operation_id": operation_id, "name": op.name, "input": step_input, "output": current}
        if current_mime:
            entry["output_mime"] = current_mime
        step_results.append(entry)

    response = {"success": True, "output": current, "steps": step_results, "has_errors": has_errors}
    if current_mime:
        response["output_mime"] = current_mime
    return jsonify(response)


@api_payload_workbench_bp.route("/api/payload-workbench/recipes", methods=["GET"])
def payload_workbench_list_recipes():
    return jsonify({"success": True, "recipes": db.list_payload_workbench_recipes()})


@api_payload_workbench_bp.route("/api/payload-workbench/recipes", methods=["POST"])
def payload_workbench_create_recipe():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "Recipe name must not be empty"})
    steps = body.get("steps") or []
    recipe_id = db.add_payload_workbench_recipe(name, steps)
    return jsonify({"success": True, "recipe": db.get_payload_workbench_recipe(recipe_id)})


@api_payload_workbench_bp.route("/api/payload-workbench/recipes/<recipe_id>", methods=["GET"])
def payload_workbench_get_recipe(recipe_id: str):
    recipe = db.get_payload_workbench_recipe(recipe_id)
    if recipe is None:
        return jsonify({"success": False, "error": f"Unknown recipe: {recipe_id}"})
    return jsonify({"success": True, "recipe": recipe})


@api_payload_workbench_bp.route("/api/payload-workbench/recipes/<recipe_id>", methods=["PATCH"])
def payload_workbench_update_recipe(recipe_id: str):
    if db.get_payload_workbench_recipe(recipe_id) is None:
        return jsonify({"success": False, "error": f"Unknown recipe: {recipe_id}"})
    body = request.get_json(silent=True) or {}
    fields = {}
    if "name" in body:
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Recipe name must not be empty"})
        fields["name"] = name
    if "steps" in body:
        fields["steps"] = body.get("steps") or []
    db.update_payload_workbench_recipe(recipe_id, **fields)
    return jsonify({"success": True, "recipe": db.get_payload_workbench_recipe(recipe_id)})


@api_payload_workbench_bp.route("/api/payload-workbench/recipes/<recipe_id>", methods=["DELETE"])
def payload_workbench_delete_recipe(recipe_id: str):
    if db.get_payload_workbench_recipe(recipe_id) is None:
        return jsonify({"success": False, "error": f"Unknown recipe: {recipe_id}"})
    db.delete_payload_workbench_recipe(recipe_id)
    return jsonify({"success": True})
