from flask import Blueprint, jsonify, request

from backend.server_core.singletons import db
from backend.server_core.workbench.decloak import run_decloak
from backend.server_core.workbench.registry import CATEGORIES, get_operation, list_operations

api_workbench_bp = Blueprint("api_workbench", __name__)


@api_workbench_bp.route("/api/workbench/operations", methods=["GET"])
def workbench_operations():
    return jsonify(
        {
            "success": True,
            "categories": CATEGORIES,
            "operations": [op.to_dict() for op in list_operations()],
        }
    )


@api_workbench_bp.route("/api/workbench/run/<operation_id>", methods=["POST"])
def workbench_run(operation_id: str):
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


@api_workbench_bp.route("/api/workbench/run-recipe", methods=["POST"])
def workbench_run_recipe():
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


@api_workbench_bp.route("/api/workbench/decloak", methods=["POST"])
def workbench_decloak():
    body = request.get_json(silent=True) or {}
    input_text = body.get("input", "")
    max_depth = body.get("max_depth")
    try:
        max_depth = int(max_depth) if max_depth is not None else 8
    except (TypeError, ValueError):
        max_depth = 8
    try:
        result = run_decloak(input_text, max_depth=max_depth)
    except Exception as e:
        return jsonify({"success": False, "error": f"Decloak failed: {e}"})
    return jsonify({"success": True, **result})


@api_workbench_bp.route("/api/workbench/recipes", methods=["GET"])
def workbench_list_recipes():
    return jsonify({"success": True, "recipes": db.list_workbench_recipes()})


@api_workbench_bp.route("/api/workbench/recipes", methods=["POST"])
def workbench_create_recipe():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "Recipe name must not be empty"})
    steps = body.get("steps") or []
    recipe_id = db.add_workbench_recipe(name, steps)
    return jsonify({"success": True, "recipe": db.get_workbench_recipe(recipe_id)})


@api_workbench_bp.route("/api/workbench/recipes/<recipe_id>", methods=["GET"])
def workbench_get_recipe(recipe_id: str):
    recipe = db.get_workbench_recipe(recipe_id)
    if recipe is None:
        return jsonify({"success": False, "error": f"Unknown recipe: {recipe_id}"})
    return jsonify({"success": True, "recipe": recipe})


@api_workbench_bp.route("/api/workbench/recipes/<recipe_id>", methods=["PATCH"])
def workbench_update_recipe(recipe_id: str):
    if db.get_workbench_recipe(recipe_id) is None:
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
    db.update_workbench_recipe(recipe_id, **fields)
    return jsonify({"success": True, "recipe": db.get_workbench_recipe(recipe_id)})


@api_workbench_bp.route("/api/workbench/recipes/<recipe_id>", methods=["DELETE"])
def workbench_delete_recipe(recipe_id: str):
    if db.get_workbench_recipe(recipe_id) is None:
        return jsonify({"success": False, "error": f"Unknown recipe: {recipe_id}"})
    db.delete_workbench_recipe(recipe_id)
    return jsonify({"success": True})
