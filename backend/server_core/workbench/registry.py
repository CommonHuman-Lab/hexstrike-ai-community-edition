"""Operation registry for the Workbench data-transform toolset.

Every operation lives in its own module under server_core/workbench/operations/<category>/
and exports a module-level OPERATION: Operation. discover_operations() walks that tree and
builds the registry automatically — adding a new operation (or a whole new category) never
requires touching this file, server_api/workbench, or the frontend.

Convention: every operation must have a param named "input" that carries its primary text —
this is what lets operations be chained into a Recipe (server_api/workbench/routes.py's
/run-recipe feeds each step's output into the next step's "input").
"""

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional


@dataclass(frozen=True)
class ParamSpec:
    name: str
    label: str
    type: str = "text"  # "text" | "textarea" | "number" | "select"
    required: bool = False
    default: Any = ""
    choices: Optional[List[str]] = None
    help_text: str = ""
    hidden: bool = False

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "label": self.label,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "help_text": self.help_text,
        }
        if self.choices:
            d["choices"] = self.choices
        if self.hidden:
            d["hidden"] = self.hidden
        return d


@dataclass(frozen=True)
class Operation:
    id: str
    category: str
    name: str
    description: str
    run: Callable[[dict], dict]
    params: List[ParamSpec] = field(default_factory=list)
    decloak_try: Optional[Callable[[str], Optional[str]]] = None
    decloak_priority: int = 100
    decloak_terminal: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "params": [p.to_dict() for p in self.params],
        }


def _discover() -> "dict[str, Operation]":
    import importlib
    import pkgutil

    import backend.server_core.workbench.operations as _operations_pkg

    operations: "dict[str, Operation]" = {}
    for _, category_name, is_pkg in pkgutil.iter_modules(_operations_pkg.__path__):
        if not is_pkg:
            continue
        category_pkg = importlib.import_module(f"backend.server_core.workbench.operations.{category_name}")
        for _, module_name, _ in pkgutil.iter_modules(category_pkg.__path__):
            module = importlib.import_module(
                f"backend.server_core.workbench.operations.{category_name}.{module_name}"
            )
            op = getattr(module, "OPERATION", None)
            if op is not None:
                operations[op.id] = op
    return operations


OPERATIONS = _discover()
CATEGORIES = sorted({op.category for op in OPERATIONS.values()})


def get_operation(operation_id: str) -> Optional[Operation]:
    return OPERATIONS.get(operation_id)


def list_operations() -> List[Operation]:
    return sorted(OPERATIONS.values(), key=lambda op: (op.category, op.name))
