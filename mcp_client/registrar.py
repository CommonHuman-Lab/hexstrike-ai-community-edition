"""Generic FastMCP tool registrar driven by a ToolSpec.

FastMCP's @mcp.tool() derives a tool's JSON schema and per-arg docs purely via
inspect.signature() + docstring parsing on the wrapped function — there is no API
to hand it an explicit schema independent of the function's real signature. To keep
genuinely-named, genuinely-schema'd per-tool MCP functions (needed for good LLM
tool-selection) without hand-writing the wrapper for every tool, this builds a real
function object per spec via exec() of a generated source string, then decorates it.

Safety: spec objects are static, developer-authored ToolSpec literals checked into
source control (server_core/tool_specs/*.py) — no request/user data ever reaches
exec(). This is the same category of technique CPython's own dataclasses module
uses internally to generate __init__.
"""

import asyncio
import importlib
import re
from typing import Any, Dict

from backend.server_core.tool_spec import ToolSpec

_TYPE_NAMES = {str: "str", bool: "bool", int: "int", float: "float", list: "list", dict: "dict"}
_PATH_PARAM_RE = re.compile(r"<(?:\w+:)?(\w+)>")
_SAFE_METHODS = {"GET": "safe_get", "POST": "safe_post", "DELETE": "safe_delete"}


def _build_signature_src(spec: ToolSpec) -> str:
    parts = []
    for p in spec.params:
        type_name = _TYPE_NAMES.get(p.type, "str")
        if p.required:
            parts.append(f"{p.name}: {type_name}")
        else:
            parts.append(f"{p.name}: {type_name} = {p.default!r}")
    return ", ".join(parts)


def _build_docstring(spec: ToolSpec) -> str:
    lines = [spec.description.strip(), "", "Args:"]
    for p in spec.params:
        lines.append(f"    {p.name}: {p.help_text or p.name}")
    lines += ["", "Returns:", f"    {spec.name} execution results"]
    return "\n    ".join(lines)


def register_tool_from_spec(mcp, api_client, logger, spec: ToolSpec):
    param_src = _build_signature_src(spec)
    docstring = _build_docstring(spec)

    endpoint_template = spec.endpoint.lstrip("/")
    path_param_names = set(_PATH_PARAM_RE.findall(endpoint_template))
    endpoint_template = _PATH_PARAM_RE.sub(r"{\1}", endpoint_template)

    body_arg_names = [p.name for p in spec.params if p.name not in path_param_names]
    data_literal = ", ".join(f"{n!r}: {n}" for n in body_arg_names)
    safe_method = _SAFE_METHODS.get(spec.method, "safe_post")

    src = (
        f"async def {spec.mcp_tool_name}({param_src}) -> Dict[str, Any]:\n"
        f'    """{docstring}\n    """\n'
        f"    _endpoint = f{endpoint_template!r}\n"
        f"    data = {{{data_literal}}}\n"
        f"    loop = asyncio.get_running_loop()\n"
        f"    return await loop.run_in_executor(\n"
        f"        None, lambda: api_client.{safe_method}(_endpoint, data)\n"
        f"    )\n"
    )

    namespace = {
        "Dict": Dict,
        "Any": Any,
        "asyncio": asyncio,
        "api_client": api_client,
    }
    exec(compile(src, f"<toolspec:{spec.name}>", "exec"), namespace)
    fn = namespace[spec.mcp_tool_name]
    return mcp.tool()(fn)


def register_toolspec_category(mcp, api_client, logger, category: str):
    """Auto-load server_core.tool_specs.<category> and register every tool in it.
    """
    module = importlib.import_module(f"backend.server_core.tool_specs.{category}")
    for spec in module.SPECS:
        register_tool_from_spec(mcp, api_client, logger, spec)
