import shlex
import time

from backend.server_core.file_ops import file_manager
from backend.server_core.python_env_manager import env_manager
from backend.server_core.tool_spec import ParamSpec, ToolSpec


def _execute_python_script_build_command(p: dict) -> str:
    filename = p["filename"] or f"script_{int(time.time())}.py"
    p["filename"] = filename

    script_result = file_manager.create_file(filename, p["script"])
    if not script_result["success"]:
        raise RuntimeError(script_result.get("error", "Failed to create script file"))

    python_path = env_manager.get_python_path(p["env_name"])
    return shlex.join([python_path, script_result["path"]])


def _install_python_package_handler(p: dict) -> dict:
    package = p["package"]
    env_name = p["env_name"]

    if not env_manager.install_package(env_name, package):
        raise RuntimeError(f"Failed to install package {package}")

    return {
        "success": True,
        "message": f"Package {package} installed successfully",
        "env_name": env_name,
    }


def _execute_python_script_postprocess(raw: dict, p: dict) -> dict:
    file_manager.delete_file(p["filename"])

    if isinstance(raw, dict):
        raw["env_name"] = p["env_name"]
        raw["script_filename"] = p["filename"]

    return raw


SPECS = [
    ToolSpec(
        name="execute_python_script",
        mcp_tool_name="execute_python_script",
        endpoint="/api/python/execute",
        category="python_env",
        description="Execute a Python script in a virtual environment on the API server.",
        params=[
            ParamSpec("script", str, required=True, help_text="Python script content to execute"),
            ParamSpec("env_name", str, default="default", help_text="Name of the virtual environment"),
            ParamSpec("filename", str, default="", help_text="Custom script filename (auto-generated if empty)"),
        ],
        build_command=_execute_python_script_build_command,
        postprocess=_execute_python_script_postprocess,
        use_cache=False,
    ),
    ToolSpec(
        name="install_python_package",
        mcp_tool_name="install_python_package",
        endpoint="/api/python/install",
        category="python_env",
        description="Install a Python package in a virtual environment on the API server.",
        params=[
            ParamSpec("package", str, required=True, help_text="Name of the Python package to install"),
            ParamSpec("env_name", str, default="default", help_text="Name of the virtual environment"),
        ],
        handler=_install_python_package_handler,
    ),
]
