from backend.server_api._generic.autoload import register_all_toolspec_blueprints
from .ai_assist import *
from .tools_catalog import *
from .ui_blueprint import *
from .settings import *
from .ctf import *
from .process import *
from .api_audit import *
from .error_handling import *
from .ops import *
from .vuln_intel import *
from .burp_agent import *
from .workbench import *
from .payload_workbench import *

def register_blueprints(app):
  """Register all API blueprints with the Flask app."""

  register_all_toolspec_blueprints(app)

  # OPS — System Monitoring & File Ops
  app.register_blueprint(api_system_monitoring_bp)
  app.register_blueprint(api_logs_bp)
  app.register_blueprint(api_web_dashboard_bp)
  app.register_blueprint(api_runs_bp)
  app.register_blueprint(api_sessions_bp)
  app.register_blueprint(api_session_notes_bp)
  app.register_blueprint(api_session_findings_bp)
  app.register_blueprint(api_session_reports_bp)
  app.register_blueprint(api_credentials_bp)
  app.register_blueprint(api_loot_bp)
  app.register_blueprint(api_topology_bp)

  # OPS — General
  app.register_blueprint(api_process_management_bp)
  app.register_blueprint(api_process_execute_async_bp)
  app.register_blueprint(api_process_get_task_result_bp)
  app.register_blueprint(api_process_pool_stats_bp)
  app.register_blueprint(api_process_cache_stats_bp)
  app.register_blueprint(api_process_clear_cache_bp)
  app.register_blueprint(api_process_resource_usage_bp)
  app.register_blueprint(api_process_performance_dashboard_bp)
  app.register_blueprint(api_process_terminate_gracefully_bp)
  app.register_blueprint(api_process_auto_scaling_bp)
  app.register_blueprint(api_process_scale_pool_bp)
  app.register_blueprint(api_process_health_check_bp)

  # Vulnerability Intelligence
  app.register_blueprint(api_vulnerability_intelligence_bp)
  app.register_blueprint(api_vuln_intel_cve_exploit_chain_bp)

  # AI Assist
  app.register_blueprint(api_chat_bp)
  app.register_blueprint(api_ai_assist_llm_agent_bp)
  app.register_blueprint(api_ai_assist_ai_recon_session_bp)
  app.register_blueprint(api_ai_assist_ai_profiling_session_bp)
  app.register_blueprint(api_ai_assist_ai_vuln_session_bp)
  app.register_blueprint(api_ai_assist_ai_osint_session_bp)
  app.register_blueprint(api_ai_assist_ai_followup_session_bp)

  # Tools Catalog
  app.register_blueprint(api_tools_catalog_bp)

  # Settings
  app.register_blueprint(api_settings_bp)

  # Web UI
  app.register_blueprint(api_ui_bp)

  # Plugins
  app.register_blueprint(api_plugins_bp)

  # CTF
  app.register_blueprint(api_ctf_create_challenge_workflow_bp)
  app.register_blueprint(api_ctf_auto_solve_challenge_bp)
  app.register_blueprint(api_ctf_team_strategy_bp)
  app.register_blueprint(api_ctf_suggest_tools_bp)
  app.register_blueprint(api_ctf_cryptography_solver_bp)
  app.register_blueprint(api_ctf_forensics_analyzer_bp)
  app.register_blueprint(api_ctf_binary_analyzer_bp)

  # Burp Agent Loop
  app.register_blueprint(api_burp_agent_bp)

  # Intelligent Error Handling
  app.register_blueprint(api_error_handling_fallback_chains_bp)
  app.register_blueprint(api_error_handling_execute_with_recovery_bp)
  app.register_blueprint(api_error_handling_classify_error_bp)
  app.register_blueprint(api_error_handling_parameter_adjustments_bp)
  app.register_blueprint(api_error_handling_alternative_tools_bp)

  # Workbench
  app.register_blueprint(api_workbench_bp)

  # Payload Workbench
  app.register_blueprint(api_payload_workbench_bp)
