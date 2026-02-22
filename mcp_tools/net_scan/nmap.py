# mcp_tools/net_scan/nmap.py

from typing import Dict, Any

def register_nmap(mcp, hexstrike_client, logger, HexStrikeColors):
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an enhanced Nmap scan against a target with real-time logging.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection, -sC for scripts)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data: Dict[str, Any] = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        logger.info(f"{HexStrikeColors.FIRE_RED}🔍 Initiating Nmap scan: {target}{HexStrikeColors.RESET}")

        # Use enhanced error handling by default
        data["use_recovery"] = True
        result = hexstrike_client.safe_post("api/tools/nmap", data)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Nmap scan completed successfully for {target}{HexStrikeColors.RESET}")

            # Check for recovery information
            if result.get("recovery_info", {}).get("recovery_applied"):
                recovery_info = result["recovery_info"]
                attempts = recovery_info.get("attempts_made", 1)
                logger.info(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Nmap scan failed for {target}{HexStrikeColors.RESET}")

            # Check for human escalation
            if result.get("human_escalation"):
                logger.error(f"{HexStrikeColors.CRITICAL} HUMAN ESCALATION REQUIRED {HexStrikeColors.RESET}")

        return result
