# mcp_tools/enhanced_network_scanning.py

from typing import Dict, Any

def register_enhanced_network_scanning_tools(mcp, hexstrike_client, logger):
    @mcp.tool()
    def rustscan_fast_scan(target: str, ports: str = "", ulimit: int = 5000,
                          batch_size: int = 4500, timeout: int = 1500,
                          scripts: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Rustscan for ultra-fast port scanning with enhanced logging.

        Args:
            target: The target IP address or hostname
            ports: Specific ports to scan (e.g., "22,80,443")
            ulimit: File descriptor limit
            batch_size: Batch size for scanning
            timeout: Timeout in milliseconds
            scripts: Run Nmap scripts on discovered ports
            additional_args: Additional Rustscan arguments

        Returns:
            Ultra-fast port scanning results
        """
        data = {
            "target": target,
            "ports": ports,
            "ulimit": ulimit,
            "batch_size": batch_size,
            "timeout": timeout,
            "scripts": scripts,
            "additional_args": additional_args
        }
        logger.info(f"⚡ Starting Rustscan: {target}")
        result = hexstrike_client.safe_post("api/tools/rustscan", data)
        if result.get("success"):
            logger.info(f"✅ Rustscan completed for {target}")
        else:
            logger.error(f"❌ Rustscan failed for {target}")
        return result

    @mcp.tool()
    def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000,
                          interface: str = "", router_mac: str = "", source_ip: str = "",
                          banners: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting.

        Args:
            target: The target IP address or CIDR range
            ports: Port range to scan
            rate: Packets per second rate
            interface: Network interface to use
            router_mac: Router MAC address
            source_ip: Source IP address
            banners: Enable banner grabbing
            additional_args: Additional Masscan arguments

        Returns:
            High-speed port scanning results with intelligent rate limiting
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "interface": interface,
            "router_mac": router_mac,
            "source_ip": source_ip,
            "banners": banners,
            "additional_args": additional_args
        }
        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = hexstrike_client.safe_post("api/tools/masscan", data)
        if result.get("success"):
            logger.info(f"✅ Masscan completed for {target}")
        else:
            logger.error(f"❌ Masscan failed for {target}")
        return result

    @mcp.tool()
    def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                          timing: str = "T4", nse_scripts: str = "", os_detection: bool = False,
                          version_detection: bool = False, aggressive: bool = False,
                          stealth: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute advanced Nmap scans with custom NSE scripts and optimized timing.

        Args:
            target: The target IP address or hostname
            scan_type: Nmap scan type (e.g., -sS, -sT, -sU)
            ports: Specific ports to scan
            timing: Timing template (T0-T5)
            nse_scripts: Custom NSE scripts to run
            os_detection: Enable OS detection
            version_detection: Enable version detection
            aggressive: Enable aggressive scanning
            stealth: Enable stealth mode
            additional_args: Additional Nmap arguments

        Returns:
            Advanced Nmap scanning results with custom NSE scripts
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "timing": timing,
            "nse_scripts": nse_scripts,
            "os_detection": os_detection,
            "version_detection": version_detection,
            "aggressive": aggressive,
            "stealth": stealth,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = hexstrike_client.safe_post("api/tools/nmap-advanced", data)
        if result.get("success"):
            logger.info(f"✅ Advanced Nmap completed for {target}")
        else:
            logger.error(f"❌ Advanced Nmap failed for {target}")
        return result

    @mcp.tool()
    def autorecon_comprehensive(target: str, output_dir: str = "/tmp/autorecon",
                               port_scans: str = "top-100-ports", service_scans: str = "default",
                               heartbeat: int = 60, timeout: int = 300,
                               additional_args: str = "") -> Dict[str, Any]:
        """
        Execute AutoRecon for comprehensive automated reconnaissance.

        Args:
            target: The target IP address or hostname
            output_dir: Output directory for results
            port_scans: Port scan configuration
            service_scans: Service scan configuration
            heartbeat: Heartbeat interval in seconds
            timeout: Timeout for individual scans
            additional_args: Additional AutoRecon arguments

        Returns:
            Comprehensive automated reconnaissance results
        """
        data = {
            "target": target,
            "output_dir": output_dir,
            "port_scans": port_scans,
            "service_scans": service_scans,
            "heartbeat": heartbeat,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔄 Starting AutoRecon: {target}")
        result = hexstrike_client.safe_post("api/tools/autorecon", data)
        if result.get("success"):
            logger.info(f"✅ AutoRecon completed for {target}")
        else:
            logger.error(f"❌ AutoRecon failed for {target}")
        return result

    @mcp.tool()
    def enum4linux_ng_advanced(target: str, username: str = "", password: str = "",
                               domain: str = "", shares: bool = True, users: bool = True,
                               groups: bool = True, policy: bool = True,
                               additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            shares: Enumerate shares
            users: Enumerate users
            groups: Enumerate groups
            policy: Enumerate policies
            additional_args: Additional Enum4linux-ng arguments

        Returns:
            Advanced SMB enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "shares": shares,
            "users": users,
            "groups": groups,
            "policy": policy,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Enum4linux-ng: {target}")
        result = hexstrike_client.safe_post("api/tools/enum4linux-ng", data)
        if result.get("success"):
            logger.info(f"✅ Enum4linux-ng completed for {target}")
        else:
            logger.error(f"❌ Enum4linux-ng failed for {target}")
        return result

    @mcp.tool()
    def rpcclient_enumeration(target: str, username: str = "", password: str = "",
                             domain: str = "", commands: str = "enumdomusers;enumdomgroups;querydominfo",
                             additional_args: str = "") -> Dict[str, Any]:
        """
        Execute rpcclient for RPC enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            commands: Semicolon-separated RPC commands
            additional_args: Additional rpcclient arguments

        Returns:
            RPC enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting rpcclient: {target}")
        result = hexstrike_client.safe_post("api/tools/rpcclient", data)
        if result.get("success"):
            logger.info(f"✅ rpcclient completed for {target}")
        else:
            logger.error(f"❌ rpcclient failed for {target}")
        return result

    @mcp.tool()
    def nbtscan_netbios(target: str, verbose: bool = False, timeout: int = 2,
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute nbtscan for NetBIOS name scanning with enhanced logging.

        Args:
            target: The target IP address or range
            verbose: Enable verbose output
            timeout: Timeout in seconds
            additional_args: Additional nbtscan arguments

        Returns:
            NetBIOS name scanning results
        """
        data = {
            "target": target,
            "verbose": verbose,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting nbtscan: {target}")
        result = hexstrike_client.safe_post("api/tools/nbtscan", data)
        if result.get("success"):
            logger.info(f"✅ nbtscan completed for {target}")
        else:
            logger.error(f"❌ nbtscan failed for {target}")
        return result

    @mcp.tool()
    def arp_scan_discovery(target: str = "", interface: str = "", local_network: bool = False,
                          timeout: int = 500, retry: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arp-scan for network discovery with enhanced logging.

        Args:
            target: The target IP range (if not using local_network)
            interface: Network interface to use
            local_network: Scan local network
            timeout: Timeout in milliseconds
            retry: Number of retries
            additional_args: Additional arp-scan arguments

        Returns:
            Network discovery results via ARP scanning
        """
        data = {
            "target": target,
            "interface": interface,
            "local_network": local_network,
            "timeout": timeout,
            "retry": retry,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = hexstrike_client.safe_post("api/tools/arp-scan", data)
        if result.get("success"):
            logger.info(f"✅ arp-scan completed")
        else:
            logger.error(f"❌ arp-scan failed")
        return result

    @mcp.tool()
    def responder_credential_harvest(interface: str = "eth0", analyze: bool = False,
                                   wpad: bool = True, force_wpad_auth: bool = False,
                                   fingerprint: bool = False, duration: int = 300,
                                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Responder for credential harvesting with enhanced logging.

        Args:
            interface: Network interface to use
            analyze: Analyze mode only
            wpad: Enable WPAD rogue proxy
            force_wpad_auth: Force WPAD authentication
            fingerprint: Fingerprint mode
            duration: Duration to run in seconds
            additional_args: Additional Responder arguments

        Returns:
            Credential harvesting results
        """
        data = {
            "interface": interface,
            "analyze": analyze,
            "wpad": wpad,
            "force_wpad_auth": force_wpad_auth,
            "fingerprint": fingerprint,
            "duration": duration,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = hexstrike_client.safe_post("api/tools/responder", data)
        if result.get("success"):
            logger.info(f"✅ Responder completed")
        else:
            logger.error(f"❌ Responder failed")
        return result

    @mcp.tool()
    def volatility_analyze(memory_file: str, plugin: str, profile: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility for memory forensics analysis with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility plugin to use
            profile: Memory profile to use
            additional_args: Additional Volatility arguments

        Returns:
            Memory forensics analysis results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "profile": profile,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility analysis: {plugin}")
        result = hexstrike_client.safe_post("api/tools/volatility", data)
        if result.get("success"):
            logger.info(f"✅ Volatility analysis completed")
        else:
            logger.error(f"❌ Volatility analysis failed")
        return result

    @mcp.tool()
    def msfvenom_generate(payload: str, format_type: str = "", output_file: str = "", encoder: str = "", iterations: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute MSFVenom for payload generation with enhanced logging.

        Args:
            payload: The payload to generate
            format_type: Output format (exe, elf, raw, etc.)
            output_file: Output file path
            encoder: Encoder to use
            iterations: Number of encoding iterations
            additional_args: Additional MSFVenom arguments

        Returns:
            Payload generation results
        """
        data = {
            "payload": payload,
            "format": format_type,
            "output_file": output_file,
            "encoder": encoder,
            "iterations": iterations,
            "additional_args": additional_args
        }
        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = hexstrike_client.safe_post("api/tools/msfvenom", data)
        if result.get("success"):
            logger.info(f"✅ MSFVenom payload generated")
        else:
            logger.error(f"❌ MSFVenom payload generation failed")
        return result
