# mcp_tools/additional_security_tools.py

from typing import Dict, Any

def register_additional_security_tools(mcp, hexstrike_client, logger):

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
