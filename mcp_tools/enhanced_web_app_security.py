# mcp_tools/enhanced_web_app_security.py

from typing import Dict, Any, Optional

def register_enhanced_web_app_security_tools(mcp, hexstrike_client, logger, HexStrikeColors):
    @mcp.tool()
    def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json",
                      wordlist: str = "/usr/share/wordlists/dirsearch/common.txt",
                      threads: int = 30, recursive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirsearch for advanced directory and file discovery with enhanced logging.

        Args:
            url: The target URL
            extensions: File extensions to search for
            wordlist: Wordlist file to use
            threads: Number of threads to use
            recursive: Enable recursive scanning
            additional_args: Additional Dirsearch arguments

        Returns:
            Advanced directory discovery results
        """
        data = {
            "url": url,
            "extensions": extensions,
            "wordlist": wordlist,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = hexstrike_client.safe_post("api/tools/dirsearch", data)
        if result.get("success"):
            logger.info(f"✅ Dirsearch scan completed for {url}")
        else:
            logger.error(f"❌ Dirsearch scan failed for {url}")
        return result

    @mcp.tool()
    def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True,
                    form_extraction: bool = True, output_format: str = "json",
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Katana for next-generation crawling and spidering with enhanced logging.

        Args:
            url: The target URL to crawl
            depth: Crawling depth
            js_crawl: Enable JavaScript crawling
            form_extraction: Enable form extraction
            output_format: Output format (json, txt)
            additional_args: Additional Katana arguments

        Returns:
            Advanced web crawling results with endpoints and forms
        """
        data = {
            "url": url,
            "depth": depth,
            "js_crawl": js_crawl,
            "form_extraction": form_extraction,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = hexstrike_client.safe_post("api/tools/katana", data)
        if result.get("success"):
            logger.info(f"✅ Katana crawl completed for {url}")
        else:
            logger.error(f"❌ Katana crawl failed for {url}")
        return result

    @mcp.tool()
    def gau_discovery(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan",
                     include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging.

        Args:
            domain: The target domain
            providers: Data providers to use
            include_subs: Include subdomains
            blacklist: File extensions to blacklist
            additional_args: Additional Gau arguments

        Returns:
            Comprehensive URL discovery results from multiple sources
        """
        data = {
            "domain": domain,
            "providers": providers,
            "include_subs": include_subs,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/gau", data)
        if result.get("success"):
            logger.info(f"✅ Gau URL discovery completed for {domain}")
        else:
            logger.error(f"❌ Gau URL discovery failed for {domain}")
        return result

    @mcp.tool()
    def waybackurls_discovery(domain: str, get_versions: bool = False,
                             no_subs: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Waybackurls for historical URL discovery with enhanced logging.

        Args:
            domain: The target domain
            get_versions: Get all versions of URLs
            no_subs: Don't include subdomains
            additional_args: Additional Waybackurls arguments

        Returns:
            Historical URL discovery results from Wayback Machine
        """
        data = {
            "domain": domain,
            "get_versions": get_versions,
            "no_subs": no_subs,
            "additional_args": additional_args
        }
        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/waybackurls", data)
        if result.get("success"):
            logger.info(f"✅ Waybackurls discovery completed for {domain}")
        else:
            logger.error(f"❌ Waybackurls discovery failed for {domain}")
        return result

    @mcp.tool()
    def arjun_parameter_discovery(url: str, method: str = "GET", wordlist: str = "",
                                 delay: int = 0, threads: int = 25, stable: bool = False,
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for HTTP parameter discovery with enhanced logging.

        Args:
            url: The target URL
            method: HTTP method to use
            wordlist: Custom wordlist file
            delay: Delay between requests
            threads: Number of threads
            stable: Use stable mode
            additional_args: Additional Arjun arguments

        Returns:
            HTTP parameter discovery results
        """
        data = {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "delay": delay,
            "threads": threads,
            "stable": stable,
            "additional_args": additional_args
        }
        logger.info(f"🎯 Starting Arjun parameter discovery: {url}")
        result = hexstrike_client.safe_post("api/tools/arjun", data)
        if result.get("success"):
            logger.info(f"✅ Arjun parameter discovery completed for {url}")
        else:
            logger.error(f"❌ Arjun parameter discovery failed for {url}")
        return result

    @mcp.tool()
    def paramspider_mining(domain: str, level: int = 2,
                          exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                          output: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter mining from web archives with enhanced logging.

        Args:
            domain: The target domain
            level: Mining level depth
            exclude: File extensions to exclude
            output: Output file path
            additional_args: Additional ParamSpider arguments

        Returns:
            Parameter mining results from web archives
        """
        data = {
            "domain": domain,
            "level": level,
            "exclude": exclude,
            "output": output,
            "additional_args": additional_args
        }
        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = hexstrike_client.safe_post("api/tools/paramspider", data)
        if result.get("success"):
            logger.info(f"✅ ParamSpider mining completed for {domain}")
        else:
            logger.error(f"❌ ParamSpider mining failed for {domain}")
        return result

    @mcp.tool()
    def x8_parameter_discovery(url: str, wordlist: str = "/usr/share/wordlists/x8/params.txt",
                              method: str = "GET", body: str = "", headers: str = "",
                              additional_args: str = "") -> Dict[str, Any]:
        """
        Execute x8 for hidden parameter discovery with enhanced logging.

        Args:
            url: The target URL
            wordlist: Parameter wordlist
            method: HTTP method
            body: Request body
            headers: Custom headers
            additional_args: Additional x8 arguments

        Returns:
            Hidden parameter discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "body": body,
            "headers": headers,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = hexstrike_client.safe_post("api/tools/x8", data)
        if result.get("success"):
            logger.info(f"✅ x8 parameter discovery completed for {url}")
        else:
            logger.error(f"❌ x8 parameter discovery failed for {url}")
        return result

    @mcp.tool()
    def jaeles_vulnerability_scan(url: str, signatures: str = "", config: str = "",
                                 threads: int = 20, timeout: int = 20,
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Jaeles for advanced vulnerability scanning with custom signatures.

        Args:
            url: The target URL
            signatures: Custom signature path
            config: Configuration file
            threads: Number of threads
            timeout: Request timeout
            additional_args: Additional Jaeles arguments

        Returns:
            Advanced vulnerability scanning results with custom signatures
        """
        data = {
            "url": url,
            "signatures": signatures,
            "config": config,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = hexstrike_client.safe_post("api/tools/jaeles", data)
        if result.get("success"):
            logger.info(f"✅ Jaeles vulnerability scan completed for {url}")
        else:
            logger.error(f"❌ Jaeles vulnerability scan failed for {url}")
        return result

    @mcp.tool()
    def dalfox_xss_scan(url: str, pipe_mode: bool = False, blind: bool = False,
                       mining_dom: bool = True, mining_dict: bool = True,
                       custom_payload: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging.

        Args:
            url: The target URL
            pipe_mode: Use pipe mode for input
            blind: Enable blind XSS testing
            mining_dom: Enable DOM mining
            mining_dict: Enable dictionary mining
            custom_payload: Custom XSS payload
            additional_args: Additional Dalfox arguments

        Returns:
            Advanced XSS vulnerability scanning results
        """
        data = {
            "url": url,
            "pipe_mode": pipe_mode,
            "blind": blind,
            "mining_dom": mining_dom,
            "mining_dict": mining_dict,
            "custom_payload": custom_payload,
            "additional_args": additional_args
        }
        logger.info(f"🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}")
        result = hexstrike_client.safe_post("api/tools/dalfox", data)
        if result.get("success"):
            logger.info(f"✅ Dalfox XSS scan completed")
        else:
            logger.error(f"❌ Dalfox XSS scan failed")
        return result

    @mcp.tool()
    def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False,
                   status_code: bool = False, content_length: bool = False,
                   title: bool = False, web_server: bool = False, threads: int = 50,
                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for fast HTTP probing and technology detection.

        Args:
            target: Target file or single URL
            probe: Enable probing
            tech_detect: Enable technology detection
            status_code: Show status codes
            content_length: Show content length
            title: Show page titles
            web_server: Show web server
            threads: Number of threads
            additional_args: Additional httpx arguments

        Returns:
            Fast HTTP probing results with technology detection
        """
        data = {
            "target": target,
            "probe": probe,
            "tech_detect": tech_detect,
            "status_code": status_code,
            "content_length": content_length,
            "title": title,
            "web_server": web_server,
            "threads": threads,
            "additional_args": additional_args
        }
        logger.info(f"🌍 Starting httpx probe: {target}")
        result = hexstrike_client.safe_post("api/tools/httpx", data)
        if result.get("success"):
            logger.info(f"✅ httpx probe completed for {target}")
        else:
            logger.error(f"❌ httpx probe failed for {target}")
        return result

    @mcp.tool()
    def anew_data_processing(input_data: str, output_file: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute anew for appending new lines to files (useful for data processing).

        Args:
            input_data: Input data to process
            output_file: Output file path
            additional_args: Additional anew arguments

        Returns:
            Data processing results with unique line filtering
        """
        data = {
            "input_data": input_data,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info("📝 Starting anew data processing")
        result = hexstrike_client.safe_post("api/tools/anew", data)
        if result.get("success"):
            logger.info("✅ anew data processing completed")
        else:
            logger.error("❌ anew data processing failed")
        return result

    @mcp.tool()
    def qsreplace_parameter_replacement(urls: str, replacement: str = "FUZZ",
                                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute qsreplace for query string parameter replacement.

        Args:
            urls: URLs to process
            replacement: Replacement string for parameters
            additional_args: Additional qsreplace arguments

        Returns:
            Parameter replacement results for fuzzing
        """
        data = {
            "urls": urls,
            "replacement": replacement,
            "additional_args": additional_args
        }
        logger.info("🔄 Starting qsreplace parameter replacement")
        result = hexstrike_client.safe_post("api/tools/qsreplace", data)
        if result.get("success"):
            logger.info("✅ qsreplace parameter replacement completed")
        else:
            logger.error("❌ qsreplace parameter replacement failed")
        return result

    @mcp.tool()
    def uro_url_filtering(urls: str, whitelist: str = "", blacklist: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute uro for filtering out similar URLs.

        Args:
            urls: URLs to filter
            whitelist: Whitelist patterns
            blacklist: Blacklist patterns
            additional_args: Additional uro arguments

        Returns:
            Filtered URL results with duplicates removed
        """
        data = {
            "urls": urls,
            "whitelist": whitelist,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info("🔍 Starting uro URL filtering")
        result = hexstrike_client.safe_post("api/tools/uro", data)
        if result.get("success"):
            logger.info("✅ uro URL filtering completed")
        else:
            logger.error("❌ uro URL filtering failed")
        return result

    @mcp.tool()
    def burpsuite_scan(project_file: str = "", config_file: str = "", target: str = "", headless: bool = False, scan_type: str = "", scan_config: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Burp Suite with enhanced logging.

        Args:
            project_file: Burp project file path
            config_file: Burp configuration file path
            target: Target URL
            headless: Run in headless mode
            scan_type: Type of scan to perform
            scan_config: Scan configuration
            output_file: Output file path
            additional_args: Additional Burp Suite arguments

        Returns:
            Burp Suite scan results
        """
        data = {
            "project_file": project_file,
            "config_file": config_file,
            "target": target,
            "headless": headless,
            "scan_type": scan_type,
            "scan_config": scan_config,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Burp Suite scan")
        result = hexstrike_client.safe_post("api/tools/burpsuite", data)
        if result.get("success"):
            logger.info(f"✅ Burp Suite scan completed")
        else:
            logger.error(f"❌ Burp Suite scan failed")
        return result

    @mcp.tool()
    def zap_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format_type: str = "xml", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OWASP ZAP with enhanced logging.

        Args:
            target: Target URL
            scan_type: Type of scan (baseline, full, api)
            api_key: ZAP API key
            daemon: Run in daemon mode
            port: Port for ZAP daemon
            host: Host for ZAP daemon
            format_type: Output format (xml, json, html)
            output_file: Output file path
            additional_args: Additional ZAP arguments

        Returns:
            ZAP scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "api_key": api_key,
            "daemon": daemon,
            "port": port,
            "host": host,
            "format": format_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = hexstrike_client.safe_post("api/tools/zap", data)
        if result.get("success"):
            logger.info(f"✅ ZAP scan completed for {target}")
        else:
            logger.error(f"❌ ZAP scan failed for {target}")
        return result

    @mcp.tool()
    def arjun_scan(url: str, method: str = "GET", data: str = "", headers: str = "", timeout: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for parameter discovery with enhanced logging.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            data: POST data for testing
            headers: Custom headers
            timeout: Request timeout
            output_file: Output file path
            additional_args: Additional Arjun arguments

        Returns:
            Parameter discovery results
        """
        payload = {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Arjun parameter discovery: {url}")
        result = hexstrike_client.safe_post("api/tools/arjun", payload)
        if result.get("success"):
            logger.info(f"✅ Arjun completed for {url}")
        else:
            logger.error(f"❌ Arjun failed for {url}")
        return result

    @mcp.tool()
    def wafw00f_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wafw00f to identify and fingerprint WAF products with enhanced logging.

        Args:
            target: Target URL or IP
            additional_args: Additional wafw00f arguments

        Returns:
            WAF detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = hexstrike_client.safe_post("api/tools/wafw00f", data)
        if result.get("success"):
            logger.info(f"✅ Wafw00f completed for {target}")
        else:
            logger.error(f"❌ Wafw00f failed for {target}")
        return result

    @mcp.tool()
    def fierce_scan(domain: str, dns_server: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fierce for DNS reconnaissance with enhanced logging.

        Args:
            domain: Target domain
            dns_server: DNS server to use
            additional_args: Additional fierce arguments

        Returns:
            DNS reconnaissance results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = hexstrike_client.safe_post("api/tools/fierce", data)
        if result.get("success"):
            logger.info(f"✅ Fierce completed for {domain}")
        else:
            logger.error(f"❌ Fierce failed for {domain}")
        return result

    @mcp.tool()
    def dnsenum_scan(domain: str, dns_server: str = "", wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsenum for DNS enumeration with enhanced logging.

        Args:
            domain: Target domain
            dns_server: DNS server to use
            wordlist: Wordlist for brute forcing
            additional_args: Additional dnsenum arguments

        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = hexstrike_client.safe_post("api/tools/dnsenum", data)
        if result.get("success"):
            logger.info(f"✅ DNSenum completed for {domain}")
        else:
            logger.error(f"❌ DNSenum failed for {domain}")
        return result

    @mcp.tool()
    def autorecon_scan(
        target: str = "",
        target_file: str = "",
        ports: str = "",
        output_dir: str = "",
        max_scans: str = "",
        max_port_scans: str = "",
        heartbeat: str = "",
        timeout: str = "",
        target_timeout: str = "",
        config_file: str = "",
        global_file: str = "",
        plugins_dir: str = "",
        add_plugins_dir: str = "",
        tags: str = "",
        exclude_tags: str = "",
        port_scans: str = "",
        service_scans: str = "",
        reports: str = "",
        single_target: bool = False,
        only_scans_dir: bool = False,
        no_port_dirs: bool = False,
        nmap: str = "",
        nmap_append: str = "",
        proxychains: bool = False,
        disable_sanity_checks: bool = False,
        disable_keyboard_control: bool = False,
        force_services: str = "",
        accessible: bool = False,
        verbose: int = 0,
        curl_path: str = "",
        dirbuster_tool: str = "",
        dirbuster_wordlist: str = "",
        dirbuster_threads: str = "",
        dirbuster_ext: str = "",
        onesixtyone_community_strings: str = "",
        global_username_wordlist: str = "",
        global_password_wordlist: str = "",
        global_domain: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute AutoRecon for comprehensive target enumeration with full parameter support.

        Args:
            target: Single target to scan
            target_file: File containing multiple targets
            ports: Specific ports to scan
            output_dir: Output directory
            max_scans: Maximum number of concurrent scans
            max_port_scans: Maximum number of concurrent port scans
            heartbeat: Heartbeat interval
            timeout: Global timeout
            target_timeout: Per-target timeout
            config_file: Configuration file path
            global_file: Global configuration file
            plugins_dir: Plugins directory
            add_plugins_dir: Additional plugins directory
            tags: Plugin tags to include
            exclude_tags: Plugin tags to exclude
            port_scans: Port scan plugins to run
            service_scans: Service scan plugins to run
            reports: Report plugins to run
            single_target: Use single target directory structure
            only_scans_dir: Only create scans directory
            no_port_dirs: Don't create port directories
            nmap: Custom nmap command
            nmap_append: Arguments to append to nmap
            proxychains: Use proxychains
            disable_sanity_checks: Disable sanity checks
            disable_keyboard_control: Disable keyboard control
            force_services: Force service detection
            accessible: Enable accessible output
            verbose: Verbosity level (0-3)
            curl_path: Custom curl path
            dirbuster_tool: Directory busting tool
            dirbuster_wordlist: Directory busting wordlist
            dirbuster_threads: Directory busting threads
            dirbuster_ext: Directory busting extensions
            onesixtyone_community_strings: SNMP community strings
            global_username_wordlist: Global username wordlist
            global_password_wordlist: Global password wordlist
            global_domain: Global domain
            additional_args: Additional AutoRecon arguments

        Returns:
            Comprehensive enumeration results with full configurability
        """
        data = {
            "target": target,
            "target_file": target_file,
            "ports": ports,
            "output_dir": output_dir,
            "max_scans": max_scans,
            "max_port_scans": max_port_scans,
            "heartbeat": heartbeat,
            "timeout": timeout,
            "target_timeout": target_timeout,
            "config_file": config_file,
            "global_file": global_file,
            "plugins_dir": plugins_dir,
            "add_plugins_dir": add_plugins_dir,
            "tags": tags,
            "exclude_tags": exclude_tags,
            "port_scans": port_scans,
            "service_scans": service_scans,
            "reports": reports,
            "single_target": single_target,
            "only_scans_dir": only_scans_dir,
            "no_port_dirs": no_port_dirs,
            "nmap": nmap,
            "nmap_append": nmap_append,
            "proxychains": proxychains,
            "disable_sanity_checks": disable_sanity_checks,
            "disable_keyboard_control": disable_keyboard_control,
            "force_services": force_services,
            "accessible": accessible,
            "verbose": verbose,
            "curl_path": curl_path,
            "dirbuster_tool": dirbuster_tool,
            "dirbuster_wordlist": dirbuster_wordlist,
            "dirbuster_threads": dirbuster_threads,
            "dirbuster_ext": dirbuster_ext,
            "onesixtyone_community_strings": onesixtyone_community_strings,
            "global_username_wordlist": global_username_wordlist,
            "global_password_wordlist": global_password_wordlist,
            "global_domain": global_domain,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting AutoRecon comprehensive enumeration: {target}")
        result = hexstrike_client.safe_post("api/tools/autorecon", data)
        if result.get("success"):
            logger.info(f"✅ AutoRecon comprehensive enumeration completed for {target}")
        else:
            logger.error(f"❌ AutoRecon failed for {target}")
        return result

    @mcp.tool()
    def http_framework_test(url: str, method: str = "GET", data: dict = {},
                           headers: dict = {}, cookies: dict = {}, action: str = "request") -> Dict[str, Any]:
        """
        Enhanced HTTP testing framework (Burp Suite alternative) for comprehensive web security testing.

        Args:
            url: Target URL to test
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            data: Request data/parameters
            headers: Custom headers
            cookies: Custom cookies
            action: Action to perform (request, spider, proxy_history, set_rules, set_scope, repeater, intruder)

        Returns:
            HTTP testing results with vulnerability analysis
        """
        data_payload = {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "action": action
        }

        logger.info(f"{HexStrikeColors.FIRE_RED}🔥 Starting HTTP Framework {action}: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/http-framework", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ HTTP Framework {action} completed for {url}{HexStrikeColors.RESET}")

            # Enhanced logging for vulnerabilities found
            if result.get("result", {}).get("vulnerabilities"):
                vuln_count = len(result["result"]["vulnerabilities"])
                logger.info(f"{HexStrikeColors.HIGHLIGHT_RED} Found {vuln_count} potential vulnerabilities {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ HTTP Framework {action} failed for {url}{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def browser_agent_inspect(url: str, headless: bool = True, wait_time: int = 5,
                             action: str = "navigate", proxy_port: Optional[int] = None, active_tests: bool = False) -> Dict[str, Any]:
        """
        AI-powered browser agent for comprehensive web application inspection and security analysis.

        Args:
            url: Target URL to inspect
            headless: Run browser in headless mode
            wait_time: Time to wait after page load
            action: Action to perform (navigate, screenshot, close, status)
            proxy_port: Optional proxy port for request interception
            active_tests: Run lightweight active reflected XSS tests (safe GET-only)

        Returns:
            Browser inspection results with security analysis
        """
        data_payload = {
            "url": url,
            "headless": headless,
            "wait_time": wait_time,
            "action": action,
            "proxy_port": proxy_port,
            "active_tests": active_tests
        }

        logger.info(f"{HexStrikeColors.CRIMSON}🌐 Starting Browser Agent {action}: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/browser-agent", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Browser Agent {action} completed for {url}{HexStrikeColors.RESET}")

            # Enhanced logging for security analysis
            if action == "navigate" and result.get("result", {}).get("security_analysis"):
                security_analysis = result["result"]["security_analysis"]
                issues_count = security_analysis.get("total_issues", 0)
                security_score = security_analysis.get("security_score", 0)

                if issues_count > 0:
                    logger.warning(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Security Issues: {issues_count} | Score: {security_score}/100 {HexStrikeColors.RESET}")
                else:
                    logger.info(f"{HexStrikeColors.HIGHLIGHT_GREEN} No security issues found | Score: {security_score}/100 {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Browser Agent {action} failed for {url}{HexStrikeColors.RESET}")

        return result

    # ---------------- Additional HTTP Framework Tools (sync with server) ----------------
    @mcp.tool()
    def http_set_rules(rules: list) -> Dict[str, Any]:
        """Set match/replace rules used to rewrite parts of URL/query/headers/body before sending.
        Rule format: {'where':'url|query|headers|body','pattern':'regex','replacement':'string'}"""
        payload = {"action": "set_rules", "rules": rules}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
        """Define in-scope host (and optionally subdomains) so out-of-scope requests are skipped."""
        payload = {"action": "set_scope", "host": host, "include_subdomains": include_subdomains}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_repeater(request_spec: dict) -> Dict[str, Any]:
        """Send a crafted request (Burp Repeater equivalent). request_spec keys: url, method, headers, cookies, data."""
        payload = {"action": "repeater", "request": request_spec}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_intruder(url: str, method: str = "GET", location: str = "query", params: Optional[list] = None,
                      payloads: Optional[list] = None, base_data: Optional[dict] = None, max_requests: int = 100) -> Dict[str, Any]:
        """Simple Intruder (sniper) fuzzing. Iterates payloads over each param individually.
        location: query|body|headers|cookie."""
        payload = {
            "action": "intruder",
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads": payloads or [],
            "base_data": base_data or {},
            "max_requests": max_requests
        }
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive",
                                  headless: bool = True, max_depth: int = 3,
                                  max_pages: int = 50) -> Dict[str, Any]:
        """
        Comprehensive Burp Suite alternative combining HTTP framework and browser agent for complete web security testing.

        Args:
            target: Target URL or domain to scan
            scan_type: Type of scan (comprehensive, spider, passive, active)
            headless: Run browser in headless mode
            max_depth: Maximum crawling depth
            max_pages: Maximum pages to analyze

        Returns:
            Comprehensive security assessment results
        """
        data_payload = {
            "target": target,
            "scan_type": scan_type,
            "headless": headless,
            "max_depth": max_depth,
            "max_pages": max_pages
        }

        logger.info(f"{HexStrikeColors.BLOOD_RED}🔥 Starting Burp Suite Alternative {scan_type} scan: {target}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/burpsuite-alternative", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Burp Suite Alternative scan completed for {target}{HexStrikeColors.RESET}")

            # Enhanced logging for comprehensive results
            if result.get("result", {}).get("summary"):
                summary = result["result"]["summary"]
                total_vulns = summary.get("total_vulnerabilities", 0)
                pages_analyzed = summary.get("pages_analyzed", 0)
                security_score = summary.get("security_score", 0)

                logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} SCAN SUMMARY {HexStrikeColors.RESET}")
                logger.info(f"  📊 Pages Analyzed: {pages_analyzed}")
                logger.info(f"  🚨 Vulnerabilities: {total_vulns}")
                logger.info(f"  🛡️  Security Score: {security_score}/100")

                # Log vulnerability breakdown
                vuln_breakdown = summary.get("vulnerability_breakdown", {})
                for severity, count in vuln_breakdown.items():
                    if count > 0:
                        color = {
                                    'critical': HexStrikeColors.CRITICAL,
        'high': HexStrikeColors.FIRE_RED,
        'medium': HexStrikeColors.CYBER_ORANGE,
        'low': HexStrikeColors.YELLOW,
        'info': HexStrikeColors.INFO
    }.get(severity.lower(), HexStrikeColors.WHITE)

                        logger.info(f"  {color}{severity.upper()}: {count}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Burp Suite Alternative scan failed for {target}{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def error_handling_statistics() -> Dict[str, Any]:
        """
        Get intelligent error handling system statistics and recent error patterns.

        Returns:
            Error handling statistics and patterns
        """
        logger.info(f"{HexStrikeColors.ELECTRIC_PURPLE}📊 Retrieving error handling statistics{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_get("api/error-handling/statistics")

        if result.get("success"):
            stats = result.get("statistics", {})
            total_errors = stats.get("total_errors", 0)
            recent_errors = stats.get("recent_errors_count", 0)

            logger.info(f"{HexStrikeColors.SUCCESS}✅ Error statistics retrieved{HexStrikeColors.RESET}")
            logger.info(f"  📈 Total Errors: {total_errors}")
            logger.info(f"  🕒 Recent Errors: {recent_errors}")

            # Log error breakdown by type
            error_counts = stats.get("error_counts_by_type", {})
            if error_counts:
                logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} ERROR BREAKDOWN {HexStrikeColors.RESET}")
                for error_type, count in error_counts.items():
                                          logger.info(f"  {HexStrikeColors.FIRE_RED}{error_type}: {count}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Failed to retrieve error statistics{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def test_error_recovery(tool_name: str, error_type: str = "timeout",
                           target: str = "example.com") -> Dict[str, Any]:
        """
        Test the intelligent error recovery system with simulated failures.

        Args:
            tool_name: Name of tool to simulate error for
            error_type: Type of error to simulate (timeout, permission_denied, network_unreachable, etc.)
            target: Target for the simulated test

        Returns:
            Recovery strategy and system response
        """
        data_payload = {
            "tool_name": tool_name,
            "error_type": error_type,
            "target": target
        }

        logger.info(f"{HexStrikeColors.RUBY}🧪 Testing error recovery for {tool_name} with {error_type}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/error-handling/test-recovery", data_payload)

        if result.get("success"):
            recovery_strategy = result.get("recovery_strategy", {})
            action = recovery_strategy.get("action", "unknown")
            success_prob = recovery_strategy.get("success_probability", 0)

            logger.info(f"{HexStrikeColors.SUCCESS}✅ Error recovery test completed{HexStrikeColors.RESET}")
            logger.info(f"  🔧 Recovery Action: {action}")
            logger.info(f"  📊 Success Probability: {success_prob:.2%}")

            # Log alternative tools if available
            alternatives = result.get("alternative_tools", [])
            if alternatives:
                logger.info(f"  🔄 Alternative Tools: {', '.join(alternatives)}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Error recovery test failed{HexStrikeColors.RESET}")

        return result
