# mcp_tools/bug_bounty_recon.py

from typing import Dict, Any

def register_bug_bounty_recon_tools(mcp, hexstrike_client, logger):
    @mcp.tool()
    def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hakrawler for web endpoint discovery with enhanced logging.

        Note: Uses standard Kali Linux hakrawler (hakluke/hakrawler) with parameter mapping:
        - url: Piped via echo to stdin (not -url flag)
        - depth: Mapped to -d flag (not -depth)
        - forms: Mapped to -s flag for showing sources
        - robots/sitemap/wayback: Mapped to -subs for subdomain inclusion
        - Always includes -u for unique URLs

        Args:
            url: Target URL to crawl
            depth: Crawling depth (mapped to -d)
            forms: Include forms in crawling (mapped to -s)
            robots: Check robots.txt (mapped to -subs)
            sitemap: Check sitemap.xml (mapped to -subs)
            wayback: Use Wayback Machine (mapped to -subs)
            additional_args: Additional Hakrawler arguments

        Returns:
            Web endpoint discovery results
        """
        data = {
            "url": url,
            "depth": depth,
            "forms": forms,
            "robots": robots,
            "sitemap": sitemap,
            "wayback": wayback,
            "additional_args": additional_args
        }
        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = hexstrike_client.safe_post("api/tools/hakrawler", data)
        if result.get("success"):
            logger.info(f"✅ Hakrawler crawling completed")
        else:
            logger.error(f"❌ Hakrawler crawling failed")
        return result

    @mcp.tool()
    def paramspider_discovery(domain: str, exclude: str = "", output_file: str = "", level: int = 2, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter discovery with enhanced logging.

        Args:
            domain: Target domain
            exclude: Extensions to exclude
            output_file: Output file path
            level: Crawling level
            additional_args: Additional ParamSpider arguments

        Returns:
            Parameter discovery results
        """
        data = {
            "domain": domain,
            "exclude": exclude,
            "output_file": output_file,
            "level": level,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ParamSpider discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/paramspider", data)
        if result.get("success"):
            logger.info(f"✅ ParamSpider discovery completed")
        else:
            logger.error(f"❌ ParamSpider discovery failed")
        return result
