from typing import Optional, Dict, List


class TechnologyDetector:
    """Advanced technology detection system for context-aware parameter selection"""

    def __init__(self):
        self.detection_patterns = {
            "web_servers": {
                "apache": ["Apache", "apache", "httpd"],
                "nginx": ["nginx", "Nginx"],
                "iis": ["Microsoft-IIS", "IIS"],
                "tomcat": ["Tomcat", "Apache-Coyote"],
                "jetty": ["Jetty"],
                "lighttpd": ["lighttpd"]
            },
            "frameworks": {
                "django": ["Django", "django", "csrftoken"],
                "flask": ["Flask", "Werkzeug"],
                "express": ["Express", "X-Powered-By: Express"],
                "laravel": ["Laravel", "laravel_session"],
                "symfony": ["Symfony", "symfony"],
                "rails": ["Ruby on Rails", "rails", "_session_id"],
                "spring": ["Spring", "JSESSIONID"],
                "struts": ["Struts", "struts"]
            },
            "cms": {
                "wordpress": ["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
                "drupal": ["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
                "joomla": ["Joomla", "joomla", "/administrator/", "com_content"],
                "magento": ["Magento", "magento", "Mage.Cookies"],
                "prestashop": ["PrestaShop", "prestashop"],
                "opencart": ["OpenCart", "opencart"]
            },
            "databases": {
                "mysql": ["MySQL", "mysql", "phpMyAdmin"],
                "postgresql": ["PostgreSQL", "postgres"],
                "mssql": ["Microsoft SQL Server", "MSSQL"],
                "oracle": ["Oracle", "oracle"],
                "mongodb": ["MongoDB", "mongo"],
                "redis": ["Redis", "redis"]
            },
            "languages": {
                "php": ["PHP", "php", ".php", "X-Powered-By: PHP"],
                "python": ["Python", "python", ".py"],
                "java": ["Java", "java", ".jsp", ".do"],
                "dotnet": ["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"],
                "nodejs": ["Node.js", "node", ".js"],
                "ruby": ["Ruby", "ruby", ".rb"],
                "go": ["Go", "golang"],
                "rust": ["Rust", "rust"]
            },
            "security": {
                "waf": ["cloudflare", "CloudFlare", "X-CF-Ray", "incapsula", "Incapsula", "sucuri", "Sucuri"],
                "load_balancer": ["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
                "cdn": ["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"]
            }
        }

        self.port_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            11211: "memcached"
        }

    def detect_technologies(self, target: str, headers: Optional[Dict[str, str]] = None, content: str = "", ports: Optional[List[int]] = None) -> Dict[str, List[str]]:
        """Comprehensive technology detection"""
        detected = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "databases": [],
            "languages": [],
            "security": [],
            "services": []
        }

        # Header-based detection
        if headers:
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for header_name, header_value in headers.items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower() or pattern.lower() in header_name.lower():
                                if tech not in detected[category]:
                                    detected[category].append(tech)

        # Content-based detection
        if content:
            content_lower = content.lower()
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in content_lower:
                            if tech not in detected[category]:
                                detected[category].append(tech)

        # Port-based service detection
        if ports:
            for port in ports:
                if port in self.port_services:
                    service = self.port_services[port]
                    if service not in detected["services"]:
                        detected["services"].append(service)

        return detected
