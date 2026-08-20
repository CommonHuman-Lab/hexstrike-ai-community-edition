import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from commonhuman_core.crawler import crawl
from commonhuman_core.http.client import HttpClient
from commonhuman_core.auth import form_login, bearer_login, http_auth
from backend.server_core import ModernVisualEngine

logger = logging.getLogger(__name__)


class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""

    def __init__(self):
        self._client = HttpClient(timeout=30, headers={
            'User-Agent': 'Security-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.session = self._client._session
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []  # [{'where':'query|headers|body|url','pattern':'regex','replacement':'str'}]
        self.scope = None  # {'host': 'example.invalid', 'include_subdomains': True}
        self._req_id = 0

    def setup_proxy(self, proxy_port: int = 8080):
        """Setup HTTP proxy for request interception"""
        self.session.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }

    def authenticate(self, auth_type: str, **kwargs) -> Dict[str, Any]:
        """Authenticate the shared session via form login, OAuth2 client-credentials, or HTTP auth."""
        try:
            auth_type = (auth_type or '').lower()

            if auth_type == 'form':
                result = form_login(
                    login_url=kwargs['login_url'],
                    username=kwargs['username'],
                    password=kwargs['password'],
                    username_field=kwargs.get('username_field') or 'username',
                    password_field=kwargs.get('password_field') or 'password',
                    extra_fields=kwargs.get('extra_fields') or None,
                    client=self._client,
                )
            elif auth_type == 'bearer':
                result = bearer_login(
                    token_url=kwargs['token_url'],
                    client_id=kwargs['client_id'],
                    client_secret=kwargs['client_secret'],
                    grant_type=kwargs.get('grant_type') or 'client_credentials',
                    client=self._client,
                )
            elif auth_type in ('basic', 'digest', 'ntlm'):
                self.session.auth = http_auth(auth_type, kwargs['auth_cred'])
                return {'success': True, 'auth_type': auth_type}
            else:
                return {'success': False, 'error': f'Unknown auth_type: {auth_type}'}

            if result.headers:
                self.session.headers.update(result.headers)

            return {
                'success': not result.is_empty(),
                'auth_type': auth_type,
                'cookies_set': bool(result.cookies),
                'authorization_header_set': 'Authorization' in result.headers,
            }
        except KeyError as e:
            return {'success': False, 'error': f'Missing required parameter: {e}'}
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'Auth', str(e))}")
            return {'success': False, 'error': str(e)}

    def intercept_request(self, url: str, method: str = 'GET', data: Any = None,
                         headers: Optional[Dict[str, Any]] = None, cookies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Intercept and analyze HTTP requests"""
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            # Apply match/replace rules prior to sending
            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self._client.get(url, params=data, headers=send_headers)
            elif method.upper() == 'POST':
                response = self._client.post(url, data=data, headers=send_headers)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            # Store request/response in history
            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }

            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],  # Limit content size
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }

            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })

            # Analyze for vulnerabilities
            self._analyze_response_for_vulns(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    # ----------------- Match & Replace and Scope -----------------
    def set_match_replace_rules(self, rules: list):
        """Set match/replace rules. Each rule: {'where','pattern','replacement'}"""
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            h = urlparse(url).hostname or ''
            target = self.scope.get('host', '')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.' + target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        from urllib.parse import parse_qsl, urlencode, urlunparse
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        # Ensure scope restriction
        if not self._in_scope(url):
            logger.warning(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SKIPPED', f'Out of scope: {url}')}")
            return original_url, data, headers
        return url, out_data, out_headers

    # ----------------- Repeater (custom send) -----------------
    def send_custom_request(self, request_spec: dict) -> dict:
        """Send a custom request with explicit fields, applying rules."""
        url = request_spec.get('url', '')
        method = request_spec.get('method', 'GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)

    # ----------------- Intruder (Sniper mode) -----------------
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                        params: Optional[list] = None, payloads: Optional[list] = None, base_data: Optional[dict] = None,
                        max_requests: int = 100) -> dict:
        """Simple fuzzing: iterate payloads over each parameter individually (Sniper)."""
        from urllib.parse import parse_qsl, urlencode, urlunparse
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response', {}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response', {}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self.session.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size', 0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {
            'success': True,
            'tested': total,
            'interesting': interesting[:50]
        }

    def _analyze_response_for_vulns(self, url: str, response):
        """Analyze HTTP response for common vulnerabilities"""
        self._check_security_headers(url, response.headers)
        self._analyze_body_for_vulns(url, response.text)

    def _check_security_headers(self, url: str, headers) -> None:
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }

        vulns = []
        for header, description in security_headers.items():
            if header not in headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })
        self.vulnerabilities.extend(vulns)

    def _analyze_body_for_vulns(self, url: str, text: str) -> None:
        vulns = []

        # Check for sensitive information disclosure
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]  # Limit matches
                })

        # Check for SQL injection indicators
        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]

        for error in sql_errors:
            if error.lower() in text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self, limit: int = 10):
        """Get recent vulnerabilities found"""
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []

    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        """Spider website to discover endpoints and forms via commonhuman_core.crawler"""
        try:
            result = crawl(base_url, injector=self._client, max_pages=max_pages, max_depth=max_depth)

            forms = [
                {
                    'action': form.action,
                    'method': form.method,
                    'inputs': [{'name': name, 'value': value} for name, value in form.params.items()],
                    'base_data': form.base_data,
                }
                for form in result.form_targets
            ]

            for url, html in result.page_sources.items():
                try:
                    head_resp = self.session.head(url, timeout=10, allow_redirects=True)
                    self._check_security_headers(url, head_resp.headers)
                except Exception:
                    pass
                self._analyze_body_for_vulns(url, html)

            return {
                'success': True,
                'discovered_urls': result.visited_urls,
                'forms': forms,
                'total_pages': len(result.visited_urls),
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'Spider', str(e))}")
            return {'success': False, 'error': str(e)}


# Global instance
http_framework = HTTPTestingFramework()
