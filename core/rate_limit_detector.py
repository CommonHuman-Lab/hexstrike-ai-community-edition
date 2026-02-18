from typing import Dict, Any, Optional
import re

class RateLimitDetector:
    """Intelligent rate limiting detection and automatic timing adjustment"""

    def __init__(self):
        self.rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "429",
            "throttle",
            "slow down",
            "retry after",
            "quota exceeded",
            "api limit",
            "request limit"
        ]

        self.timing_profiles = {
            "aggressive": {"delay": 0.1, "threads": 50, "timeout": 5},
            "normal": {"delay": 0.5, "threads": 20, "timeout": 10},
            "conservative": {"delay": 1.0, "threads": 10, "timeout": 15},
            "stealth": {"delay": 2.0, "threads": 5, "timeout": 30}
        }

    def detect_rate_limiting(self, response_text: str, status_code: int, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Detect rate limiting from response"""
        rate_limit_detected = False
        confidence = 0.0
        indicators_found = []

        # Status code check
        if status_code == 429:
            rate_limit_detected = True
            confidence += 0.8
            indicators_found.append("HTTP 429 status")

        # Response text check
        response_lower = response_text.lower()
        for indicator in self.rate_limit_indicators:
            if indicator in response_lower:
                rate_limit_detected = True
                confidence += 0.2
                indicators_found.append(f"Text: '{indicator}'")

        # Header check
        if headers:
            rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"]
            for header_name in headers.keys():
                for rl_header in rate_limit_headers:
                    if rl_header.lower() in header_name.lower():
                        rate_limit_detected = True
                        confidence += 0.3
                        indicators_found.append(f"Header: {header_name}")

        confidence = min(1.0, confidence)

        return {
            "detected": rate_limit_detected,
            "confidence": confidence,
            "indicators": indicators_found,
            "recommended_profile": self._recommend_timing_profile(confidence)
        }

    def _recommend_timing_profile(self, confidence: float) -> str:
        """Recommend timing profile based on rate limit confidence"""
        if confidence >= 0.8:
            return "stealth"
        elif confidence >= 0.5:
            return "conservative"
        elif confidence >= 0.2:
            return "normal"
        else:
            return "aggressive"

    def adjust_timing(self, current_params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Adjust timing parameters based on profile"""
        timing = self.timing_profiles.get(profile, self.timing_profiles["normal"])

        adjusted_params = current_params.copy()

        # Adjust common parameters
        if "threads" in adjusted_params:
            adjusted_params["threads"] = timing["threads"]
        if "delay" in adjusted_params:
            adjusted_params["delay"] = timing["delay"]
        if "timeout" in adjusted_params:
            adjusted_params["timeout"] = timing["timeout"]

        # Tool-specific adjustments
        if "additional_args" in adjusted_params:
            args = adjusted_params["additional_args"]

            # Remove existing timing arguments
            args = re.sub(r'-t\s+\d+', '', args)
            args = re.sub(r'--threads\s+\d+', '', args)
            args = re.sub(r'--delay\s+[\d.]+', '', args)

            # Add new timing arguments
            args += f" -t {timing['threads']}"
            if timing["delay"] > 0:
                args += f" --delay {timing['delay']}"

            adjusted_params["additional_args"] = args.strip()

        return adjusted_params
