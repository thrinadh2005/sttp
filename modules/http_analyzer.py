from urllib.request import Request, urlopen
from urllib.parse import urlparse
from typing import Dict, Optional
from datetime import datetime


class HTTPAnalyzer:
    def __init__(self, url: str):
        self.url = url
        self.headers: Dict[str, str] = {}
        self.analysis: Dict[str, Optional[str]] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def fetch_headers(self) -> Dict[str, str]:
        self.start_time = datetime.now()
        self.headers = {}
        try:
            req = Request(self.url, method="HEAD")
            with urlopen(req, timeout=10) as resp:
                for k, v in resp.headers.items():
                    self.headers[k] = v
        except Exception:
            try:
                req = Request(self.url, method="GET")
                with urlopen(req, timeout=10) as resp:
                    for k, v in resp.headers.items():
                        self.headers[k] = v
            except Exception:
                self.headers = {}
        finally:
            self.end_time = datetime.now()
        return self.headers

    def analyze(self) -> Dict[str, Optional[str]]:
        if not self.headers:
            self.fetch_headers()
        parsed = urlparse(self.url)
        server = self.headers.get("Server")
        content_type = self.headers.get("Content-Type")
        security = {
            "strict_transport_security": "present" if any(h.lower() == "strict-transport-security" for h in self.headers.keys()) else "missing",
            "x_content_type_options": "present" if any(h.lower() == "x-content-type-options" for h in self.headers.keys()) else "missing",
            "x_frame_options": "present" if any(h.lower() == "x-frame-options" for h in self.headers.keys()) else "missing",
            "content_security_policy": "present" if any(h.lower() == "content-security-policy" for h in self.headers.keys()) else "missing",
            "referrer_policy": "present" if any(h.lower() == "referrer-policy" for h in self.headers.keys()) else "missing",
        }
        self.analysis = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "server": server,
            "content_type": content_type,
            "security_headers": security,
        }
        return self.analysis

    def get_results(self) -> Dict:
        return {
            "url": self.url,
            "headers": self.headers,
            "analysis": self.analysis,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
        }
