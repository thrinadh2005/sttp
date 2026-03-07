import socket
from datetime import datetime
from typing import Dict, List, Optional


class DNSTools:
    def __init__(self):
        self.query: Optional[str] = None
        self.addresses: List[str] = []
        self.hostname: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def resolve_host(self, hostname: str) -> List[str]:
        self.query = hostname
        self.addresses = []
        self.start_time = datetime.now()
        try:
            infos = socket.getaddrinfo(hostname, None)
            for info in infos:
                addr = info[4][0]
                if addr not in self.addresses:
                    self.addresses.append(addr)
        finally:
            self.end_time = datetime.now()
        return self.addresses

    def reverse_lookup(self, ip: str) -> Optional[str]:
        self.query = ip
        self.hostname = None
        self.start_time = datetime.now()
        try:
            self.hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            self.hostname = None
        finally:
            self.end_time = datetime.now()
        return self.hostname

    def get_results(self) -> Dict:
        return {
            "query": self.query,
            "addresses": self.addresses,
            "hostname": self.hostname,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
        }
