"""
Port Scanner Module
Educational tool for learning network scanning techniques
"""

import socket
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import threading


class PortScanner:
    """
    Port Scanner Module for educational purposes.
    Demonstrates TCP and UDP scanning techniques.
    """
    
    # Common port services
    COMMON_PORTS = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt"
    }
    
    def __init__(self, target: str, timeout: float = 1.0):
        """
        Initialize the port scanner.
        
        Args:
            target: Target IP address or hostname
            timeout: Socket timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.open_ports: List[Dict] = []
        self.closed_ports: List[int] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        self.last_protocol: Optional[str] = None
        
    def resolve_hostname(self) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return self.target
    
    def scan_tcp_port(self, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single TCP port.
        
        Args:
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open, service_name)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            is_open = (result == 0)
            service = self.COMMON_PORTS.get(port, "Unknown")
            
            return (port, is_open, service)
        except socket.error:
            return (port, False, self.COMMON_PORTS.get(port, "Unknown"))
    
    def scan_udp_port(self, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single UDP port.
        
        Args:
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open, service_name)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(b'\x00', (self.target, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return (port, True, self.COMMON_PORTS.get(port, "Unknown"))
        except socket.timeout:
            # UDP timeout doesn't necessarily mean port is closed
            return (port, False, self.COMMON_PORTS.get(port, "Unknown"))
        except socket.error:
            return (port, False, self.COMMON_PORTS.get(port, "Unknown"))
    
    def scan_common_ports(self, protocol: str = "TCP") -> List[Dict]:
        """
        Scan only common ports (fast scan).
        
        Args:
            protocol: "TCP" or "UDP"
            
        Returns:
            List of open port dictionaries
        """
        self.scan_start_time = datetime.now()
        self.open_ports = []
        self.last_protocol = protocol
        
        ports_to_scan = list(self.COMMON_PORTS.keys())
        
        print(f"\n{'='*60}")
        print(f"🔍 Scanning {self.target} ({protocol}) - Common Ports")
        print(f"{'='*60}")
        print(f"Start time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scanning {len(ports_to_scan)} ports...\n")
        
        for i, port in enumerate(ports_to_scan):
            if protocol == "TCP":
                port, is_open, service = self.scan_tcp_port(port)
            else:
                port, is_open, service = self.scan_udp_port(port)
            
            if is_open:
                self.open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'OPEN',
                    'protocol': protocol
                })
                print(f"  ✓ [+] Port {port:5d} OPEN  - {service}")
            
            # Progress indicator
            if (i + 1) % 5 == 0:
                print(f"  Progress: {i+1}/{len(ports_to_scan)} ports scanned...")
        
        self.scan_end_time = datetime.now()
        self._print_scan_summary()
        
        return self.open_ports
    
    def scan_port_range(self, start_port: int, end_port: int, 
                        protocol: str = "TCP", 
                        threads: int = 1) -> List[Dict]:
        """
        Scan a range of ports (deep scan).
        
        Args:
            start_port: Starting port number
            end_port: Ending port number
            protocol: "TCP" or "UDP"
            threads: Number of threads for parallel scanning
            
        Returns:
            List of open port dictionaries
        """
        self.scan_start_time = datetime.now()
        self.open_ports = []
        self.last_protocol = protocol
        
        ports_to_scan = range(start_port, end_port + 1)
        
        print(f"\n{'='*60}")
        print(f"🔍 Scanning {self.target} ({protocol}) - Port Range")
        print(f"{'='*60}")
        print(f"Start time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scanning ports {start_port} to {end_port} ({len(ports_to_scan)} ports)...")
        print(f"Using {threads} thread(s)...\n")
        
        if threads > 1:
            # Multi-threaded scanning
            self._scan_with_threads(ports_to_scan, protocol, threads)
        else:
            # Single-threaded scanning
            for i, port in enumerate(ports_to_scan):
                if protocol == "TCP":
                    port_num, is_open, service = self.scan_tcp_port(port)
                else:
                    port_num, is_open, service = self.scan_udp_port(port)
                
                if is_open:
                    self.open_ports.append({
                        'port': port_num,
                        'service': service,
                        'status': 'OPEN',
                        'protocol': protocol
                    })
                    print(f"  ✓ [+] Port {port_num:5d} OPEN  - {service}")
                
                # Progress indicator
                if (i + 1) % 100 == 0:
                    print(f"  Progress: {i+1}/{len(ports_to_scan)} ports scanned...")
        
        self.scan_end_time = datetime.now()
        self._print_scan_summary()
        
        return self.open_ports
    
    def _scan_with_threads(self, ports: range, protocol: str, num_threads: int):
        """Scan ports using multiple threads."""
        def scan_chunk(port_chunk):
            for port in port_chunk:
                if protocol == "TCP":
                    port_num, is_open, service = self.scan_tcp_port(port)
                else:
                    port_num, is_open, service = self.scan_udp_port(port)
                
                if is_open:
                    self.open_ports.append({
                        'port': port_num,
                        'service': service,
                        'status': 'OPEN',
                        'protocol': protocol
                    })
                    print(f"  ✓ [+] Port {port_num:5d} OPEN  - {service}")
        
        # Split ports into chunks for threads
        port_list = list(ports)
        chunk_size = len(port_list) // num_threads
        chunks = [port_list[i:i+chunk_size] for i in range(0, len(port_list), chunk_size)]
        
        threads = []
        for chunk in chunks:
            t = threading.Thread(target=scan_chunk, args=(chunk,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
    
    def _print_scan_summary(self):
        """Print scan summary."""
        duration = self.scan_end_time - self.scan_start_time
        
        print(f"\n{'='*60}")
        print(f"📊 SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target:         {self.target}")
        print(f"Open Ports:     {len(self.open_ports)}")
        print(f"Duration:       {duration.total_seconds():.2f} seconds")
        print(f"End time:       {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
    
    def get_results(self) -> Dict:
        """
        Get scan results as a dictionary.
        
        Returns:
            Dictionary containing scan results
        """
        return {
            'target': self.target,
            'scan_type': self.last_protocol,
            'open_ports': self.open_ports,
            'scan_start': self.scan_start_time.isoformat() if self.scan_start_time else None,
            'scan_end': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'duration_seconds': (
                (self.scan_end_time - self.scan_start_time).total_seconds()
                if self.scan_start_time and self.scan_end_time else None
            )
        }
    
    @staticmethod
    def get_security_tips() -> List[str]:
        """
        Get security tips related to port scanning.
        
        Returns:
            List of security tips
        """
        return [
            "🔒 Close unnecessary ports to reduce attack surface",
            "🛡️ Use a firewall to filter incoming connections",
            "📡 Enable port knocking for additional security",
            "🔐 Use strong authentication for exposed services",
            "📊 Regularly audit open ports on your systems",
            "🚫 Disable unused services completely",
            "🔑 Use VPN for accessing remote services"
        ]
