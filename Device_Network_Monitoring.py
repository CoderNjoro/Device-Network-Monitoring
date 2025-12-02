import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
from datetime import datetime
from collections import defaultdict
import platform
import psutil
import socket

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class NetworkTrafficMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Traffic Monitor - Process & GeoIP Analysis")
        self.root.geometry("1900x1100")
        self.monitoring = False
        self.packet_count = 0
        self.traffic_data = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'ports': set()})
        self.process_connections = defaultdict(lambda: {
            'name': '',
            'pid': 0,
            'bytes': 0,
            'packets': 0,
            'destinations': defaultdict(int),
            'ports': set(),
            'geoip_info': {}
        })
        
        self.suspicious_ips = {}
        self.blocked_ips = set()
        self.suspicious_processes = {}
        self.ip_geolocation_cache = {}
        self.suspicious_ports = {31, 135, 139, 445, 1433, 3389, 5900, 8888, 9999}
        
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy not installed.\nInstall with: pip install scapy psutil requests")
            return
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create the user interface"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Monitor Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(control_frame, text="Status: Idle", foreground="gray", font=("Arial", 11, "bold"))
        self.status_label.pack(anchor=tk.W, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Data", command=self.clear_data)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats Frame
        stats_frame = ttk.LabelFrame(control_frame, text="Live Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=10)
        
        stats_inner = ttk.Frame(stats_frame)
        stats_inner.pack(fill=tk.X)
        
        self.packet_label = ttk.Label(stats_inner, text="Packets: 0", font=("Arial", 10, "bold"))
        self.packet_label.pack(side=tk.LEFT, padx=20)
        
        self.traffic_label = ttk.Label(stats_inner, text="Traffic: 0 KB", font=("Arial", 10, "bold"))
        self.traffic_label.pack(side=tk.LEFT, padx=20)
        
        self.process_label = ttk.Label(stats_inner, text="Processes: 0", font=("Arial", 10, "bold"))
        self.process_label.pack(side=tk.LEFT, padx=20)
        
        self.threat_label = ttk.Label(stats_inner, text="Threats: 0", font=("Arial", 10, "bold"), foreground="red")
        self.threat_label.pack(side=tk.LEFT, padx=20)
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Process Activity Tab
        process_frame = ttk.Frame(notebook)
        notebook.add(process_frame, text="Process Activity")
        
        ttk.Label(process_frame, text="Active Processes & Network Connections:").pack(anchor=tk.W, pady=5)
        
        self.process_tree = ttk.Treeview(
            process_frame,
            columns=('Process', 'PID', 'Packets', 'Bytes', 'Remote IP', 'Country', 'Port', 'Destinations', 'Risk'),
            show='headings',
            height=20
        )
        
        self.process_tree.heading('Process', text='Process Name')
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Packets', text='Packets')
        self.process_tree.heading('Bytes', text='Bytes (KB)')
        self.process_tree.heading('Remote IP', text='Remote IP')
        self.process_tree.heading('Country', text='Country')
        self.process_tree.heading('Port', text='Port')
        self.process_tree.heading('Destinations', text='Destinations')
        self.process_tree.heading('Risk', text='Risk')
        
        self.process_tree.column('Process', width=130)
        self.process_tree.column('PID', width=60)
        self.process_tree.column('Packets', width=70)
        self.process_tree.column('Bytes', width=90)
        self.process_tree.column('Remote IP', width=130)
        self.process_tree.column('Country', width=100)
        self.process_tree.column('Port', width=70)
        self.process_tree.column('Destinations', width=100)
        self.process_tree.column('Risk', width=90)
        
        process_scroll = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scroll.set)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        process_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Live Packets Tab
        packets_frame = ttk.Frame(notebook)
        notebook.add(packets_frame, text="Live Packets")
        
        ttk.Label(packets_frame, text="Real-time Network Packets:").pack(anchor=tk.W, pady=5)
        
        self.packets_tree = ttk.Treeview(
            packets_frame,
            columns=('Time', 'Process', 'Source', 'Dest', 'Protocol', 'Port', 'Size'),
            show='headings',
            height=20
        )
        
        self.packets_tree.heading('Time', text='Timestamp')
        self.packets_tree.heading('Process', text='Process')
        self.packets_tree.heading('Source', text='Source IP')
        self.packets_tree.heading('Dest', text='Dest IP')
        self.packets_tree.heading('Protocol', text='Protocol')
        self.packets_tree.heading('Port', text='Port')
        self.packets_tree.heading('Size', text='Size (bytes)')
        
        self.packets_tree.column('Time', width=90)
        self.packets_tree.column('Process', width=120)
        self.packets_tree.column('Source', width=110)
        self.packets_tree.column('Dest', width=110)
        self.packets_tree.column('Protocol', width=80)
        self.packets_tree.column('Port', width=70)
        self.packets_tree.column('Size', width=90)
        
        packets_scroll = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.packets_tree.yview)
        self.packets_tree.configure(yscrollcommand=packets_scroll.set)
        self.packets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packets_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # GeoIP Intelligence Tab
        geo_frame = ttk.Frame(notebook)
        notebook.add(geo_frame, text="GeoIP Intelligence")
        
        ttk.Label(geo_frame, text="Geographical Source Analysis:").pack(anchor=tk.W, pady=5)
        
        self.geo_tree = ttk.Treeview(
            geo_frame,
            columns=('IP', 'Country', 'City', 'ISP', 'Connections', 'Data_MB', 'Process', 'Threat'),
            show='headings',
            height=20
        )
        
        self.geo_tree.heading('IP', text='IP Address')
        self.geo_tree.heading('Country', text='Country')
        self.geo_tree.heading('City', text='City')
        self.geo_tree.heading('ISP', text='ISP / Organization')
        self.geo_tree.heading('Connections', text='Connections')
        self.geo_tree.heading('Data_MB', text='Data (MB)')
        self.geo_tree.heading('Process', text='Associated Process')
        self.geo_tree.heading('Threat', text='Threat')
        
        self.geo_tree.column('IP', width=120)
        self.geo_tree.column('Country', width=100)
        self.geo_tree.column('City', width=100)
        self.geo_tree.column('ISP', width=160)
        self.geo_tree.column('Connections', width=100)
        self.geo_tree.column('Data_MB', width=90)
        self.geo_tree.column('Process', width=120)
        self.geo_tree.column('Threat', width=90)
        
        geo_scroll = ttk.Scrollbar(geo_frame, orient=tk.VERTICAL, command=self.geo_tree.yview)
        self.geo_tree.configure(yscrollcommand=geo_scroll.set)
        self.geo_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        geo_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Suspicious Processes Tab
        suspicious_frame = ttk.Frame(notebook)
        notebook.add(suspicious_frame, text="Suspicious Processes")
        
        ttk.Label(suspicious_frame, text="Processes with Suspicious Behavior:").pack(anchor=tk.W, pady=5)
        
        self.suspicious_tree = ttk.Treeview(
            suspicious_frame,
            columns=('Process', 'PID', 'Threat', 'Severity', 'Details', 'Status'),
            show='headings',
            height=20
        )
        
        self.suspicious_tree.heading('Process', text='Process Name')
        self.suspicious_tree.heading('PID', text='PID')
        self.suspicious_tree.heading('Threat', text='Threat Type')
        self.suspicious_tree.heading('Severity', text='Severity')
        self.suspicious_tree.heading('Details', text='Details')
        self.suspicious_tree.heading('Status', text='Status')
        
        self.suspicious_tree.column('Process', width=140)
        self.suspicious_tree.column('PID', width=70)
        self.suspicious_tree.column('Threat', width=150)
        self.suspicious_tree.column('Severity', width=100)
        self.suspicious_tree.column('Details', width=300)
        self.suspicious_tree.column('Status', width=100)
        
        suspicious_scroll = ttk.Scrollbar(suspicious_frame, orient=tk.VERTICAL, command=self.suspicious_tree.yview)
        self.suspicious_tree.configure(yscrollcommand=suspicious_scroll.set)
        self.suspicious_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        suspicious_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Alerts Tab
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text="Alert Log")
        
        ttk.Label(alerts_frame, text="Security Alerts & Events:").pack(anchor=tk.W, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, wrap=tk.WORD, height=25, font=("Courier", 9))
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        self.alerts_text.config(state=tk.DISABLED)
        
        # Configure tag colors
        self.process_tree.tag_configure('normal', background='#e6ffe6')
        self.process_tree.tag_configure('suspicious', background='#ffffcc')
        self.process_tree.tag_configure('malicious', background='#ffcccc')
        
        self.packets_tree.tag_configure('tcp', background='#e6f3ff')
        self.packets_tree.tag_configure('udp', background='#fff3e6')
        self.packets_tree.tag_configure('icmp', background='#f3e6ff')
        self.packets_tree.tag_configure('dns', background='#e6ffe6')
        
        self.geo_tree.tag_configure('local', background='#e6ffe6')
        self.geo_tree.tag_configure('safe', background='#e6f3ff')
        self.geo_tree.tag_configure('suspicious', background='#ffffcc')
        self.geo_tree.tag_configure('malicious', background='#ffcccc')
        
        self.suspicious_tree.tag_configure('critical', background='#ffcccc')
        self.suspicious_tree.tag_configure('high', background='#ffe6cc')
        self.suspicious_tree.tag_configure('medium', background='#ffffcc')
    
    def log_alert(self, message, level="INFO"):
        """Log security alerts"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "CRITICAL":
            alert = f"[{timestamp}] 🚨 CRITICAL: {message}\n"
        elif level == "HIGH":
            alert = f"[{timestamp}] ⚠️  HIGH: {message}\n"
        elif level == "MEDIUM":
            alert = f"[{timestamp}] ℹ️  MEDIUM: {message}\n"
        else:
            alert = f"[{timestamp}] ℹ️  {message}\n"
        
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.insert(tk.END, alert)
        self.alerts_text.config(state=tk.DISABLED)
        self.alerts_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_monitoring(self):
        """Start real packet capture"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is required. Install with: pip install scapy psutil requests")
            return
        
        if platform.system() in ["Windows", "Darwin"]:
            messagebox.showinfo("Note", "Administrator/Root privileges required for packet capture.")
        
        self.monitoring = True
        self.status_label.config(text="Status: ✓ Monitoring Active", foreground="green")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_alert("Packet capture started")
        
        thread = threading.Thread(target=self._capture_packets, daemon=True)
        thread.start()
    
    def stop_monitoring(self):
        """Stop packet capture"""
        self.monitoring = False
        self.status_label.config(text="Status: Stopped", foreground="gray")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_alert("Packet capture stopped")
    
    def clear_data(self):
        """Clear all collected data"""
        self.packets_tree.delete(*self.packets_tree.get_children())
        self.process_tree.delete(*self.process_tree.get_children())
        self.geo_tree.delete(*self.geo_tree.get_children())
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.config(state=tk.DISABLED)
        
        self.packet_count = 0
        self.traffic_data.clear()
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.process_connections.clear()
        self.suspicious_ips.clear()
        self.suspicious_processes.clear()
        self.blocked_ips.clear()
        self.ip_geolocation_cache.clear()
        
        self.update_statistics_display()
    
    def _get_process_name(self, local_port):
        """Get process name and PID from port"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == local_port:
                    try:
                        proc = psutil.Process(conn.pid)
                        return proc.name(), conn.pid
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return "Unknown", conn.pid
        except (psutil.AccessDenied, OSError):
            pass
        return "Unknown", 0
    
    def _get_geoip_info(self, ip_address):
        """Get GeoIP information for an IP address"""
        if ip_address in self.ip_geolocation_cache:
            return self.ip_geolocation_cache[ip_address]
        
        if ip_address.startswith(('10.', '172.', '192.168.', '127.', '169.')):
            info = {'country': 'Private', 'city': 'Local', 'isp': 'Local Network', 'org': 'Local'}
            self.ip_geolocation_cache[ip_address] = info
            return info
        
        try:
            if REQUESTS_AVAILABLE:
                response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        info = {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'org': data.get('org', 'Unknown')
                        }
                        self.ip_geolocation_cache[ip_address] = info
                        return info
        except Exception:
            pass
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            info = {'country': 'Unknown', 'city': 'Unknown', 'isp': hostname, 'org': hostname}
            self.ip_geolocation_cache[ip_address] = info
            return info
        except Exception:
            pass
        
        info = {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'org': 'Unknown'}
        self.ip_geolocation_cache[ip_address] = info
        return info
    
    def _capture_packets(self):
        """Capture real packets using Scapy"""
        try:
            self.log_alert("Starting real-time packet capture...")
            sniff(prn=self._packet_callback, store=False, stop_filter=lambda x: not self.monitoring)
        except PermissionError:
            self.log_alert("Permission denied. Run as Administrator/Root", "CRITICAL")
            self.stop_monitoring()
        except Exception as e:
            self.log_alert(f"Capture error: {str(e)}", "CRITICAL")
            self.stop_monitoring()
    
    def _packet_callback(self, packet):
        """Process captured packet"""
        try:
            if not self.monitoring:
                return
            
            self.packet_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            src_ip = None
            dst_ip = None
            protocol = "Other"
            src_port = 0
            dst_port = 0
            length = len(packet)
            process_name = "Unknown"
            pid = 0
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    process_name, pid = self._get_process_name(src_port)
                
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    process_name, pid = self._get_process_name(src_port)
                    
                    if DNS in packet:
                        protocol = "DNS"
                
                elif ICMP in packet:
                    protocol = "ICMP"
            
            # Update statistics
            if src_ip:
                self.ip_stats[src_ip]['packets'] += 1
                self.ip_stats[src_ip]['bytes'] += length
                if dst_port > 0:
                    self.ip_stats[src_ip]['ports'].add(dst_port)
            
            # Track process connections
            if process_name != "Unknown" or pid > 0:
                key = f"{process_name}_{pid}"
                self.process_connections[key]['name'] = process_name
                self.process_connections[key]['pid'] = pid
                self.process_connections[key]['bytes'] += length
                self.process_connections[key]['packets'] += 1
                if dst_port > 0:
                    self.process_connections[key]['ports'].add(dst_port)
                self.process_connections[key]['destinations'][dst_ip] += 1
                
                if dst_ip not in self.process_connections[key]['geoip_info']:
                    geo_info = self._get_geoip_info(dst_ip)
                    self.process_connections[key]['geoip_info'][dst_ip] = geo_info
            
            self.protocol_stats[protocol] += 1
            self.traffic_data['total'] += length
            
            tag = protocol.lower()
            self.packets_tree.insert('', tk.END, values=(
                timestamp, process_name, src_ip or "N/A", dst_ip or "N/A", protocol, dst_port, length
            ), tags=(tag,))
            
            if len(self.packets_tree.get_children()) > 300:
                first_item = self.packets_tree.get_children()[0]
                self.packets_tree.delete(first_item)
            
            if src_ip and process_name != "Unknown":
                self._check_process_threats(process_name, pid, src_ip, dst_ip, dst_port, protocol)
            
            if self.packet_count % 20 == 0:
                self.update_statistics_display()
        
        except Exception:
            pass
    
    def _check_process_threats(self, process_name, pid, src_ip, dst_ip, dst_port, protocol):
        """Detect suspicious process behavior"""
        key = f"{process_name}_{pid}"
        geo_info = self._get_geoip_info(dst_ip)
        high_risk_countries = {'North Korea', 'Iran', 'Syria', 'Cuba'}
        
        if geo_info.get('country') in high_risk_countries:
            if key not in self.suspicious_processes:
                self.suspicious_processes[key] = {
                    'name': process_name,
                    'pid': pid,
                    'threat': f'High-Risk Country ({geo_info.get("country")})',
                    'severity': 'CRITICAL',
                    'details': f"Connecting to {dst_ip}",
                    'count': 1
                }
                self.log_alert(f"{process_name} (PID:{pid}) -> {geo_info.get('country')}", "CRITICAL")
        
        if dst_port in self.suspicious_ports and protocol == "TCP":
            if key not in self.suspicious_processes:
                self.suspicious_processes[key] = {
                    'name': process_name,
                    'pid': pid,
                    'threat': 'Suspicious Port',
                    'severity': 'HIGH',
                    'details': f"Port {dst_port} in {geo_info.get('country')}",
                    'count': 1
                }
                self.log_alert(f"{process_name} (PID:{pid}) accessing port {dst_port}", "HIGH")
        
        if len(self.process_connections[key]['ports']) > 15:
            if key not in self.suspicious_processes:
                self.suspicious_processes[key] = {
                    'name': process_name,
                    'pid': pid,
                    'threat': 'Port Scanning',
                    'severity': 'CRITICAL',
                    'details': f"{len(self.process_connections[key]['ports'])} ports",
                    'count': len(self.process_connections[key]['ports'])
                }
                self.log_alert(f"{process_name} (PID:{pid}) port scanning detected", "CRITICAL")
        
        if len(self.process_connections[key]['destinations']) > 20:
            if key not in self.suspicious_processes:
                self.suspicious_processes[key] = {
                    'name': process_name,
                    'pid': pid,
                    'threat': 'Data Exfiltration',
                    'severity': 'CRITICAL',
                    'details': f"To {len(self.process_connections[key]['destinations'])} IPs",
                    'count': len(self.process_connections[key]['destinations'])
                }
                self.log_alert(f"{process_name} (PID:{pid}) data exfiltration detected", "CRITICAL")
    
    def update_statistics_display(self):
        """Update all statistics displays"""
        self.packet_label.config(text=f"Packets: {self.packet_count}")
        total_kb = self.traffic_data['total'] / 1024
        self.traffic_label.config(text=f"Traffic: {total_kb:.2f} KB")
        self.process_label.config(text=f"Processes: {len(self.process_connections)}")
        self.threat_label.config(text=f"Threats: {len(self.suspicious_processes)}")
        
        # Process stats
        self.process_tree.delete(*self.process_tree.get_children())
        for key, data in sorted(self.process_connections.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]:
            if data['destinations']:
                first_ip = list(data['destinations'].keys())[0]
                geo = data['geoip_info'].get(first_ip, {})
                country = geo.get('country', 'Unknown')
            else:
                country = 'N/A'
            
            risk = "CRITICAL" if key in self.suspicious_processes else ("HIGH" if data['bytes'] > 10000000 else "LOW")
            tag = 'malicious' if risk == "CRITICAL" else ('suspicious' if risk == "HIGH" else 'normal')
            
            self.process_tree.insert('', tk.END, values=(
                data['name'],
                data['pid'],
                data['packets'],
                f"{data['bytes'] / 1024:.1f}",
                list(data['destinations'].keys())[0] if data['destinations'] else 'N/A',
                country,
                max(data['ports']) if data['ports'] else 0,
                len(data['destinations']),
                risk
            ), tags=(tag,))
        
        # GeoIP stats
        self.geo_tree.delete(*self.geo_tree.get_children())
        ip_stats_agg = defaultdict(lambda: {'country': '', 'city': '', 'isp': '', 'connections': 0, 'bytes': 0, 'processes': set(), 'threat': 'LOW'})
        
        for key, data in self.process_connections.items():
            for ip, count in data['destinations'].items():
                geo = data['geoip_info'].get(ip, {})
                ip_stats_agg[ip]['country'] = geo.get('country', 'Unknown')
                ip_stats_agg[ip]['city'] = geo.get('city', 'Unknown')
                ip_stats_agg[ip]['isp'] = geo.get('isp', 'Unknown')
                ip_stats_agg[ip]['connections'] += count
                ip_stats_agg[ip]['bytes'] += data['bytes']
                ip_stats_agg[ip]['processes'].add(data['name'])
                
                if ip in self.blocked_ips:
                    ip_stats_agg[ip]['threat'] = 'CRITICAL'
        
        for ip, stats in sorted(ip_stats_agg.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]:
            tag = 'local' if stats['country'] == 'Private' else ('malicious' if stats['threat'] == 'CRITICAL' else 'safe')
            processes = ', '.join(list(stats['processes'])[:2])
            
            self.geo_tree.insert('', tk.END, values=(
                ip,
                stats['country'],
                stats['city'],
                stats['isp'][:30],
                stats['connections'],
                f"{stats['bytes']/1024/1024:.1f}",
                processes,
                stats['threat']
            ), tags=(tag,))
        
        # Suspicious processes
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        for key, threat in self.suspicious_processes.items():
            tag = 'critical' if threat['severity'] == 'CRITICAL' else ('high' if threat['severity'] == 'HIGH' else 'medium')
            self.suspicious_tree.insert('', tk.END, values=(
                threat['name'],
                threat['pid'],
                threat['threat'],
                threat['severity'],
                threat['details'],
                "FLAGGED"
            ), tags=(tag,))


def main():
    """Main entry point"""
    root = tk.Tk()
    app = NetworkTrafficMonitor(root)
    root.mainloop()


if __name__ == "__main__":
    main()