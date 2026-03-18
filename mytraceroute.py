#!/usr/bin/env python3
import socket
import struct
import sys
import time

MAX_HOPS = 30
TRIES = 3
TIMEOUT = 2.0
BASE_PORT = 33434

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def get_local_ip(dest):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dest, 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def create_udp_packet(src_ip, dst_ip, ttl, src_port, dst_port):
    ip_ver = 4
    ip_ihl = 5
    ip_ver_ihl = (ip_ver << 4) + ip_ihl
    ip_tos = 0
    ip_tot_len = 20 + 8
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = ttl
    ip_proto = socket.IPPROTO_UDP
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_check = 0

    ip_header_net = struct.pack("!BBHHHBBH4s4s",
                                ip_ver_ihl,
                                ip_tos,
                                ip_tot_len,
                                ip_id,
                                ip_frag_off,
                                ip_ttl,
                                ip_proto,
                                ip_check,
                                ip_saddr,
                                ip_daddr)

    ip_header = bytearray(ip_header_net)
    ip_header[2], ip_header[3] = ip_header[3], ip_header[2]
    ip_header = bytes(ip_header)

    ip_check = checksum(ip_header)
    ip_header = bytearray(ip_header)
    ip_header[10] = (ip_check >> 8) & 0xFF
    ip_header[11] = ip_check & 0xFF
    ip_header = bytes(ip_header)

    udp_length = 8
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

    pseudo_header = struct.pack("!4s4sBBH",
                                ip_saddr,
                                ip_daddr,
                                0,
                                ip_proto,
                                udp_length)
    udp_checksum = checksum(pseudo_header + udp_header)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    return ip_header + udp_header

def traceroute(dest_name, resolve_dns=True):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print(f"Error: Host {dest_name} not found")
        sys.exit(1)

    print(f"Traceroute to {dest_name} ({dest_addr}), {MAX_HOPS} hops max")

    src_ip = get_local_ip(dest_addr)

    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_socket.bind((src_ip, 0))
    except PermissionError:
        print("Ошибка: требуются права суперпользователя (sudo)")
        sys.exit(1)

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(TIMEOUT)
        recv_socket.bind((src_ip, 0))
    except PermissionError:
        print("Ошибка: требуются права суперпользователя (sudo)")
        send_socket.close()
        sys.exit(1)

    sequence = 0

    for ttl in range(1, MAX_HOPS + 1):
        print(f"{ttl:2}", end=" ")
        hop_addr = None
        reached = False

        for _ in range(TRIES):
            dst_port = BASE_PORT + sequence
            sequence += 1
            src_port = 12345

            packet = create_udp_packet(src_ip, dest_addr, ttl, src_port, dst_port)

            start_time = time.time()
            send_socket.sendto(packet, (dest_addr, 0))

            try:
                # В цикле ожидаем ответ, но учитываем возможность чужих пакетов
                while True:
                    # Оставшееся время ожидания для этой попытки
                    remaining = TIMEOUT - (time.time() - start_time)
                    if remaining <= 0:
                        raise socket.timeout
                    recv_socket.settimeout(remaining)

                    data, addr = recv_socket.recvfrom(512)

                    # Анализ полученного ICMP-пакета
                    # Определяем длину внешнего IP-заголовка
                    outer_ip_hdr_len = (data[0] & 0x0F) * 4
                    icmp_type = data[outer_ip_hdr_len]
                    icmp_code = data[outer_ip_hdr_len + 1]

                    # Извлекаем тело ICMP-сообщения
                    icmp_body = data[outer_ip_hdr_len + 8:]
                    # Длина исходного IP-заголовка (нашего пакета)
                    inner_ip_hdr_len = (icmp_body[0] & 0x0F) * 4
                    # Извлекаем UDP-заголовок исходного пакета (первые 8 байт данных)
                    inner_udp = icmp_body[inner_ip_hdr_len:inner_ip_hdr_len + 8]
                    # Порт назначения исходного UDP-пакета (байты 2-3 в UDP-заголовке)
                    inner_dst_port = struct.unpack("!H", inner_udp[2:4])[0]

                    # Проверяем, относится ли этот ответ к нашему пакету
                    if inner_dst_port != dst_port:
                        # Чужой пакет, игнорируем и продолжаем ждать
                        continue

                   
                    elapsed = (time.time() - start_time) * 1000

                    if icmp_type == 11:  # Time Exceeded
                        print(f"{elapsed:.2f} ms", end=" ")
                        hop_addr = addr[0]
                    elif icmp_type == 3 and icmp_code == 3:  # Port Unreachable
                        print(f"{elapsed:.2f} ms", end=" ")
                        hop_addr = addr[0]
                        reached = True
                    else:
                        # Другие ICMP  – тоже считаем ответом
                        print(f"{elapsed:.2f} ms", end=" ")
                        hop_addr = addr[0]

                    break  # Выходим из внутреннего цикла ожидания

            except socket.timeout:
                print("*", end=" ")

        if hop_addr:
            if resolve_dns:
                try:
                    host = socket.gethostbyaddr(hop_addr)[0]
                    print(f"{host} ({hop_addr})")
                except socket.herror:
                    print(hop_addr)
            else:
                print(hop_addr)
        else:
            print()

        if reached:
            break

    send_socket.close()
    recv_socket.close()

if __name__ == "__main__":
    resolve_dns = True
    if len(sys.argv) < 2:
        print("Usage: sudo ./mytraceroute.py [-n] <host>")
        sys.exit(1)
    if sys.argv[1] == "-n":
        resolve_dns = False
        destination = sys.argv[2]
    else:
        destination = sys.argv[1]

    traceroute(destination, resolve_dns)
