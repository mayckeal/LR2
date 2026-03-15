import socket
import sys
import time

MAX_HOPS = 30
TRIES = 3
TIMEOUT = 2.0
BASE_PORT = 33434


def traceroute(dest_name, resolve_dns=True):

    
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print(f"Error: Host {dest_name} not found")
        sys.exit(1)

    print(f"Traceroute to {dest_name} ({dest_addr}), {MAX_HOPS} hops max")

    sequence = 0

    for ttl in range(1, MAX_HOPS + 1):

        print(f"{ttl}", end=" ")

        hop_addr = None

        for attempt in range(TRIES):

            port = BASE_PORT + sequence
            sequence += 1

            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.settimeout(TIMEOUT)
            recv_socket.bind(("", 0))

            start_time = time.time()

            send_socket.sendto(b"", (dest_addr, port))

            try:
                data, addr = recv_socket.recvfrom(512)

                elapsed = (time.time() - start_time) * 1000
                print(f"{round(elapsed,2)} ms", end=" ")

                hop_addr = addr[0]

            except socket.timeout:
                print("*", end=" ")

            finally:
                send_socket.close()
                recv_socket.close()

       
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
            print("")

      
        if hop_addr == dest_addr:
            break


if __name__ == "__main__":

    resolve_dns = True

    if len(sys.argv) < 2:
        print("Usage: sudo python3 traceroute_udp.py [-n] <host>")
        sys.exit(1)

    if sys.argv[1] == "-n":
        resolve_dns = False
        destination = sys.argv[2]
    else:
        destination = sys.argv[1]

    traceroute(destination, resolve_dns)