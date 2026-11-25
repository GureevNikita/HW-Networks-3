import argparse
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import sr1
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send


def parse_ports(ports_in_line):
    ports = set()
    for part in ports_in_line.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            if end >= 65535 + 1 or start < 1:
                print('неправильные порты')
            for i in range(start, end + 1):
                ports.add(i)
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip')
    parser.add_argument('specs', nargs='+', )
    parser.add_argument('--timeout', type=float, default=2.0)
    parser.add_argument('-j', '--num-threads', type=int, default=20)
    parser.add_argument('-v', '--verbose', action='store_true',  # просто bool
                        )
    parser.add_argument('-g', '--guess', action='store_true')

    return parser.parse_args()


def make_dns_query():
    transaction_id = random.randint(1, 65535)
    query = DNS(id=transaction_id, rd=1,  # рекурсивный резолв
                qd=DNSQR(qname='example.com', qtype='A')  # вопрос
                )
    return transaction_id, bytes(query)


def is_dns_response(data, transaction_id):
    try:
        pkt = DNS(data)
        return pkt.qr == 1 and pkt.id == transaction_id  # пришел ответ, причем нужный
    except Exception:
        return False


# получение заданного количества байтов из TCP-сокета
def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None

        data += chunk
    return data


# определение протокола для TCP
def guess_tcp(ip, port, timeout):
    # HTTP
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            request = (
                b'GET / HTTP/1.0\r\n'
                b'Host: example.com\r\n'
                b'Connection: close\r\n\r\n'
            )
            s.sendall(request)
            response = s.recv(1024)
            if response.startswith(b'HTTP/'):
                return 'HTTP'

    except Exception:  # мб так пока
        pass

    # DNS
    try:
        transaction_id, query = make_dns_query()
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack('!H', len(query)) + query)
            length_data = recv_exact(s, 2)

            if length_data:
                length = struct.unpack('!H', length_data)[0]
                response = recv_exact(s, length)

                if response and is_dns_response(response, transaction_id):
                    return 'DNS'

    except Exception:
        pass

    # ECHO
    try:
        message = b'asdasd'
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(message)
            response = recv_exact(s, len(message))
            if response == message:
                return 'ECHO'

    except Exception:
        pass

    return '-'


# определение протокола для UDP
def guess_udp(ip, port, timeout):
    # DNS
    try:
        transaction_id, query = make_dns_query()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, port))
            response, _ = s.recvfrom(4096)

            if is_dns_response(response, transaction_id):
                return 'DNS'

    except Exception:
        pass

    # ECHO
    try:
        message = b'asdasdd'

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(message, (ip, port))
            response, _ = s.recvfrom(1024)

            if response == message:
                return 'ECHO'

    except Exception:
        pass

    return '-'


# tcp/udp
def guess_protocol(ip, proto, port, timeout):
    if proto == 'tcp':
        return guess_tcp(ip, port, timeout)

    if proto == 'udp':
        return guess_udp(ip, port, timeout)

    return '-'


def tcp_syn_scan(ip: str, port: int, timeout: float):
    start = time.perf_counter()
    sport = random.randint(1024, 65535)

    # пытвемся сделать рукопожатие
    pkt = IP(dst=ip) / TCP(
        sport=sport,
        dport=port,
        flags='S'
    )

    resp = sr1(pkt, timeout=timeout, verbose=0,
               threaded=False)  # !!! threaded=False иначе ловит ошибку [Errno 9] Bad file descriptor

    elapsed_ms = (time.perf_counter() - start) * 1000

    if resp is None:
        return port, False, elapsed_ms

    if resp.haslayer(TCP):
        tcp_resp = resp.getlayer(TCP)
        flags = int(tcp_resp.flags)

        # проверка SYN и ACK
        if (flags & 0x12) == 0x12:
            # отправляем Reset на полуоткрытое соединение
            rst = IP(dst=ip) / TCP(
                sport=sport,
                dport=port,
                flags='R',
                seq=int(tcp_resp.ack)
            )

            send(rst, verbose=0)

            return port, True, elapsed_ms

    return port, False, elapsed_ms


def udp_scan(ip: str, port: int, timeout: float):
    # проверка DNS и ECHO
    _, dns_query = make_dns_query()

    probes = [
        dns_query,
        b'asdasda'
    ]

    for payload in probes:

        sport = random.randint(1024, 65535)

        pkt = IP(dst=ip) / UDP(
            sport=sport,
            dport=port
        ) / Raw(load=payload)

        resp = sr1(pkt, timeout=timeout, verbose=0, threaded=False)

        if resp is None:
            continue

        # проверка ICMP
        if resp.haslayer(ICMP):
            icmp = resp.getlayer(ICMP)

            if icmp.type == 3:
                # порт не доступен
                return port, False

            continue

        # получен ответ
        if resp.haslayer(UDP):
            return port, True

    # не получен ответ
    return port, False


def main():
    args = parse_args()
    tasks = []

    for spec in args.specs:
        if '/' in spec:
            proto, port_part = spec.split('/', 1)
        else:
            proto = spec
            port_part = '1-65535'

        proto = proto.lower()

        if proto not in ('tcp', 'udp'):
            print('неправильный протокол')
            sys.exit(1)

        for port in parse_ports(port_part):
            tasks.append((proto, port))

    if not tasks:
        print('ytn портов')
        sys.exit(0)

    # запускаем сканирование
    results = []
    with ThreadPoolExecutor(max_workers=args.num_threads) as pool:
        fut_map = {}
        for proto, port in tasks:
            if proto == 'tcp':
                fut = pool.submit(tcp_syn_scan, args.ip, port, args.timeout)
                fut_map[fut] = ('tcp', port)
            elif proto == 'udp':
                fut = pool.submit(udp_scan, args.ip, port, args.timeout)
                fut_map[fut] = ('udp', port)

        for fut in as_completed(fut_map):
            proto, port = fut_map[fut]
            try:
                if proto == "tcp":
                    p, is_open, ms = fut.result()
                elif proto == "udp":
                    p, is_open = fut.result()
                    ms = None
            except Exception:
                continue
            if is_open:
                results.append((proto, p, ms))

    results.sort(key=lambda x: (x[1], x[0]))

    # печатаем
    for proto, port, ms in results:
        parts = [proto.upper(), str(port)]

        if args.verbose:
            if proto == "tcp" and ms is not None:
                parts.append(f"{int(round(ms))}ms")
            else:
                parts.append("-")

        if args.guess:
            parts.append(guess_protocol(args.ip, proto, port, args.timeout))

        print(" ".join(parts))


if __name__ == '__main__':
    main()
