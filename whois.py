from scapy.all import *
import socket
import re
import argparse
import prettytable


def trace(hostname: str) -> list[str]:
    """Trace route to hostname by IP addresses"""

    destination = socket.gethostbyname(hostname)
    ip_addreses = []

    max_hops = 32
    default_port = 33434
    end_code = 3

    for ttl in range(max_hops):
        empty_packet = IP(
            dst=destination,
            ttl=ttl
        ) / UDP(
            dport=default_port
        )

        responce = sr1(
            empty_packet,
            verbose=False,
            timeout=1
        )

        if responce is not None:
            ip_addreses.append(responce.src)

            if responce.type == end_code:
                break

    return ip_addreses


description_regexp = re.compile(
    r'^(?:descr|OrgName|owner):\s*(.*)$'
)
country_regexp = re.compile(
    r'^(?:country|Country):\s*(.*)$'
)
autonomus_station_regexp = re.compile(
    '^(?:origin|OriginAS|aut-num):\s*(.*)$'
)


def parse_rir(log: str) -> tuple[str, str, str] | None:
    autonomus_station = None
    country = None
    description = None

    for line in log.splitlines():
        if (description_match := description_regexp.match(line)) is not None:
            description = description_match.group(1)
        elif (country_match := country_regexp.match(line)) is not None:
            country = country_match.group(1)
        elif (autonomus_station_match := autonomus_station_regexp.match(line)) is not None:
            autonomus_station = autonomus_station_match.group(1)

    if description is None or \
            country is None or \
            autonomus_station is None:
        return None

    return autonomus_station, country, description


def whois(ip: str) -> tuple[str, str, str] | None:
    rir_hostnames = [
        'whois.ripe.net',
        'whois.arin.net',
        'whois.apnic.net',
        'whois.afrinic.net',
        'whois.lacnic.net'
    ]
    rir_port = 43

    for rir_hostname in rir_hostnames:
        rir_ip = socket.gethostbyname(rir_hostname)

        rir_socket = socket.create_connection(
            (rir_ip, rir_port)
        )
        rir_socket.sendall(
            f'{ip}\n'.encode()
        )

        log = ""

        while (buffer := rir_socket.recv(1024).decode()) is not None and len(buffer) > 0:
            log += buffer

        rir_socket.close()

        if (result := parse_rir(log)) is not None:
            return result

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname')

    args = parser.parse_args()

    table = prettytable.PrettyTable()

    table.field_names = ['ip', 'as', 'country', 'description']

    ip_list = trace(args.hostname)

    info = [
        (ip, whois(ip)) for ip in ip_list
    ]

    for ip, (autonomus_station, country, description) in info:
        table.add_row(
            [ip, autonomus_station, country, description])

    print(table)


if __name__ == '__main__':
    main()
