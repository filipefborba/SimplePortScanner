import nmap
import argparse
import cowsay

# Terminal colors (completely optional)
# https://www.geeksforgeeks.org/print-colors-python-terminal/
class term_colors:
    reset = '\033[0m'
    bold = '\033[01m'
    underline = '\033[04m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    cyan = '\033[36m'
    lightred = '\033[91m'
    lightgreen = '\033[92m'
    yellow = '\033[93m'
    lightblue = '\033[94m'
    lightcyan = '\033[96m'


def parse_arguments(ports_range, tcp, udp):
    # -Pn: Treat all hosts as online -- skip host discovery
    host_discovery = '-Pn'

    # -p <port ranges>: Only scan specified ports
    ports = "-p"+ports_range

    # -sS: TCP SYN | -sU: UDP Scan
    # -sV: Probe open ports to determine service/version info
    is_tcp = 'S' if tcp else ''
    is_udp = 'U' if udp else ''
    scan_args = '-s'+is_tcp+is_udp+'V'

    return f'{host_discovery} {ports} {scan_args}'


def state_color(state):
    if state == 'open':
        return f'{term_colors.green}{state}{term_colors.reset}'
    elif state == 'closed':
        return f'{term_colors.red}{state}{term_colors.reset}'
    else:
        return f'{term_colors.yellow}{state}{term_colors.reset}'


def main():
    # Read arguments from command line
    parser = argparse.ArgumentParser(
        description='Python Port Scanner made by Borba for the Hacker Technologies class.')
    parser.add_argument(
        'hosts', type=str, help='IP from machine or network to be scanned. E.g. "192.168.50.250".')  # args.hosts
    parser.add_argument('-r', '--range', type=str,
                        help='Range of ports to be scanned. Default: "22-443".', default='22-443')  # args.range
    parser.add_argument('--tcp', action="store_true",
                        help='Enable TCP scan. Default: False.', default=False)  # args.tcp
    parser.add_argument('--udp', action="store_true",
                        help='Enable UDP scan. Default: False.', default=False)  # args.udp
    args = parser.parse_args()

    # Greet message (completely optional)
    cowsay.cow("Welcome to Borba's Port Scanner")

    # Instantiate portscanner and begin scanning
    nm = nmap.PortScanner()
    portscanner_args = parse_arguments(args.range, args.tcp, args.udp)
    nm.scan(hosts=args.hosts, arguments=portscanner_args)

    # Print results
    print('Host --|-- Port/Protocol --|-- Status --|-- Service --|-- Version')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                host_name = f'{term_colors.bold}{host} ({nm[host].hostname()}){term_colors.reset}'
                port_proto = f'{term_colors.lightcyan}{port}/{proto}{term_colors.reset}'
                state = state_color(nm[host][proto][port]['state'])
                service = nm[host][proto][port]['name']
                product_version = f'{nm[host][proto][port]["product"]} {nm[host][proto][port]["version"]}'
                print(f'{host_name} | {port_proto} | {state} | {service} | {product_version}')

if __name__ == "__main__":
    main()
