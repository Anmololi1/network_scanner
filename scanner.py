import socket
import sys
import subprocess

def scan_port(ip, port):
    try:
        socket.create_connection((ip, port))
        return True
    except socket.error:
        return False

def get_services(ip):
    services = {}
    for port in range(1, 65535):
        if scan_port(ip, port):
            services[port] = get_service_version(port)

    return services

def get_service_version(port):
    services = {
        80: "HTTP",
        443: "HTTPS",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        22: "SSH",
        23: "Telnet",
        53: "DNS",
        21: "FTP"
    }

    try:
        p = subprocess.Popen(["nmap", "-p", str(port), ip], stdout=subprocess.PIPE)
        output = p.communicate()[0].decode("utf-8")
        version = re.search(r"Version: (.*)", output).group(1)
    except subprocess.CalledProcessError:
        version = "Unknown"

    return services.get(port, version)

def scan_cctv(ip):
    for port in [80, 443]:
        if scan_port(ip, port):
            print("CCTV is running on IP address {} and port {}".format(ip, port))

def main():
    ip_range = sys.argv[1]

    for ip in range(ip_range.split(".")[0], ip_range.split(".")[2] + 1):
        for j in range(int(ip_range.split(".")[1]), 255):
            ip_address = "{}.{}.{}.{}".format(ip, j, ip_range.split(".")[2], ip_range.split(".")[3])

            print("Scanning IP address: {}...".format(ip_address))

            services = get_services(ip_address)

            for port, service in services.items():
                if service == "Unknown":
                    continue

                print("Open port: {} ({})".format(port, service))

            if scan_cctv(ip_address):
                print("CCTV is running on IP address {}".format(ip_address))

if __name__ == "__main__":
    main()
