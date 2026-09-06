import socket


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((target, port))

        return result ==0

    finally:
        sock.close()


def main():
    target = input("Enter target: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid target.")
        return

    print(f"\nScanning {target_ip}...\n")

    found = 0

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"[OPEN] Port {port}")
            found += 1

    print(f"\nScan complete. Found {found} open port(s).")


if __name__ == "__main__":
    main()