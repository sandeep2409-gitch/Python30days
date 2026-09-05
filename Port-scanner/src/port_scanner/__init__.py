import socket 
target=input("Enter target :")
start_port=int(input("Enter start port:"))
end_port=int(input("Enter end port:"))
try:
     target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("Invalid target")
    raise SystemExit
    print(f"\nScanning {target_ip}...\n")
for port in range(start_port, end_port + 1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        print(f"[OPEN] Port {port}")
    sock.close()
print("\nScan complete.")