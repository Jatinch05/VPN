import socket


# Create a dummy connection to an external address
def get_local_ip():
    try:
        # Connect to an external server (Google's public DNS server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        return f"Error: {e}"

local_ip = get_local_ip()
print(f"Local IP Address: {local_ip}")


# hostname = socket.gethostname()
# IPAddr = socket.gethostbyname(hostname)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((local_ip, 5000))
server.listen(1)
print(f"Server is listening on {local_ip}")

client_socket, client_address = server.accept()
print(f"Connection from {client_address}")
while True:
    data = client_socket.recv(1024).decode()
    if not data:
        break
    print(f"Received: {data}")
    # client_socket.send(data.encode())

client_socket.close()
server.close()
