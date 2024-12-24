import socket

def run_client(server_ip, server_port, target_ip, target_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    try:
        target_address = f"{target_ip}:{target_port}"
        client_socket.sendall(target_address.encode())
        print(f"Sent target address to server: {target_address}")

        response = client_socket.recv(1024)
        print("Response from server:", response.decode())

    finally:
        client_socket.close()

if __name__ == "__main__":
    run_client("127.0.0.1", 5000, "127.0.0.1", 8080)
