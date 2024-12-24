import socket

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 5000))  
    server_socket.listen(5)
    print("Server is listening on port 5000...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")

        try:
            data = client_socket.recv(1024).decode()
            target_ip, target_port = data.split(":")
            target_port = int(target_port)
            print(f"Received target address: {target_ip}:{target_port}")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
                forward_socket.connect((target_ip, target_port))
                forward_socket.sendall(b"Hello from the server!")

                response = forward_socket.recv(1024)
                print(f"Response from {target_ip}:{target_port}: {response.decode()}")

            client_socket.sendall(response)

        except Exception as e:
            print(f"Error: {e}")
            client_socket.sendall(f"Error: {e}".encode())

        finally:
            client_socket.close()

if __name__ == "__main__":
    run_server()
