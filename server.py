import socket

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IPAddr, 12345))
server.listen(1)
print(f"Server is listening on {IPAddr}")

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
