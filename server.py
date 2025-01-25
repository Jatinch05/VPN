# import socket
# import pickle
# #from RSA import rsa,rsa_decryption
# from ECDH import ecdh_public_private_gen,ecdh_symmetric_key_gen,serialize_public_key,deserialize_public_key
# from AES import aes_encrypt,aes_decrypt
# import asyncio
#
# async def manage_client(loop,transport,data,addr):
#     print(f"Received message from {addr}: {data.decode()}")
#     transport.sendto("hello Client".encode(),addr)
#     #receiveing public key from client
#
#
#
# class Server_Protocol(asyncio.DatagramProtocol):
#     def __init__(self,loop):
#         self.loop=loop
#
#     def connection_made(self,transport):
#         self.transport=transport
#         print("Server is running...")
#
#     def datagram_received(self, data, addr):
#         print(f"Data received from {addr}")
#         asyncio.create_task(manage_client(self.loop,self.transport,data,addr))
#
#     def connection_lost(self, exc):
#         print("connection lost: ",exec)
#
# async def run_server():
#     loop=asyncio.get_running_loop()
#     transport,protocol=await loop.create_datagram_endpoint(
#         protocol_factory=lambda: Server_Protocol(loop),
#         local_addr=('localhost',5000)
#     )
#     try:
#         # Keep the server running
#         await asyncio.sleep(float('inf'))
#     except asyncio.CancelledError:
#         pass
#     finally:
#         transport.close()
#     # Create a UDP socket
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     server_socket.bind(("localhost", 5000))
#
#     print("Server started listening on port 5000...")
#
#     while True:
#         # Receive data from the client
#         data, client_addr = server_socket.recvfrom(1024)
#         print(f"Received message: {data.decode()} from {client_addr}")
#
#         # Send a response to the client
#         server_socket.sendto(b"Hello, Client!", client_addr)
#
#         # Receive public key from the client
#         data, client_addr = server_socket.recvfrom(1024)
#         try:
#             # Unpickle the received public key
#             client_public_key = pickle.loads(data)# received x,y cords of public key
#             print(f"Client's public key: {client_public_key}")
#         except Exception as e:
#             print(f"Error unpickling data: {e}")
#             continue
#
#         print("Generating and sending the server's public key to the client...")
#         # Generate server's public/private objects
#         server_public_key, server_private_key = ecdh_public_private_gen()
#
#         # Serialize the public key
#         serialized_public_key = serialize_public_key(server_public_key) #bcz pickle cant dump cryptographic objects
#         #we are converting public key object to (x,y)
#         message = pickle.dumps(serialized_public_key)
#         #sending client public keys
#         server_socket.sendto(message, client_addr)
#         print("sent public key")
#
#         #deserialize client's public key
#         client_public_key=deserialize_public_key(*client_public_key) #converting (x,y) cords to public_key object
#         # generating symmetric key
#         symmetric_key=ecdh_symmetric_key_gen(server_private_key,client_public_key)
#         print(f"symmetric key = {symmetric_key}") #256-bit shared secret key
#
#         data,client_addr=server_socket.recvfrom(1024)
#         decrypted_data=aes_decrypt(symmetric_key,data)
#         print("decrypted data: ",decrypted_data)
#
#
#
# if __name__ == "__main__":
#     asyncio.run(run_server())

import sys
import asyncio
import pickle
from ECDH import ecdh_public_private_gen, ecdh_symmetric_key_gen, serialize_public_key, deserialize_public_key
from AES import aes_encrypt, aes_decrypt

# Switch to SelectorEventLoop for compatibility with Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def manage_client(transport, data, addr):
    print(f"Received message from {addr}: {data.decode()}")
    transport.sendto("hello Client".encode(), addr)

    # Generate server's public/private key pair using ECDH
    server_public_key, server_private_key = ecdh_public_private_gen()

    # Serialize the public key to send as (x, y) tuple
    serialized_public_key = serialize_public_key(server_public_key)

    # Convert the tuple into bytes using pickle
    serialized_public_key_bytes = pickle.dumps(serialized_public_key)

    # Send server's public key to the client
    transport.sendto(serialized_public_key_bytes, addr)
    print("Sent public key to the client")

    # Unserialize the client's public key and generate the shared symmetric key
    try:
        # Deserialize the received data directly (as (x, y) tuple)
        client_public_key = deserialize_public_key(*pickle.loads(data))  # Deserialize the pickled data
        print(f"Client's public key (deserialized): {client_public_key}")
    except Exception as e:
        print(f"Error deserializing data: {e}")
        return  # Handle the error gracefully

    # Generate symmetric key using the ECDH method
    symmetric_key = ecdh_symmetric_key_gen(server_private_key, client_public_key)
    print(f"Symmetric key = {symmetric_key}")  # 256-bit shared secret key

    # Wait for further communication (receive encrypted data from the client)

class Server_Protocol(asyncio.DatagramProtocol):
    def __init__(self, loop):
        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport
        print("Server is running...")

    def datagram_received(self, data, addr):
        print(f"Data received from {addr}")
        # Handle client interaction asynchronously
        asyncio.create_task(manage_client(self.transport, data, addr))

    def connection_lost(self, exc):
        print("Connection lost:", exc)

    def error_received(self, exc):
        print("Error received:", exc)

async def run_server():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        protocol_factory=lambda: Server_Protocol(loop),
        local_addr=('localhost', 5000)
    )

    try:
        # Keep the server running indefinitely
        await asyncio.sleep(float('inf'))
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(run_server())

