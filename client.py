import socket
import sys
import asyncio
from ECDH import ecdh_public_private_gen, ecdh_symmetric_key_gen, serialize_public_key, deserialize_public_key
from AES import aes_encrypt, aes_decrypt
import pickle
# Switch to SelectorEventLoop for compatibility with Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class ClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, on_con_lost, private_key):
        self.message = message
        self.on_con_lost = on_con_lost
        self.private_key = private_key  # Store the private key in the protocol instance

    def connection_made(self, transport):
        self.transport = transport
        print(f"Starting Client...")
        print(f"Sending message: {self.message}")
        self.transport.sendto(self.message.encode(), ('::1', 5000))  # Sending initial message

    def datagram_received(self, data, addr):
        print(f"Message received: {data.decode()}")
        if data.decode() == "Quit":
            self.on_con_lost.set_result(True)

        # Handle the server's public key response
        try:
            # Deserialize the server's public key tuple (x, y)
            server_public_key = deserialize_public_key(*pickle.loads(data))  # Deserialize the pickled data
            print(f"Received server's public key: {server_public_key}")
        except Exception as e:
            print(f"Error deserializing data: {e}")
            server_public_key = (0, 0)
            exit(0)

        # Generate the symmetric key based on the public/private keys
        symmetric_key = ecdh_symmetric_key_gen(self.private_key, server_public_key)
        print(f"symmetric key = {symmetric_key}")  # 256-bit shared secret key

        # Encrypted conversation using shared symmetric key and AES
        message = input("Enter message: ")
        encrypted_message = aes_encrypt(symmetric_key, message)
        self.transport.sendto(encrypted_message, addr)

    def error_received(self, exc):
        print(f"Error received: {exc}")

    def connection_lost(self, exc):
        print("Socket closed")

async def run_client():
    loop = asyncio.get_running_loop()
    message = "Hello, Server!"
    on_con_lost = loop.create_future()

    # Generate public and private keys using ECDH
    print("Generating Public and Private Keys...")
    public_key, private_key = ecdh_public_private_gen()

    # Serialize the public key to (x, y) tuple
    serialized_public_key = serialize_public_key(public_key)

    # Create the datagram endpoint for the client
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(message, on_con_lost, private_key),  # Pass the private_key to the protocol
        family=socket.AF_INET6,  # Explicitly use IPv6
    )

    try:
        # Send and receive data using UDP
        await on_con_lost  # Wait until the server responds or an error occurs
        print("Sent and received message from server.")

        # Send the serialized public key (x, y) directly to the server (without pickling)
        transport.sendto(pickle.dumps(serialized_public_key), ('::1', 5000))  # Send serialized public key as (x, y) tuple

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(run_client())
