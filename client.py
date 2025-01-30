import asyncio
import enum
import socket
import pickle

from twisted.runner.procmon import transport

from ECDH import ecdh_public_private_gen, ecdh_symmetric_key_gen, serialize_public_key, deserialize_public_key
from AES import aes_encrypt, aes_decrypt

class ClientState(enum.IntEnum):
    HANDSHAKE_INITIATED = enum.auto()
    HANDSHAKE_COMPLETED = enum.auto()
    CONNECTED = enum.auto()
    DISCONNECTED = enum.auto()

class ClientHandler:
    def __init__(self):
        self.state = ClientState.HANDSHAKE_INITIATED
        self.client_private_key = None
        self.client_public_key = None
        self.symmetric_key = None

    def handle_server_response(self, data):
        if self.state == ClientState.HANDSHAKE_INITIATED:
            print("Handshake initiated")
            # Expecting "hello Client" from server (text data)
            try:
                message = data.decode()  # Only decode if expecting text
                print(f"Received response: {message}")
                if message == "hello Client":
                    # Generate client's key pair
                    self.client_public_key, self.client_private_key = ecdh_public_private_gen()
                    serialized_public_key = serialize_public_key(self.client_public_key)
                    self.state = ClientState.HANDSHAKE_COMPLETED
                    print("Handshake completed")
                    return pickle.dumps(serialized_public_key)  # Send serialized public key
            except UnicodeDecodeError:
                print("Error decoding handshake message as text.")

        elif self.state == ClientState.HANDSHAKE_COMPLETED:
            # Expecting server's serialized public key (binary data)
            try:
                server_public_key = deserialize_public_key(*pickle.loads(data))
                #print(f"Server's public key (deserialized): {server_public_key}")

                # Generate symmetric key
                self.symmetric_key = ecdh_symmetric_key_gen(self.client_private_key, server_public_key)
                #print(f"Symmetric key = {self.symmetric_key}")
                self.state = ClientState.CONNECTED
                print("State = Connected")
                return "hello testing".encode()
            except Exception as e:
                print(f"Error during key exchange: {e}")

        elif self.state == ClientState.CONNECTED:
            # Encrypted communication
            try:
               return "hello testing".encode()
               #encrypted convo
            except Exception as e:
                print(f"Error during encrypted communication: {e}")
                self.state = ClientState.DISCONNECTED

        elif self.state == ClientState.DISCONNECTED:
            print("Disconnected from the server.")


class ClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, client_handler, on_con_lost):
        self.client_handler = client_handler
        self.on_con_lost = on_con_lost

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto("hello Server".encode(), ("127.0.0.1", 5000))

    def datagram_received(self, data, addr):
        print(f"Data received from server: {data}")
        response = self.client_handler.handle_server_response(data)
        if response:
            self.transport.sendto(response, addr)

    def error_received(self, exc):
        print(f"Error received: {exc}")

    def connection_lost(self, exc):
        print("Connection closed")


async def run_client():
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    client_handler = ClientHandler()
    # Create the datagram endpoint for the client
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(client_handler, on_con_lost),
        family=socket.AF_INET
    )
    try:
        await on_con_lost
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(run_client())
