import asyncio
import enum
import socket
import pickle
from ECDH import ecdh_public_private_gen, ecdh_symmetric_key_gen, serialize_public_key, deserialize_public_key

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.events import (
 HandshakeCompleted,
 ConnectionTerminated,
 ConnectionIdIssued,
 StreamReset,
 DatagramFrameReceived,
 StreamDataReceived,
 ConnectionIdRetired,
 PingAcknowledged,
 ProtocolNegotiated,
 StopSendingReceived,
)
from aioquic.quic.logger import QuicLogger
from dataclasses import dataclass

@dataclass
class UnknownFrameReceived(QuicEvent):
    """
    Event triggered when unknown frame type is received
    """
    frame_type : int
    raw_data : bytes

class CustomQuicProtocol(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super.__init__(*args,**kwargs)
        self.logger=QuicLogger()

    def quic_event_received(self, event):
        if isinstance(event,HandshakeCompleted):
            print("Handshake Completed!")
            self._quic.send_stream_data(self._quic.get_next_available_stream_id(),b"hello server!")

        elif isinstance(event,ConnectionTerminated):
            print("Connection Terminated",event.error_code)

        elif isinstance(event,DatagramFrameReceived):
            print(f"Datagram received: {event.data.decode()} ")

        elif isinstance(event,UnknownFrameReceived):
            print(f"Unknown frame type:({event.frame_type}) arrived with data: {event.raw_data.decode()}")

        elif isinstance(event,ConnectionTerminated):
            print(f"Connection closed error:{event.error_code}")
            print(f"Connection termination frame type:{event.frame_type}, reason : {event.reason_phrase}")

        elif isinstance(event,PingAcknowledged):
            print(f"unique id of ping :{event.uid}")

        elif isinstance(event,ProtocolNegotiated):
            print(f"ALPN protocol : {event.alpn_protocol}")

        elif isinstance(event,StopSendingReceived):
            print(f"error code:{event.error_code}")

        elif isinstance(event,StreamDataReceived):
            print(f"Stream received:{event.data} from {event.stream_id}")
            if event.end_stream:
                print("End of stream received")

        elif isinstance(event,StreamReset):
            print(f"{event.stream_id} stream restarted ,error:{event.error_code} ")


    def send_custom_data(self):#for sending control messages
        stream_id=self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id,b"control stmts",end_stream=True)#unidirectional control message

    def send_datagram(self,data):
        self._quic.send_datagram_frame(data)



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
    configuration=QuicConfiguration(is_client=False)
    configuration.alpn_protocols = ["h3", "hq-29"]  # Example 9: ALPN protocols
    configuration.congestion_control_algorithm = "cubic"  # Example 10: Congestion control
    configuration.quic_logger = QuicLogger()  # Example 11: Logging QUIC events
    configuration.load_cert_chain(certfile="cert.pem", keyfile="key.pem")  # Example 12: TLS setup

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

    async with connect("localhost", 4433, configuration=configuration, create_protocol=CustomQuicProtocol) as protocol:
        protocol: CustomQuicProtocol

        # Send custom data
        protocol.send_custom_data()

        # Send datagram
        protocol.send_datagram(b"Custom datagram data")

        # Wait for events
        await asyncio.sleep(10)  # Keep connection open to receive responses


if __name__ == "__main__":
    asyncio.run(run_client())
