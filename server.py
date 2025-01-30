import enum
import asyncio
import pickle
from ECDH import ecdh_public_private_gen, ecdh_symmetric_key_gen, serialize_public_key, deserialize_public_key
from AES import aes_encrypt, aes_decrypt


async def manage_client(transport, data, addr, client_handler):
    if client_handler.state == ClientState.HANDSHAKE_INITIATED:
        print("Handshake initiated")
        print(f"Received message from {addr}: {data.decode()}")
        transport.sendto("hello Client".encode(), addr)

        # Generate server's public/private key pair using ECDH
        server_public_key, server_private_key = ecdh_public_private_gen()

        # Store the private key in the client handler
        client_handler.server_private_key = server_private_key

        # Serialize the public key to send as (x, y) tuple
        serialized_public_key = serialize_public_key(server_public_key)
        #print(f"Serialized public key: {serialized_public_key}")

        # Convert the tuple into bytes using pickle
        serialized_public_key_bytes = pickle.dumps(serialized_public_key)
        #print(f"public key in bytes: {serialized_public_key_bytes}")

        # Send server's public key to the client
        transport.sendto(serialized_public_key_bytes, addr)
        #print("Sent public key to the client:", serialized_public_key)

        # Transition to HANDSHAKE_COMPLETED state
        client_handler.state = ClientState.HANDSHAKE_COMPLETED
        print("Handshake Completed")

    elif client_handler.state == ClientState.HANDSHAKE_COMPLETED:
        # Unserialize the client's public key and generate the shared symmetric key
        try:
            # Deserialize the received data directly (as (x, y) tuple)
            client_public_key = deserialize_public_key(*pickle.loads(data))  # Deserialize the pickled data
           # print(f"Client's public key (deserialized): {client_public_key}")
        except Exception as e:
            print(f"Error deserializing data: {e}")
            client_handler.state=ClientState.DISCONNECTED
            return  # Handle the error gracefully
        # Use the stored server_private_key
        server_private_key = client_handler.server_private_key
        if server_private_key is None:
            print("Server private key is missing!")
            client_handler.state=ClientState.DISCONNECTED
            return
        # Generate symmetric key using the ECDH method
        symmetric_key = ecdh_symmetric_key_gen(server_private_key, client_public_key)
        #print(f"Symmetric key = {symmetric_key}")  # 256-bit shared secret key
        client_handler.symmetric_key = symmetric_key
        # Transition to CONNECTED state
        client_handler.state = ClientState.CONNECTED
        print("State = Connected")

    elif client_handler.state == ClientState.CONNECTED:
        # Handle encrypted communication
        symmetric_key=client_handler.symmetric_key

        try:
          print(data.decode())
          #encrypted convo

        except Exception as e:
            print(f"Error handling encrypted communication: {e}")
            client_handler.state = ClientState.DISCONNECTED
            # Remove the client handler from the dictionary
            print()
            del Server_Protocol().client_handlers[addr]
        print("inside Connected")

    elif client_handler.state == ClientState.DISCONNECTED:
        print(f"Client {addr} has disconnected.")
        # Remove the client handler from the dictionary
        print(Server_Protocol().client_handlers[addr])
        del Server_Protocol().client_handlers[addr]

class ClientState(enum.Enum):
    HANDSHAKE_INITIATED = enum.auto()  # key sharing initiated
    HANDSHAKE_COMPLETED = enum.auto()  # sharing completed
    CONNECTED = enum.auto()  # client connected
    DISCONNECTED = enum.auto()  # client disconnected

class ClientHandler:
    def __init__(self, datagram_queue):
        self.state = ClientState.HANDSHAKE_INITIATED
        self.datagram_queue: asyncio.Queue[bytes] = datagram_queue #creating an asynchronous queue that stores bytes
        self.stopping = False
        self.server_private_key=None
        self.symmetric_key=None

    async def start(self):
        while not self.stopping:
            datagram = await self.datagram_queue.get()
            # Process datagram based on current state
            # This is just a placeholder; actual processing is done in manage_client
            pass

    async def __aenter__(self):#stopping set to false upon entering this Client handler class
        self.stopping = False
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):#stopping set to true upon exiting
        self.stopping = True

class Server_Protocol(asyncio.DatagramProtocol):  # datagram protocol already has datagram received functions
    def __init__(self):
        self.client_handlers = {}  # to store client addresses

    def connection_made(self, transport):
        self.transport = transport
        print("Server is running")

    def datagram_received(self, data, addr):
        print(f"Data received from {addr}: {data}")
        if addr not in self.client_handlers:  # new client detected
            datagram_queue = asyncio.Queue()
            client_handler = ClientHandler(datagram_queue)
            self.client_handlers[addr] = client_handler  # assigning a client_handler object to each addr
        print(self.client_handlers)
        # creating a task for each datagram received
        asyncio.create_task(manage_client(self.transport, data, addr, self.client_handlers[addr]))

    def connection_lost(self, exc):
        print("connection lost,error generated: ", exc)

    def error_received(self, exc):
        print("Connection lost,error received", exc)


async def run_server():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        protocol_factory=Server_Protocol,
        local_addr=('127.0.0.1', 5000)
    )
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(run_server())



# Explanation of asyncio.get_running_loop() usage:

# 1. Event Loop in `run_server()`:
#    The `run_server()` function is the main asynchronous coroutine that is executed by the event loop.
#    It does not need to explicitly retrieve the event loop using `asyncio.get_running_loop()`.
#    This is because `asyncio.run()` automatically manages the event loop when running the main coroutine (`run_server()`).
#    Inside `run_server()`, we wait for tasks like `manage_client()` to be scheduled and executed, and the event loop handles that for us.

# 2. Event Loop in `manage_client()`:
#    In contrast, `manage_client()` is an asynchronous task responsible for I/O operations (e.g., `sock_recvfrom` and `sock_sendto`),
#    which require non-blocking behavior and must be scheduled by the event loop.
#    Since `manage_client()` is called multiple times in parallel (once for each client interaction), it cannot manage the event loop itself.
#    Therefore, it needs to access the currently running event loop using `asyncio.get_running_loop()` to perform asynchronous I/O operations.

# Key Points:
# - `run_server()` is the entry point for the server and runs within the event loop. It doesn't need to explicitly fetch the running loop, as the event loop is already being managed by `asyncio.run()`.
# - `manage_client()` performs I/O tasks and needs access to the running event loop to handle non-blocking operations (e.g., receiving and sending data).

# Why the distinction?
# - `run_server()` is the top-level coroutine, responsible for scheduling tasks like `manage_client()`. As the main coroutine, it doesn't require direct interaction with the event loop.
# - `manage_client()` is a smaller coroutine within the event loop, and it needs to access the event loop to handle non-blocking I/O operations. This is why `asyncio.get_running_loop()` is called inside `manage_client()`.
