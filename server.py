import socket
import pickle
#from RSA import rsa,rsa_decryption
from ECDH import ecdh_public_private_gen,ecdh_symmetric_key_gen,serialize_public_key,deserialize_public_key
from AES import aes_encrypt,aes_decrypt

def run_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("localhost", 5000))

    print("Server started listening on port 5000...")

    while True:
        # Receive data from the client
        data, client_addr = server_socket.recvfrom(1024)
        print(f"Received message: {data.decode()} from {client_addr}")

        # Send a response to the client
        server_socket.sendto(b"Hello, Client!", client_addr)

        # Receive public key from the client
        data, client_addr = server_socket.recvfrom(1024)
        try:
            # Unpickle the received public key
            client_public_key = pickle.loads(data)
            print(f"Client's public key: {client_public_key}")
        except Exception as e:
            print(f"Error unpickling data: {e}")
            continue

        print("Generating and sending the server's public key to the client...")
        # Generate server's public/private keys
        server_public_key, server_private_key = ecdh_public_private_gen()

        # Serialize the public key
        serialized_public_key = serialize_public_key(server_public_key)
        message = pickle.dumps(serialized_public_key)
        #sending client public keys
        server_socket.sendto(message, client_addr)
        print("sent public key")

        #deserialize client's public key
        client_public_key=deserialize_public_key(*client_public_key)
        # generating symmetric key
        symmetric_key=ecdh_symmetric_key_gen(server_private_key,client_public_key)
        print(f"symmetric key = {symmetric_key}") #256-bit shared secret key

        data,client_addr=server_socket.recvfrom(1024)
        decrypted_data=aes_decrypt(symmetric_key,data)
        print("decrypted data: ",decrypted_data)



if __name__ == "__main__":
    run_server()

