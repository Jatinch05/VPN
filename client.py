import socket
#from RSA import rsa, rsa_encryption
from ECDH import ecdh_public_private_gen,ecdh_symmetric_key_gen,serialize_public_key,deserialize_public_key
from AES import aes_encrypt,aes_decrypt
import pickle

def run_client():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Started, sent Hello")

    # Message to be sent to the server
    message = "Hello, Server!"
    client_socket.sendto(message.encode(), ("localhost", 5000))

    # Receive the response from the server
    data, server_addr = client_socket.recvfrom(1024)
    print("Received from server:", data.decode())

    # generating public and private keys
    print("Sending Public Key to server...")
    public_key, private_key = ecdh_public_private_gen()
    # Serialize the public key
    serialized_public_key = serialize_public_key(public_key)
    message = pickle.dumps(serialized_public_key)
    #sending server public keys
    client_socket.sendto(message,server_addr)

    data, server_addr = client_socket.recvfrom(1024)  # Receive server's public key
    try:
        # Unpickle the received data
        server_public_key = pickle.loads(data)
        print(f"Received server's public key: {server_public_key}")
    except Exception as e:
        print(f"Error unpickling data: {e}")
        server_public_key=(0,0)
        exit(0)

    #deserialize server's public key
    server_public_key=deserialize_public_key(*server_public_key)
    # generating symmetric key
    symmetric_key=ecdh_symmetric_key_gen(private_key,server_public_key)

    print(f"symmetric key = {symmetric_key}") #256-bit shared secret key

    #encrypted conversation using shared secret key and AES
    message=input("enter message: ")
    encrypted_message=aes_encrypt(symmetric_key,message)
    client_socket.sendto(encrypted_message,server_addr)


    # Close the client socket
    client_socket.close()

if __name__ == "__main__":
    run_client()
