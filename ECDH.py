from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Function to generate public/private keys
def ecdh_public_private_gen():
    curve = ec.SECP256R1() #creates an elliptic curve with random G and n

    private_key_object = ec.generate_private_key(curve, default_backend())
    # Generate private key object , default backend helps in picking of random point on curve

   #private_key = private_key_object.private_numbers().private_value  # Get private key as integer if u want to print it

    public_key_object = private_key_object.public_key()  # Generate public key from private key

    #public_key = public_key_object.public_numbers()
    # public_key_x = public_key.x
    # public_key_y = public_key.y  if u want to print public key

    return public_key_object, private_key_object #returning cryptographic objects

def ecdh_symmetric_key_gen(receiver_private_key_object,sender_public_key_object):
    # Perform the ECDH key exchange
    shared_secret = receiver_private_key_object.exchange(ec.ECDH(), sender_public_key_object)
    #Share Secret key = receiver_private_key * (sender_public_key)

    #since the shared secret key might not be 256 bit
    # Derive a symmetric key using a hash function (e.g., SHA-256)
    shared_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    shared_key.update(shared_secret) #hashing the shared secret key
    derived_key = shared_key.finalize()

    return derived_key

# Convert the public key to x, y coordinates for serialization bcz pickle cant process cryptographic objects
def serialize_public_key(public_key_object):
    public_numbers = public_key_object.public_numbers() #Returns object with public keys x,y coordinates
    public_key=(public_numbers.x,public_numbers.y) #returning a tuple of  (x-cords,y-cords)
    return public_key

# Deserialize the public key from x, y coordinates
def deserialize_public_key(x, y):
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return public_numbers.public_key(default_backend())  # This will return the correct ECPublicKey object
