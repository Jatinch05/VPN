import random

# Miller-Rabin primality test
def is_prime(n, k=5):  # k is the number of iterations
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)  # Compute a^d % n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Function to generate a random prime number
def generate_prime(bits):
    while True:
        # Generate a random odd number of the given bit size
        candidate = random.getrandbits(bits) | 1
        if is_prime(candidate):
            return candidate

# GCD Function
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Modular Inverse Function with Loading Screen
def mod_inv(e, phi):
    print(f"Finding mod inverse for e = {e} and Euler's totient = {phi}", end="")

    # Calculate modular inverse
    for d in range(2, phi):
        if (e * d) % phi == 1:
            print(f"d = {d}")
            return d
    return -1

# RSA Function
def rsa():
    print("RSA encryption for exchange of symmetric key")

    # Generate two random 16-bit primes
    prime1 = generate_prime(16)
    prime2 = generate_prime(16)

    # Compute modulus and Euler's totient
    n = prime1 * prime2
    euler = (prime1 - 1) * (prime2 - 1)

    # Choose a random `e` coprime to Euler's totient
    while True:
        randomnumber = random.randint(2, euler)
        if gcd(randomnumber, euler) == 1:
            e = randomnumber
            break

    # Compute the modular inverse of `e`
    try:
        d = mod_inv(e, euler)
        if d == -1:
            raise ValueError("No modular inverse found")
    except ValueError as ex:
        print(ex)
        return None

    # Generate public and private keys
    public_key=(n,e)
    private_key=(n,d)
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    return public_key, private_key


def rsa_encryption(message, public_key):
    n, e = public_key
    # Convert the message to an integer (each character converted to ASCII)
    m = int.from_bytes(message.encode(), 'big')
    print(m)
    # Ensure the message is smaller than n
    if m >= n:
        raise ValueError("Message is too large for the RSA modulus. Consider using padding.")

    # Perform RSA encryption: c = m^e % n
    c = pow(m, e, n)
    return c


def rsa_decryption(encrypted_message, private_key):
    n, d = private_key
    # Perform RSA decryption: c^d % n
    decrypted_message_int = pow(encrypted_message, d, n)

    # Convert the decrypted integer back to bytes
    decrypted_message_bytes = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8,
                                                             byteorder='big')

    # Since the message was originally encoded as ASCII, we need to decode it back to a string
    decrypted_message = decrypted_message_bytes.decode('latin1')  # Using 'latin1' to handle byte-to-char conversion

    return decrypted_message
