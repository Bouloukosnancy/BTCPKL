import base58
import hashlib
from OpenSSL import crypto

def load_p12_file(file_path):
    with open(file_path, 'rb') as f:
        p12_data = crypto.load_pkcs12(f.read())
    return p12_data

def extract_key_and_cert(p12):
    privatekey = p12.get_privatekey()
    cert = p12.get_certificate()
    return privatekey, cert

def get_private_key_from_address(address, api_key_file):
    # Decode the Bitcoin address
    decoded = base58.b58decode(address)

    # Remove the first and last bytes (version bytes)
    stripped_bytes = decoded[1:-1]

    # Perform SHA-256 hashing
    sha256_1 = hashlib.sha256(stripped_bytes).hexdigest()

    # Perform SHA-256 hashing again
    sha256_2 = hashlib.sha256(sha256_1).hexdigest()

    # Take the first 32 bytes (256 bits) as the private key
    private_key = sha256_2[:32]

    # Load the API key file
    p12 = load_p12_file(api_key_file)

    # Extract the private key and certificate
    private_key_obj, _ = extract_key_and_cert(p12)

    # Check if the private key matches the calculated private key
    if private_key_obj.export_key(format='DER') == private_key:
        # Confirm the HASH160 of the address
        decoded_bytes = base58.b58decode(address)
        hash160 = decoded_bytes[1:-1]
        hash160_str = hash160.hex()
        print("HASH160 confirmed:", hash160_str)
        return private_key
    else:
        print("Private key verification failed.")
        return None

# Prompt the user to enter a Bitcoin address
address = input("Enter Bitcoin address: ")
api_key_file = "/path/to/api/key.pfx"
private_key = get_private_key_from_address(address, api_key_file)
print("Private Key:", private_key)
