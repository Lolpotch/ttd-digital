from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256


def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def sign_message(private_key_pem, message):
    private_key = RSA.import_key(private_key_pem)
    h = SHA3_256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)
    return signature, h.hexdigest()


def verify_signature(public_key_pem, message, signature):
    public_key = RSA.import_key(public_key_pem)
    h = SHA3_256.new(message.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True, h.hexdigest()
    except (ValueError, TypeError):
        return False, h.hexdigest()