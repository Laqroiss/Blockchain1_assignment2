import random
from hashlib import sha256

def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result
class RSA:
    @staticmethod
    def generate_keys():
        def is_prime(n):
            if n <= 1:
                return False
            for i in range(2, int(n**0.5) + 1):
                if n % i == 0:
                    return False
            return True

        def generate_prime():
            while True:
                prime = random.randint(100, 300)
                if is_prime(prime):
                    return prime

        p = generate_prime()
        q = generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)

        e = random.choice([i for i in range(2, phi) if is_prime(i) and phi % i != 0])
        d = pow(e, -1, phi)

        return (e, n), (d, n)

    @staticmethod
    def encrypt(public_key, message):
        e, n = public_key
        message_int = int.from_bytes(message.encode(), 'big')
        return mod_exp(message_int, e, n)

    @staticmethod
    def decrypt(private_key, ciphertext):
        d, n = private_key
        decrypted_int = mod_exp(ciphertext, d, n)
        return decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()

class DigitalSignature:
    @staticmethod
    def sign(private_key, document):
        document_hash = int(sha256(document.encode()).hexdigest(), 16)
        d, n = private_key
        return mod_exp(document_hash, d, n)

    @staticmethod
    def verify(public_key, document, signature):
        document_hash = int(sha256(document.encode()).hexdigest(), 16)
        e, n = public_key
        return document_hash == mod_exp(signature, e, n)

class Transaction:
    def __init__(self, sender, receiver, amount, signature):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "signature": self.signature
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.wallet_public_key = None

    def add_transaction(self, transaction):
        if self.verify_transaction(transaction):
            self.pending_transactions.append(transaction)

    def mine_block(self, miner_address):
        block = {
            "transactions": [t.to_dict() for t in self.pending_transactions],
            "miner": miner_address
        }
        self.chain.append(block)
        self.pending_transactions = []

    def verify_transaction(self, transaction):
        try:
            if not DigitalSignature.verify(transaction.sender, f"{transaction.receiver}:{transaction.amount}", transaction.signature):
                raise ValueError("Signature is wrong")
            return True
        except Exception as e:
            print(f"Transaction verification failed: {e}")
            return False

class Wallet:
    def __init__(self):
        self.public_key, self.private_key = RSA.generate_keys()

    def create_transaction(self, receiver, amount):
        message = f"{receiver}:{amount}"
        signature = DigitalSignature.sign(self.private_key, message)
        return Transaction(self.public_key, receiver, amount, signature)

if __name__ == "__main__":
    blockchain = Blockchain()
    wallet = Wallet()

    receiver_wallet = Wallet()

    transaction = wallet.create_transaction(receiver_wallet.public_key, 100)

    blockchain.add_transaction(transaction)

    blockchain.mine_block(wallet.public_key)

    for block in blockchain.chain:
        print(block)
