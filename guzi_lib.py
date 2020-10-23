import hashlib
import ecdsa

EMPTY_HASH = 0x0000000000000000000000000000000000000000000000000000000000000000

def create_empty_init_blocks(birthdate, new_user_pub_key, new_user_priv_key, ref_pub_key):
    """
    Return Block[]
    """
    birthday_block = Block(
            close_date=birthdate,
            signer=new_user_pub_key,
            guzis=0,
            guzas=0,
            balance=0,
            total=0)
    birthday_block.previous_block_hash =  EMPTY_HASH
    birthday_block.merkle_root =  EMPTY_HASH
    birthday_block.sign(new_user_priv_key)
    init_block = Block(
            previous_block=birthday_block,
            signer=ref_pub_key,
            guzis=0,
            guzas=0,
            balance=0,
            total=0)
    init_block.merkle_root =  EMPTY_HASH
    init_block.hash =  EMPTY_HASH
    return [birthday_block, init_block]

def fill_init_blocks(blocks, ref_priv_key):
    """
    Return Block[]
    """
    pass

def create_empty_block(previous_block):
    """
    Return Block
    """
    block = Block(previous_block=previous_block)
    return block

def create_transaction(tx_type, source, amount, target_company="", target_user="", start_index=-1, end_index=-1, start_date=-1, end_date=-1, detail=""):
    """
    Return Transaction
    """
    pass

def add_transaction_to_block(transaction, block):
    """
    Return Block
    """
    pass

def close_block(blockchain):
    """
    Return Block
    """
    pass

def calculate_merkle_root(block):
    """
    Return Hash
    """
    pass

def create_daily_guzis(last_block):
    pass

def send(blockchain, email):
    pass


class Block:
    def __init__(self,
            close_date=None, previous_block=None, signer=None,
            guzis=-1, guzas=-1, balance=-1, total=-1,
            transactions=[], engagements=[]):
        self.version = 0x01
        self.close_date = close_date
        self.previous_block_hash = previous_block.hash if previous_block else None
        self.merkle_root = None
        self.signer = signer
        self.guzis = previous_block.guzis if previous_block else guzis
        self.guzas = previous_block.guzas if previous_block else guzas
        self.balance = previous_block.balance if previous_block else balance
        self.total = previous_block.total if previous_block else total
        self.transactions = transactions
        self.engagements = engagements
        self.hash = None

    def to_hex(self):
        hex_result = f"{self.version:02x}"
        hex_result += f"{int(self.close_date.timestamp()):08x}"
        hex_result += f"{self.previous_block_hash:064x}"
        hex_result += f"{self.merkle_root:064x}"
        hex_result += f"{self.signer:066x}"
        hex_result += f"{self.guzis:04x}"
        hex_result += f"{self.guzas:04x}"
        hex_result += f"{self.balance:06x}"
        hex_result += f"{self.total:08x}"
        hex_result += f"{0:04x}" #transactions
        hex_result += f"{0:04x}" #engagements
        return hex_result

    def to_hash(self):
        hex_string = self.to_hex()
        byte_array = bytearray.fromhex(hex_string)
        return hashlib.sha256(byte_array).hexdigest()

    def sign(self, privkey):
        """
        privkey : int
        return bytes
        """
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(f"{privkey:064x}"), curve=ecdsa.SECP256k1)
        self.hash = sk.sign(self.to_hash().encode())
        return self.hash


class Transaction:
    def __init__(self, tx_type, source, amount, target_company="", target_user="", start_index=-1, end_index=-1, start_date=-1, end_date=-1, detail=""):

        sel.version = 1
        self.tx_type = tx_type
        self.source = source
        self.amount = amount
        self.target_company = target_company
        self.target_user = target_user
        self.start_index = start_index
        self.end_index = end_index
        self.start_date = start_index
        self.end_date = end_date
        self.detail = detail
        self.hash = ""
