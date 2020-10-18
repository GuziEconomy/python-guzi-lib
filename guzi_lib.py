
def create_empty_init_blocks(birthdate, new_user_pub_key, ref_pub_key):
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
    birthday_block.previous_block_hash =  "0000000000000000000000000000000000000000000000000000000000000000"
    birthday_block.merkle_root =  "0000000000000000000000000000000000000000000000000000000000000000"
    init_block = Block()
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
        self.version = "01"
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
        hex_string = self.version
        hex_string += format(self.close_date.timestamp(), 'x')
        hex_string += self.previous_block_hash
        hex_string += self.merkle_root
        hex_string += self.signer
        hex_string += f"{self.guzis:0{4}x}"
        hex_string += f"{self.guzas:0{4}x}"
        hex_string += f"{self.balance:0{6}x}"
        hex_string += f"{self.total:0{8}x}"
        hex_string += 0000 #transactions
        hex_string += 0000 #engagements
        return hex_string

    def sign(self, privkey):
        hex_string = self.to_hex()
        byte_array = bytearray.fromhex(hex_string)
        hash = hashlib.sha256(byte_array).hexdigest()
        # Reste a signer ça


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
