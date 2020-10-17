
def create_empty_init_blocks(birthdate, new_user_pub_key, ref_pub_key):
    """
    Return Block[]
    """
    pass

def fill_init_blocks(blocks, ref_priv_key):
    """
    Return Block[]
    """
    pass

def create_empty_block(prev_block):
    """
    Return Block
    """
    block = Block()
    block.previous_block_hash = prev_block.hash
    block.guzis = prev_block.guzis
    block.guzas = prev_block.guzas
    block.balance = prev_block.balance
    block.total = prev_block.total
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
    def __init__(self):
        self.version = 1
        self.close_date = None
        self.previous_block_hash = 0
        self.merkle_root = None
        self.signer = None
        self.guzis = 0
        self.guzas = 0
        self.balance = 0
        self.total = 0
        self.transactions = []
        self.engagements = []
        self.hash = None


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
