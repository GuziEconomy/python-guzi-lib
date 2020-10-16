

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
    pass


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
