import hashlib
import ecdsa
import pytz
from datetime import datetime, date
from enum import Enum


EMPTY_HASH = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

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
    birthday_block.previous_block_hash = EMPTY_HASH
    birthday_block.merkle_root = EMPTY_HASH
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
    birth_block, init_block = blocks
    init_block.close_date = datetime.now(tz=pytz.utc)
    new_user_pub_key = birth_block.signer
    init_block.add_transaction(GuziCreationTransaction(new_user_pub_key, birth_block))
    init_block.add_transaction(GuzaCreationTransaction(new_user_pub_key, birth_block))
    init_block.compute_transactions()
    init_block.compute_merkle_root()
    init_block.sign(ref_priv_key)
    return blocks

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


class Signable:

    def to_hex(self):
        raise NotImplemented

    def to_hash(self):
        return hashlib.sha256(self.to_hex()).digest()

    def sign(self, privkey):
        """
        privkey : int
        return bytes
        """
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        self.hash = sk.sign(self.to_hex())
        self.hash_int = int.from_bytes(self.hash, byteorder='big', signed=False)
        return self.hash


class Block(Signable):

    def __init__(self,
            close_date=None, previous_block=None, signer=None,
            guzis=-1, guzas=-1, balance=-1, total=-1,
            transactions=None, engagements=None):
        self.version = 0x01
        self.close_date = close_date
        self.previous_block = previous_block if previous_block else None
        self.previous_block_hash = previous_block.hash if previous_block else None
        self.merkle_root = None
        self.signer = signer
        self.guzis = previous_block.guzis if previous_block else guzis
        self.guzas = previous_block.guzas if previous_block else guzas
        self.balance = previous_block.balance if previous_block else balance
        self.total = previous_block.total if previous_block else total
        self.transactions = transactions if transactions else []
        self.engagements = engagements if engagements else []
        self.hash = None
        self.hash_int = None

    def add_transaction(self, tx):
        self.transactions.append(tx)

    def to_hex(self):
        hex_result = self.version.to_bytes(1, byteorder='big')
        hex_result += int(self.close_date.timestamp()).to_bytes(4, byteorder='big')
        hex_result += self.previous_block_hash
        hex_result += self.merkle_root
        hex_result += self.signer
        hex_result += self.guzis.to_bytes(2, byteorder='big')
        hex_result += self.guzas.to_bytes(2, byteorder='big')
        hex_result += self.balance.to_bytes(3, byteorder='big')
        hex_result += self.total.to_bytes(4, byteorder='big')
        hex_result += len(self.transactions) .to_bytes(2, byteorder='big')#transactions count
        hex_result += (0).to_bytes(2, byteorder='big') #engagements count
        return hex_result
    
    def compute_merkle_root(self):
        self.merkle_root = self._tx_list_to_merkle_root(
            [t.to_hash() for t in self.transactions])
        return self.merkle_root

    def _tx_list_to_merkle_root(self, hashlist, firstcall=True):
        if len(hashlist) == 0:
            return None
        if len(hashlist) == 1:
            if firstcall:
                return self._hash_pair(hashlist[0], hashlist[0])
            else:
                return hashlist[0]
        else:
            # [h0, h1, h2] => [h0, h1, h2, h2]
            if len(hashlist) %2 == 1:
                hashlist.append(hashlist[-1])
            # [h0, h1, h2, h3] => [(h0, h1), (h2, h3)]
            hash_pairs = [(hashlist[i], hashlist[i + 1])  
                for i in range(0, len(hashlist), 2)]
            new_hashlist = [self._hash_pair(h0, h1)
                for h0, h1 in hash_pairs] 
            return self._tx_list_to_merkle_root(new_hashlist, False)

    def _hash_pair(self, hash0, hash1):
        return hashlib.sha256(hash0+hash1).digest()

    def compute_transactions(self):
        self.guzis = self.previous_block.guzis
        for tx in self.transactions:
            if tx.tx_type == TxType.GUZI_CREATE.value:
                self.guzis += tx.amount
        self.guzas = self.previous_block.guzas
        for tx in self.transactions:
            if tx.tx_type == TxType.GUZA_CREATE.value:
                self.guzas += tx.amount


class TxType(Enum):
    GUZI_CREATE = 0x00
    GUZA_CREATE = 0x01


class Transaction(Signable):

    def __init__(self, tx_type, source, amount, tx_date=None, target_company="", target_user="", start_index=-1, end_index=-1, start_date=-1, end_date=-1, detail=""):

        self.version = 1
        self.tx_type = tx_type
        self.date = tx_date
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


class GuziCreationTransaction(Transaction):
    """

    A GuziCreationTransaction is a Transaction to create daily guzis for user
    by himself, to himself. It only depends of current block total accumulated
    value.

    version : 01
    tx_type : 00
    date : creation date
    source : public key of owner
    amount : number of created guzis, depend of total accumulated of current
        block. amount = (total_accumulated)^(1/3) + 1
    hash of the transaction

    """
    def __init__(self, owner, last_block):
        amount = 1 # TODO
        super().__init__(TxType.GUZI_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc))

    def to_hex(self):
        hex_result = self.version.to_bytes(1, byteorder='big')
        hex_result += self.tx_type.to_bytes(1, byteorder='big')
        hex_result += int(self.date.timestamp()).to_bytes(4, byteorder='big')
        hex_result += self.source
        hex_result += self.amount.to_bytes(2, byteorder='big')
        return hex_result


class GuzaCreationTransaction(Transaction):
    """

    A GuzaCreationTransaction is a Transaction to create daily guzas for user
    by himself, to himself. It only depends of current block total accumulated
    value and birthday date, which must imply age > 18 years old.

    version : 01
    tx_type : 01
    date : creation date
    source : public key of owner
    amount : number of created guzis, depend of total accumulated of current
        block. amount = (total_accumulated)^(1/3) + 1
    hash of the transaction

    """
    # TODO : check age > 18
    def __init__(self, owner, last_block):
        amount = 1 # TODO
        super().__init__(TxType.GUZA_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc))

    def to_hex(self):
        hex_result = self.version.to_bytes(1, byteorder='big')
        hex_result += self.tx_type.to_bytes(1, byteorder='big')
        hex_result += int(self.date.timestamp()).to_bytes(4, byteorder='big')
        hex_result += self.source
        hex_result += self.amount.to_bytes(2, byteorder='big')
        return hex_result
