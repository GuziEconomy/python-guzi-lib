import hashlib
import ecdsa
import pytz
import umsgpack
from datetime import datetime, date
from enum import Enum



EMPTY_HASH = 0
ENDIAN = 'big'


class TxType(Enum):
    GUZI_CREATE = 0x00
    GUZA_CREATE = 0x01


class Blockchain(list):
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if len(self) !=len(other):
                return False
            for b1, b2 in zip(self, other):
                if b1 != b2:
                    return False
            return True
        else:
            return False

    def start(self, birthdate, new_pubkey, new_privkey, ref_pubkey):
        self.append(BirthBlock(birthdate, new_pubkey, new_privkey))
        init_block = Block(
                previous_block=self[0],
                signer=ref_pubkey,
                guzis=0,
                guzas=0,
                balance=0,
                total=0)
        init_block.merkle_root =  EMPTY_HASH
        init_block.hash =  EMPTY_HASH
        self.append(init_block)

    def validate(self, ref_privkey):
        birth_block = self[0]
        init_block = self[1]
        init_block.close_date = datetime.now(tz=pytz.utc)
        new_user_pub_key = birth_block.signer
        init_block.add_transaction(GuziCreationTransaction(new_user_pub_key, birth_block))
        init_block.add_transaction(GuzaCreationTransaction(new_user_pub_key, birth_block))
        init_block.compute_transactions()
        init_block.compute_merkle_root()
        init_block.sign(ref_privkey)

    def save_to_file(self, outfile):
        """
        Save the content of the Blockchain to the given file
        """
        umsgpack.pack([bytes(b) for b in self], outfile)

    def load_from_file(self, infile):
        hashed_blocks = umsgpack.unpack(infile)
        for b in hashed_blocks:
            block = Block()
            block.from_bytes(b)
            self.append(block)


class Signable:
    def __bytes__(self):
        raise NotImplemented

    def to_hash(self):
        return hashlib.sha256(bytes(self)).digest()

    def sign(self, privkey):
        """
        privkey : int
        return bytes
        """
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        self.hash = sk.sign(bytes(self))
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

    def __str__(self):
        return "v{} at {} by {}... [{},{},{},{}]".format(
                self.version, self.close_date,
                self.signer.hex()[:10],
                self.guzis, self.guzas, self.balance, self.total)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.to_hash() == other.to_hash()

    def add_transaction(self, tx):
        self.transactions.append(tx)

    def __bytes__(self):
        return umsgpack.packb([
            1, # Type
            self.close_date.timestamp() if self.close_date else 0,
            self.previous_block_hash,
            self.merkle_root,
            self.signer,
            self.guzis, 
            self.guzas,
            self.balance,
            self.total,
            len(self.transactions),
            len(self.engagements)
        ])

    def from_bytes(self, bytes_):
        data = umsgpack.unpackb(bytes_)
        if not data[0] == 1:
            return
        self.close_date = datetime.utcfromtimestamp(data[1]) if data[1] else None
        self.previous_block_hash = data[2]
        self.merkle_root = data[3]
        self.signer = data[4]
        self.guzis = data[5]
        self.guzas = data[6]
        self.balance = data[7]
        self.total = data[8]
        self.transactions = []
        self.engagements = []

    
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


class BirthBlock(Block):
    def __init__(self, birthdate, new_user_pub_key, new_user_priv_key):
        super().__init__(
                close_date=birthdate,
                signer=new_user_pub_key,
                guzis=0, guzas=0,
                balance=0, total=0)
        self.previous_block_hash = EMPTY_HASH
        self.merkle_root = EMPTY_HASH
        self.sign(new_user_priv_key)


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

    def __bytes__(self):
        return umsgpack.packb([
            self.version,
            self.tx_type,
            self.date.timestamp(),
            self.source,
            self.amount
        ])


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

    def __bytes__(self):
        return umsgpack.packb([
            self.version,
            self.tx_type,
            self.date.timestamp(),
            self.source,
            self.amount
        ])
