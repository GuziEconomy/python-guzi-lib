import hashlib
import ecdsa
import pytz
import umsgpack
from datetime import datetime, date
from enum import Enum



EMPTY_HASH = 0
ENDIAN = 'big'
VERSION = 1


def guzi_hash(data):
    return hashlib.sha256(data).digest()


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
                previous_block_signature=self[0].signature,
                signer=ref_pubkey,
                merkle_root=EMPTY_HASH,
                signature=EMPTY_HASH,
                guzis=0, guzas=0, balance=0, total=0)
        self.append(init_block)

    def validate(self, ref_privkey):
        birth_block = self[0]
        init_block = self[1]
        init_block.close_date = datetime.now(tz=pytz.utc)
        new_user_pub_key = birth_block.signer
        init_block.add_transaction(GuziCreationTransaction(new_user_pub_key, birth_block))
        init_block.add_transaction(GuzaCreationTransaction(new_user_pub_key, birth_block))
        init_block.compute_transactions(birth_block)
        init_block.compute_merkle_root()
        init_block.sign(ref_privkey)

    def save_to_file(self, outfile):
        """
        Save the content of the Blockchain to the given file
        """
        umsgpack.pack([b.pack() for b in self], outfile)

    def load_from_file(self, infile):
        hashed_blocks = umsgpack.unpack(infile)
        for b in hashed_blocks:
            block_as_list = umsgpack.unpackb(b)
            block = Block(*block_as_list)
            self.append(block)


class Packable:
    def pack(self):
        raise NotImplemented

    def pack_for_hash(self):
        raise NotImplemented


class Signable(Packable):
    def to_hash(self):
        return guzi_hash(self.pack_for_hash())

    def sign(self, privkey):
        """
        privkey : int
        return bytes
        """
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        self.signature = sk.sign(self.pack_for_hash())
        return self.signature


class Block(Signable):

    def __init__(self,
            version=1, close_date=None, previous_block_signature=None, merkle_root=None,
            signer=None, guzis=-1, guzas=-1, balance=-1, total=-1,
            b_transactions=None, b_engagements=None, signature=None):
        self.version = version
        self.close_date = datetime.utcfromtimestamp(close_date).replace(tzinfo=pytz.utc) if close_date else None
        self.previous_block_signature = previous_block_signature
        self.merkle_root = merkle_root
        self.signer = signer
        self.guzis = guzis
        self.guzas = guzas
        self.balance = balance
        self.total = total
        self.transactions = [Transaction(*umsgpack.unpackb(b_tx)) for b_tx in b_transactions] if b_transactions else []
        self.engagements = []
        self.signature = signature

    def __str__(self):
        return "v{} at {} by {}... [{},{},{},{}]".format(
                self.version, self.close_date,
                self.signer.hex()[:10],
                self.guzis, self.guzas, self.balance, self.total)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.pack() == other.pack()

    def add_transaction(self, tx):
        self.transactions.append(tx)

    def add_transactions(self, tx):
        for t in tx:
            self.add_transaction(t)

    def pack_for_hash(self):
        return umsgpack.packb([
            self.version, # Version
            self.close_date.timestamp() if self.close_date else 0,
            self.previous_block_signature,
            self.merkle_root,
            self.signer,
            self.guzis, 
            self.guzas,
            self.balance,
            self.total,
            len(self.transactions),
            len(self.engagements)
        ])

    def pack(self):
        return umsgpack.packb([
            self.version, # Version
            self.close_date.timestamp() if self.close_date else 0,
            self.previous_block_signature,
            self.merkle_root,
            self.signer,
            self.guzis, 
            self.guzas,
            self.balance,
            self.total,
            [t.pack() for t in self.transactions],
            [e.pack() for e in self.engagements],
            self.signature
        ])

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

    def compute_transactions(self, previous_block = None):
        self.guzis = previous_block.guzis if previous_block else 0
        for tx in self.transactions:
            if tx.tx_type == TxType.GUZI_CREATE.value:
                self.guzis += tx.amount
        self.guzas = previous_block.guzas if previous_block else 0
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
        self.previous_block_signature = EMPTY_HASH
        self.merkle_root = EMPTY_HASH
        self.sign(new_user_priv_key)


class Transaction(Signable):

    def __init__(self, version, tx_type, source, amount, tx_date=None,
            target_company="", target_user="", start_index=-1, end_index=-1,
            start_date=-1, end_date=-1, detail="", signature=None):
        self.version = version
        self.tx_type = tx_type
        self.date = datetime.utcfromtimestamp(tx_date).replace(tzinfo=pytz.utc) if tx_date else tx_date
        self.source = source
        self.amount = amount
        self.target_company = target_company
        self.target_user = target_user
        self.start_index = start_index
        self.end_index = end_index
        self.start_date = start_index
        self.end_date = end_date
        self.detail = detail
        self.signature = signature

    def __str__(self):
        return "{}, {}, {}, {}".format(self.tx_type, self.date, self.source, self.amount)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (self.version == other.version and
        self.tx_type == other.tx_type and
        self.date == other.date and
        self.source == other.source and
        self.amount == other.amount and
        self.target_company == other.target_company and
        self.target_user == other.target_user and
        self.start_index == other.start_index and
        self.end_index == other.end_index and
        self.start_date == other.start_date and
        self.end_date == other.end_date and
        self.detail == other.detail and
        self.signature == other.signature)

    def pack_for_hash(self):
        return umsgpack.packb([
            self.version,
            self.tx_type,
            self.date.timestamp(),
            self.source,
            self.amount,
            self.target_company,
            self.target_user,
            self.start_index,
            self.end_index,
            self.start_date,
            self.end_date,
            self.detail,
        ])

    def pack(self):
        return umsgpack.packb([
            self.version,
            self.tx_type,
            self.source,
            self.amount,
            self.date.timestamp(),
            self.target_company,
            self.target_user,
            self.start_index,
            self.end_index,
            self.start_date,
            self.end_date,
            self.detail,
            self.signature
        ])


class GuziCreationTransaction(Transaction):
    """

    A GuziCreationTransaction is a Transaction to create daily guzis for user
    by himself, to himself. It only depends of current block total accumulated
    value.

    """
    def __init__(self, owner, last_block):
        amount = 1 # TODO
        super().__init__(VERSION, TxType.GUZI_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc).timestamp())


class GuzaCreationTransaction(Transaction):
    """

    A GuzaCreationTransaction is a Transaction to create daily guzas for user
    by himself, to himself. It only depends of current block total accumulated
    value and birthday date, which must imply age > 18 years old.

    """
    # TODO : check age > 18
    def __init__(self, owner, last_block):
        amount = 1 # TODO
        super().__init__(VERSION, TxType.GUZA_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc).timestamp())
