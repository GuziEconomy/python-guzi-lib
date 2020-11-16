import hashlib
import ecdsa
import pytz
import umsgpack
from datetime import datetime, date
from enum import Enum



EMPTY_HASH = 0
VERSION = 1
MAX_TX_IN_BLOCK = 30


###########################################################
# USEFULL CLASSES AND FUNCTIONS
###########################################################
def guzi_hash(data):
    return hashlib.sha256(data).digest()


class TxType(Enum):

    GUZI_CREATE = 0x00
    GUZA_CREATE = 0x01
    PAYMENT = 0x02
    GUZI_ENGAGEMENT = 0x03
    GUZA_ENGAGEMENT = 0x04
    REFUSAL = 0x05
    OWNER_SET = 0x10
    ADMIN_SET = 0x11
    WORKER_SET = 0x12
    PAYER_SET = 0x13
    PAY_ORDER = 0x14
    LEAVE_ORDER = 0x15



class GuziError(Exception):
    """ Base class for Guzi exceptions """
    pass


class UnsignedPreviousBlockError(GuziError):
    pass


class FullBlockError(GuziError):
    pass


class Packer:
    def pack_transaction(self, transaction):
        return NotImplemented

    def pack_transaction_without_hash(self, transaction):
        return NotImplemented

    def pack_block(self, block):
        return NotImplemented

    def pack_block_without_hash(self, block):
        return NotImplemented

    def pack_bloockchain(self, blockchain, outfile=None):
        return NotImplemented


class BytePacker(Packer):

    def pack_transaction(self, transaction):
        return umsgpack.packb(transaction.as_full_list())

    def pack_transaction_without_hash(self, transaction):
        return umsgpack.packb(transaction.as_list())

    def pack_block(self, block):
        return umsgpack.packb(block.as_full_list())

    def pack_block_without_hash(self, block):
        return umsgpack.packb(block.as_list())

    def pack_bloockchain(self, blockchain, outfile=None):
        if outfile is not None:
            umsgpack.pack([b.pack() for b in blockchain], outfile)
        else:
            return umsgpack.packb([b.pack() for b in blockchain])


class Packable:
    def pack_for_hash(self):
        return NotImplemented


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


###########################################################
# MODEL CLASSES
###########################################################


class Blockchain(list):
    """
    """
    def __init__(self):
        self.packer = BytePacker()

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
                merkle_root=EMPTY_HASH)
        self.append(init_block)

    def validate(self, ref_privkey):
        birth_block = self[0]
        init_block = self[1]
        init_block.close_date = datetime.now(tz=pytz.utc)
        new_user_pub_key = birth_block.signer
        init_block.add_transaction(GuziCreationTransaction(new_user_pub_key))
        init_block.add_transaction(GuzaCreationTransaction(new_user_pub_key))
        init_block.guzi_index = (init_block.close_date.isoformat(), 0)
        init_block.guza_index = (init_block.close_date.isoformat(), 0)
        init_block.compute_merkle_root()
        init_block.sign(ref_privkey)

    def save_to_file(self, outfile):
        """
        Save the content of the Blockchain to the given file
        """
        self.packer.pack_bloockchain(self, outfile)

    def pack(self):
        return self.packer.pack_bloockchain(self)

    def load_from_file(self, infile):
        hashed_blocks = umsgpack.unpack(infile)
        self._from_hashed_blocks(hashed_blocks)

    def load_from_bytes(self, b):
        hashed_blocks = umsgpack.unpackb(b)
        self._from_hashed_blocks(hashed_blocks)

    def new_block(self):
        if len(self) > 0 and not self[-1].is_signed():
            raise UnsignedPreviousBlockError
        block = Block()
        if len(self) > 0:
            block.previous_block_signature = self[-1].signature
        super().append(block)

    def add_transaction(self, transaction):
        assert(isinstance(transaction, Transaction))
        self[-1].add_transaction(transaction)

    def guzis(self):
        """ Return int number of guzis availables """
        pass

    def guzas(self):
        """ Return int number of guzas availables """
        pass

    def _reduce(self, pubkey):
        for index, block in reversed(list(enumerate(self))):
            if block._containUser(pubkey):
                return self[index:]

    def _from_hashed_blocks(self, hashed_blocks):
        for b in hashed_blocks:
            block_as_list = umsgpack.unpackb(b)
            block = Block(*block_as_list)
            self.append(block)

    def sign_last_block(self, privkey):
        self[-1].sign(privkey)

    def find_block_by_date(self, date):
        for index, block in reversed(list(enumerate(self))):
            if block.close_date is not None and block.close_date.date() < date:
                return self[index+1]

    def get_next_guzis(self, amount):
        block = self.cursor_block
        tx = self.cursor_tx
        guzi = self.cursor_guzi
        return []


class Block(Signable):

    def __init__(self,
            version=VERSION, close_date=None, previous_block_signature=None, merkle_root=None,
            signer=None, guzi_index=None, guza_index=None, balance=None, total=None,
            b_transactions=None, b_engagements=None, signature=None):
        self.version = version
        self.close_date = datetime.utcfromtimestamp(close_date).replace(tzinfo=pytz.utc) if close_date else None
        self.previous_block_signature = previous_block_signature
        self.merkle_root = merkle_root
        self.signer = signer
        self.guzi_index = guzi_index
        self.guza_index = guza_index
        self.balance = balance
        self.total = total
        self.transactions = [Transaction(*umsgpack.unpackb(b_tx)) for b_tx in b_transactions] if b_transactions else []
        self.engagements = []
        self.signature = signature

        self.packer = BytePacker()

    def __str__(self):
        return "v{} at {} by {}... [{},{},{},{}]".format(
                self.version, self.close_date,
                self.signer.hex()[:10] if self.signer else "unsigned",
                self.guzis(), self.guzas(), self.balance, self.total)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return isinstance(other, Block) and self.pack() == other.pack()

    def add_transaction(self, tx):
        if self.is_signed():
            raise FullBlockError
        if len(self.transactions) >= MAX_TX_IN_BLOCK:
            raise FullBlockError
        if tx not in self.transactions:
            self.transactions.append(tx)

    def add_transactions(self, tx):
        for t in tx:
            self.add_transaction(t)

    def find_transaction(self, tx_type, date):
        """
        Return the transaction of given tx_type with given signature date
        If no transaction is found, return None
        """
        for t in self.transactions:
            if tx_type == t.tx_type and date == t.date.date():
                return t
        return None

    def as_list(self):
        return [
            self.version,
            self.close_date.timestamp() if self.close_date else 0,
            self.previous_block_signature,
            self.merkle_root,
            self.signer,
            self.guzi_index, 
            self.guza_index,
            self.balance,
            self.total,
            len(self.transactions),
            len(self.engagements)
        ]

    def as_full_list(self):
        l = self.as_list()[:-2]
        l += [
            [t.pack() for t in self.transactions],
            [e.pack() for e in self.engagements],
            self.signature
        ]
        return l

    def pack_for_hash(self):
        return self.packer.pack_block_without_hash(self)

    def pack(self):
        return self.packer.pack_block(self)

    def compute_merkle_root(self):
        self.merkle_root = self._tx_list_to_merkle_root(
            [t.to_hash() for t in self.transactions])
        return self.merkle_root

    #def compute_transactions(self, previous_block = None):
    #    self.guzis = 
    #    for tx in self.transactions:
    #        if tx.tx_type == TxType.GUZI_CREATE.value:
    #            self.guzis += tx.amount
    #    self.guzas = previous_block.guzas if previous_block else 0
    #    for tx in self.transactions:
    #        if tx.tx_type == TxType.GUZA_CREATE.value:
    #            self.guzas += tx.amount

    def is_signed(self):
        return self.signature is not None

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

    def _containTx(self, transaction):
        return transaction in self.transactions

    def _containUser(self, pubkey):
        for t in self.transactions:
            if pubkey in (t.target_user, t.target_company, t.source):
                return True
        return False


class BirthBlock(Block):

    def __init__(self, birthdate, new_user_pub_key, new_user_priv_key):
        super().__init__(
                close_date=birthdate,
                signer=new_user_pub_key)
        self.previous_block_signature = EMPTY_HASH
        self.merkle_root = EMPTY_HASH
        self.sign(new_user_priv_key)


class Transaction(Signable):

    def __init__(self, version, tx_type, source, amount, tx_date=None,
            target_company="", target_user="", guzis_positions=[], detail="", signature=None):
        self.version = version
        self.tx_type = tx_type
        self.date = datetime.utcfromtimestamp(tx_date).replace(tzinfo=pytz.utc) if tx_date else tx_date
        self.source = source
        self.amount = amount
        self.target_company = target_company
        self.target_user = target_user
        self.guzis_positions = guzis_positions
        self.detail = detail
        self.signature = signature

        self.packer = BytePacker()

    def __str__(self):
        return "{}, {}, {}, {}".format(self.tx_type, self.date, self.source, self.amount)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (isinstance(other, Transaction) and
                self.version == other.version and
                self.tx_type == other.tx_type and
                self.date == other.date and
                self.source == other.source and
                self.amount == other.amount and
                self.target_company == other.target_company and
                self.target_user == other.target_user and
                self.guzis_positions == other.guzis_positions and
                self.detail == other.detail and
                self.signature == other.signature)

    def as_list(self):
        return [
            self.version,
            self.tx_type,
            self.source,
            self.amount,
            self.date.timestamp(),
            self.target_company,
            self.target_user,
            self.guzis_positions,
            self.detail,
        ]

    def as_full_list(self):
        l = self.as_list()
        l.append(self.signature)
        return l

    def pack_for_hash(self):
        return self.packer.pack_transaction_without_hash(self)

    def pack(self):
        return self.packer.pack_transaction(self)


class GuziCreationTransaction(Transaction):

    """
    A GuziCreationTransaction is done by a user to himself, creating his own
    Guzis. This transaction only contains date, user id and the amount of
    created guzis.
    A user can create (total)^(1/3)+1 Guzis/day
    """
    def __init__(self, owner, total=0):
        amount = 1 + total**(1/3)
        super().__init__(VERSION, TxType.GUZI_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc).timestamp())


class GuzaCreationTransaction(Transaction):

    """
    A GuzaCreationTransaction is done by a user to himself, creating his own
    Guzas. This transaction only contains date, user id and the amount of
    created guzas.
    A user can create (total)^(1/3)+1 Guzas/day
    """
    # TODO : check age > 18
    def __init__(self, owner, total=0):
        amount = 1 + total**(1/3)
        super().__init__(VERSION, TxType.GUZA_CREATE.value, owner, amount, tx_date=datetime.now(tz=pytz.utc).timestamp())


class PaymentTransaction(Transaction):

    """
    This is the MAIN transaction. When a user spend guzis to another one or
    to a company ; or from a company to another one.
    """
    def __init__(self, last_block, source, target, amount, is_company_target=False, detail=None):
        tx_date = datetime.now(tz=pytz.utc)
        target_company = target if is_company_target is not None else None
        target_user = target if is_company_target is None else None
        guzis_positions = self.get_guzi_positions(last_block, amount)

        super().__init__(
                VERSION, TxType.PAYMENT.value, source, amount,
                tx_date=tx_date.timestamp() ,
                target_company=target_company,
                target_user=target_user,
                guzis_positions=guzis_positions,
                detail=detail
                )

    def get_guzi_positions(self, current_block, amount):
        i = current_block.guzi_index
        return [([str(tx_date.year)+str(tx_date.month)+str(tx_date.day)],list(range(amount)))]



class GuziEngagementTransaction(Transaction):

    """
    An Engagement is what we usually call in classical money systems a loan.
    It's a contract sealed in the blockchain saying "I commit to pay X Guzis
    each day during Y days for a total amount of Z=X*Y"
    """
    pass


class GuzaEngagementTransaction(Transaction):

    """
    An Engagement is what we usually call in classical money systems a loan.
    It's a contract sealed in the blockchain saying "I commit to pay X Guzas
    each day during Y days for a total amount of Z=X*Y"
    """
    pass


class RefusedTransaction(Transaction):

    """
    A user has 15 days to refuse a transaction, unless he adds it to his 
    blockchain in which case he cannot refuse it anymore.
    When Alice receives a payment transaction and refuses it, she neither adds
    the payment transaction nor the refusing one to her blockchain. But the
    sender of the payment transaction must add the refusing transaction as
    proof that he can refund his account with refused guzis.
    """
    pass


class OwnerSetTransaction(Transaction):

    """
    Owners of a company are users who gets guzis earned by the company in
    excess of the workers' salaries. Every 25 of each month, the company
    must send the guzis to each owner (with setted pro rata).
    """
    pass


class AdminSetTransaction(Transaction):

    """
    Admins are users who can modify roles of a company.
    There cannot have no admin for a company.
    """
    pass


class WorderSetTransaction(Transaction):

    """
    Workers are users who get a salary for their job in a company. Every 25 of
    each month, the company must send the setted value to each worker (or the
    maximum it can in case of guzi diet).
    """
    pass


class PayerSetTransaction(Transaction):

    """
    Payers are users who can send payment orders to the company.
    """
    pass


class PaymentOrderTransaction(Transaction):

    """
    As a company does not have it's own will, it must obey some users to know
    which other company it has to pay. This is why PaymentOrders are here.
    A user being payer in a company can send it payment order. The company
    will then send the payment to the given target or return an error message.
    """
    pass


class LeavingOrderTransaction(Transaction):

    """
    Any user can, at any moment, leave a company he has a role in,
    except if he is the last admin. There must always be at least one admin
    in a company. So if he really wants to leave, he can set anyone as admin of
    the company and then leave. In some case, that could be funny, in fact.
    """
    pass
