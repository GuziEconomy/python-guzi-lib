import hashlib
import ecdsa
import pytz
import umsgpack
from datetime import datetime, date, time
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
class NotRemovableTransactionError(GuziError):
    pass
class InvalidBlockchainError(GuziError):
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

    def __init__(self, pubkey):
        self.pubkey = pubkey
        self.packer = BytePacker()
        self.last_spend_date = None
        self.last_spend_guzi = None

    def __eq__(self, other):
        if other is None:
            return False
        if isinstance(other, Blockchain):
            if len(self) !=len(other):
                return False
            for b1, b2 in zip(self, other):
                if b1 != b2:
                    return False
            return True
        else:
            return False

    def save_to_file(self, outfile):
        """
        Save the content of the Blockchain to the given file
        """
        self.packer.pack_bloockchain(self, outfile)

    def pack(self):
        return self.packer.pack_bloockchain(self)

    def as_email(self):
        pass

    def load_from_file(self, infile):
        hashed_blocks = umsgpack.unpack(infile)
        self._from_hashed_blocks(hashed_blocks)

    def load_from_bytes(self, b):
        hashed_blocks = umsgpack.unpackb(b)
        self._from_hashed_blocks(hashed_blocks)

    def _find_transaction(self, transaction):
        for block in self:
            if block._contain_transaction(transaction):
                return block
        return None

    def new_block(self):
        if len(self) > 0 and not self[0].is_signed():
            raise UnsignedPreviousBlockError
        block = Block()
        if len(self) > 0:
            previous_block = self[0]
            block.previous_block_signature = previous_block.signature
            block.balance = previous_block.balance
            block.total = previous_block.total
        else:
            block.balance = 0
            block.total = 0

        super().insert(0, block)

    def add_transaction_from_blockchain(self, blockchain):
        """Return None or refusal transaction

        1. Check the given blockchain
        2. Add the last transaction from this blockchain to itself
        3. Add random transactions from this blockchain to itself

        Return refusal transaction if blockchain is invalid

        Must check which tx_type transaction is to decide what to do with it.
        """
        pass

    def add_transaction(self, transaction):
        assert(isinstance(transaction, Transaction))
        self[0].add_transaction(transaction)

    def refuse_transaction(self, transaction):
        """Return a refusal transaction

        If transaction was already added, remove it from current block.
        If transaction was already sealed, raise Error
        """
        block_with_tx = self._find_transaction(transaction)
        if block_with_tx is None:
            pass
        elif block_with_tx != self[0]:
            raise NotRemovableTransactionError
        else:
            if self[0].is_signed():
                raise NotRemovableTransactionError
            self[0]._remove_transaction(transaction)
        return Transaction(VERSION, TxType.REFUSAL.value,
                source=transaction.target_user,
                amount=transaction.amount,
                tx_date=datetime.now(tz=pytz.utc).timestamp(),
                target_user=transaction.source,
                detail=transaction.signature)

    @staticmethod
    def is_valid(blockchain):
        """Return boolean

        True if given blockchain seems valid
        False if an incoherence was detected
        """
        pass

    def sign_last_block(self, privkey):
        self[0].close_date = datetime.now(tz=pytz.utc)
        self[0].sign(privkey)

    def _reduce(self, pubkey):
        for index, block in list(enumerate(self)):
            if block._containUser(pubkey):
                return self[:index+1]
        return self

    def _reduce_to_date(self, date):
        for index, block in list(enumerate(self)):
            if block.close_date is not None and block.close_date.date() < date:
                return self[:index]
        return self

    def _from_hashed_blocks(self, hashed_blocks):
        for b in hashed_blocks:
            block_as_list = umsgpack.unpackb(b)
            block = Block(*block_as_list)
            self.append(block)


class UserBlockchain(Blockchain):

    def start(self, birthdate, my_privkey, ref_pubkey):
        self.clear()
        self.insert(0, BirthBlock(birthdate, self.pubkey, my_privkey))
        init_block = Block(
                previous_block_signature=self[0].signature,
                signer=ref_pubkey,
                merkle_root=EMPTY_HASH)
        self.insert(0, init_block)

    def validate(self, ref_privkey):
        init_block = self[0]
        init_block.balance = 0
        init_block.total = 0
        init_block.close_date = datetime.now(tz=pytz.utc)
        init_block.guzi_index = (init_block.close_date.isoformat(), 0)
        init_block.guza_index = (init_block.close_date.isoformat(), 0)
        self.make_daily_guzis()
        self.make_daily_guzas()
        init_block.compute_merkle_root()
        init_block.sign(ref_privkey)

    def _get_guzis_amount(self):
        n = self[0].total
        if n < 0:
            raise InvalidBlockchainError("Total can never be negative")
        floatroot = (n ** (1.0 / 3.0))
        introot = int(round(floatroot))
        if introot*introot*introot == n:
            return introot + 1
        return introot

    def make_daily_guzis(self, dt=None):
        """ Return int number of guzis availables

        A Guzi Creation Transaction is done by a user to himself, creating his own
        Guzis. This transaction only contains date, user id and the amount of
        created guzis.
        A user must create (total)^(1/3)+1 Guzis/day (rounded down)
        """
        amount = self._get_guzis_amount()
        if dt is None:
            dt = datetime.now(tz=pytz.utc)
        guzis = [[dt.date().isoformat(), list(range(amount))]]
        self.add_transaction(Transaction(VERSION, TxType.GUZI_CREATE.value, self.pubkey, amount, tx_date=dt.timestamp(), guzis_positions=guzis))
        if self.last_spend_date is None:
            self.last_spend_date = dt.date()
        return self[0].transactions[0]

    def make_daily_guzas(self, dt=None):
        # TODO : check age > 18
        """ Return int number of guzas availables

        A Guza Creation Transaction is done by a user to himself, creating his own
        Guzas. This transaction only contains date, user id and the amount of
        created guzas.
        A user must create (total)^(1/3)+1 Guzas/day (rounded down)
        """
        amount = self._get_guzis_amount()
        if dt is None:
            dt = datetime.now(tz=pytz.utc)
        guzas = [[dt.date().isoformat(), list(range(amount))]]
        self.add_transaction(Transaction(VERSION, TxType.GUZA_CREATE.value, self.pubkey, amount, tx_date=dt.timestamp(), guzis_positions=guzas))
        return self[0].transactions[0]

    def pay_to_user(self, target, amount):
        """Return Transaction to pay given target with amount Guzis

        Also add this Transaction to itself
        """
        guzis_positions = self._get_available_guzis(amount)
        tx = Transaction(
            VERSION,
            TxType.PAYMENT.value,
            self.pubkey,
            amount,
            tx_date=datetime.now(tz=pytz.utc).timestamp(),
            target_user=target,
            guzis_positions=guzis_positions
        )
        self._spend_guzis_from_availables(guzis_positions, amount)
        self.add_transaction(tx)
        return tx

    def pay_to_company(self, target, amount):
        pass

    def engage_guzis_to_user(self, target, days, daily_amount):
        pass

    def engage_guzis_to_company(self, target, days, daily_amount):
        pass

    def engage_guzas(self, target, days, daily_amount):
        pass

    def _get_available_guzis(self, amount=-1):
        """Return amount number of first available Guzis

        If amount=-1, return all available guzis
        """
        result = []
        for b in self:
            result += b._get_available_guzis(self.last_spend_date, self.last_spend_guzi)
        return result

    def _spend_guzis_from_availables(self, available_guzis, amount):
        """Update last_spend_guzi and last_spend_date

        depending on given available_guzis
        """
        to_spend = amount
        for row in reversed(available_guzis):
            if len(row[1]) > to_spend:
                self.last_spend_guzi = row[1][-1*to_spend]
                to_spend = 0
            else:
                to_spend -= len(row[1])
                self.last_spend_guzi = 0
            if to_spend == 0:
                self.last_spend_date = date.fromisoformat(row[0])


class CompanyBlockchain(Blockchain):

    def start(self, creator_pubkey, roles):
        """Return None

        Raise an error if no admin is given in roles
        Raise an error if no owner is given in roles
        """
        pass

    def add_transaction(self, blockchain):
        """Return Transaction or None

        Mus handle multiple cases :
        - payment given
        - engagement given
        """
        pass

    def obey_order(self, order):
        """Return Transaction"""
        pass

    def refuse_transaction(self, transaction):
        """Return Transaction"""
        pass


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
                self.guzi_index, self.guza_index, self.balance, self.total)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return other is not None and isinstance(other, Block) and self.pack() == other.pack()

    def add_transaction(self, tx):
        if self.is_signed():
            raise FullBlockError
        if len(self.transactions) >= MAX_TX_IN_BLOCK:
            raise FullBlockError
        if tx not in self.transactions:
            self.transactions.insert(0, tx)

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

    def as_email(self):
        pass

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

    def _contain_transaction(self, transaction):
        return transaction in self.transactions

    def _remove_transaction(self, transaction):
        self.transactions.remove(transaction)

    def _containUser(self, pubkey):
        for t in self.transactions:
            if pubkey in (t.target_user, t.target_company, t.source):
                return True
        return False

    def _get_available_guzis(self, last_spend_date, last_spend_guzi):
        result = []
        for tx in self.transactions:
            if tx.date.date() >= last_spend_date and tx.tx_type == TxType.GUZI_CREATE.value:
                result += tx.guzis_positions
                if tx.date.date() == last_spend_date:
                    result[-1][1] = result[-1][1][:last_spend_guzi]
                    if len(result[-1][1]) == 0:
                        result.pop()
        return result


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
            target_company=None, target_user=None, guzis_positions=[], detail=None, signature=None):
        self.version = version
        self.tx_type = tx_type
        self.date = datetime.utcfromtimestamp(tx_date).replace(tzinfo=pytz.utc) if tx_date else datetime.now()
        self.source = source
        self.amount = int(amount)
        self.target_company = target_company
        self.target_user = target_user
        self.guzis_positions = guzis_positions
        self.detail = detail
        self.signature = signature

        self.packer = BytePacker()

    def __str__(self):
        return "{}, {}, {}, {}, {}".format(self.tx_type, self.date, self.source.hex()[:10], self.amount, self.guzis_positions)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (other is not None and
                isinstance(other, Transaction) and
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

    def as_email(self):
        pass


class Company:

    def __init__(self, company_pubkey, my_pubkey):
        pass

    def set_owner_order(self, my_privkey, owner, value, detail=""):
        pass

    def set_admin_order(self, my_privkey, admin, value, detail=""):
        pass

    def set_worker_order(self, my_privkey, worker, value, detail=""):
        pass

    def set_payer_order(self, my_privkey, payer, value, detail=""):
        pass

    def leave_order(self, my_privkey, detail=""):
        pass

    def pay_order(self, my_privkey, target, amount):
        pass


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
        return [(tx_date.isoformat(),list(range(amount)))]


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