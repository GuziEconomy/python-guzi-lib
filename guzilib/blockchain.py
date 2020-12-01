import umsgpack
from guzilib.crypto import guzi_hash, Signable, unzip_positions, EMPTY_HASH
from guzilib.packer import BytePacker
from guzilib.errors import FullBlockError, NegativeAmountError, UnsignedPreviousBlockError, InsufficientFundsError, InvalidBlockchainError, NotRemovableTransactionError
import pytz
from datetime import date
from enum import Enum

VERSION = 1
MAX_TX_IN_BLOCK = 30

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
        return Transaction(VERSION, Transaction.REFUSAL,
                source=transaction.target_user,
                amount=transaction.amount,
                tx_date=date.today().isoformat(),
                target_user=transaction.source,
                detail=transaction.signature)

    def is_valid(self):
        """Return boolean

        True if given blockchain seems valid
        False if an incoherence was detected
        """
        pass

    def sign_last_block(self, privkey):
        self[0].close_date = date.today()
        self[0].sign(privkey)

    def _reduce(self, pubkey):
        for index, block in list(enumerate(self)):
            if block._containUser(pubkey):
                return self[:index+1]
        return self

    def _reduce_to_date(self, date):
        for index, block in list(enumerate(self)):
            if block.close_date is not None and block.close_date < date:
                return self[:index]
        return self

    def _from_hashed_blocks(self, hashed_blocks):
        for b in hashed_blocks:
            block_as_list = umsgpack.unpackb(b)
            block = Block(*block_as_list)
            self.append(block)

    def _contain_transaction(self, tx):
        """Return True if transaction already in the blockchain

        :tx: TODO
        :returns: TODO

        """
        for b in self:
            if b._contain_transaction(tx):
                return True
        return False


class UserBlockchain(Blockchain):

    def start(self, birthdate, my_privkey, ref_pubkey):
        self.clear()
        self.insert(0, BirthBlock(birthdate, self.pubkey, my_privkey))
        init_block = Block(
                previous_block_signature=self[0].signature,
                signer=ref_pubkey,
                merkle_root=EMPTY_HASH)
        self.insert(0, init_block)

    def validate(self, ref_privkey, dt=None):
        init_block = self[0]
        init_block.balance = 0
        init_block.total = 0
        init_block.close_date = date.today()
        init_block.guzi_index = (init_block.close_date.isoformat(), 0)
        init_block.guza_index = (init_block.close_date.isoformat(), 0)
        self.make_daily_guzis(dt)
        self.make_daily_guzas(dt)
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
        dt = dt or date.today()
        guzis = [[[dt.isoformat()], list(range(amount))]]
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, self.pubkey, amount, tx_date=dt.isoformat(), guzis_positions=guzis)
        if self._contain_transaction(tx):
            return
        self.add_transaction(tx)
        if self.last_spend_date is None:
            self.last_spend_date = dt
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
        dt = dt or date.today()
        guzas = [[[dt.isoformat()], list(range(amount))]]
        self.add_transaction(Transaction(VERSION, Transaction.GUZA_CREATE, self.pubkey, amount, tx_date=dt.isoformat(), guzis_positions=guzas))
        return self[0].transactions[0]

    def pay_to_user(self, target, amount):
        """Return Transaction to pay given target with amount Guzis

        Also add this Transaction to itself
        """
        if amount < 0:
            raise NegativeAmountError
        if amount > self._get_available_guzis_amount():
            raise InsufficientFundsError
        guzis_positions = self._get_available_guzis()
        tx = Transaction(
            VERSION,
            Transaction.PAYMENT,
            self.pubkey,
            amount,
            tx_date=date.today().isoformat(),
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

    def _get_available_guzis(self):
        """Return amount number of first available Guzis

        If amount=-1, return all available guzis
        """
        guzis = []
        for block in self:
            guzis += block._guzis()

        guzis = unzip_positions(guzis)
        if self.last_spend_date is not None and self.last_spend_guzi is not None:
            for i, g in list(enumerate(guzis)):
                if date.fromisoformat(g[0]) == self.last_spend_date and g[1] == self.last_spend_guzi:
                    return guzis[i+1:]
        return guzis


    def _get_available_guzis_amount(self):
        """Return the total number of Guzis spendable
        :returns: TODO

        """
        return len(self._get_available_guzis())

    def _spend_guzis_from_availables(self, available_guzis, amount):
        """Update last_spend_guzi and last_spend_date

        depending on given available_guzis
        """
        if amount == 0:
            return
        self.last_spend_date = date.fromisoformat(available_guzis[amount-1][0])
        self.last_spend_guzi = available_guzis[amount-1][1]


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
        self.close_date = date.fromisoformat(close_date) if close_date else None
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
            if tx_type == t.tx_type and date == t.date:
                return t
        return None

    def as_list(self):
        return [
            self.version,
            self.close_date.isoformat() if self.close_date else 0,
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
        return guzi_hash(hash0+hash1)

    def _contain_transaction(self, transaction):
        return transaction in self.transactions

    def _remove_transaction(self, transaction):
        self.transactions.remove(transaction)

    def _containUser(self, pubkey):
        for t in self.transactions:
            if pubkey in (t.target_user, t.target_company, t.source):
                return True
        return False

    def _guzis(self):
        result = []
        for tx in self.transactions:
            result += tx._guzis()
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

    def __init__(self, version, tx_type, source, amount, tx_date=None,
            target_company=None, target_user=None, guzis_positions=[], detail=None, signature=None):
        self.version = version
        self.tx_type = tx_type
        self.date = date.fromisoformat(tx_date) if tx_date else date.today()
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
            self.date.isoformat(),
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

    def _guzis(self):
        if self.tx_type == Transaction.GUZI_CREATE:
            return self.guzis_positions
        return []
