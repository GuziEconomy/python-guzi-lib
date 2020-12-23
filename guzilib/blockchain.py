import itertools
from datetime import date

import umsgpack

from guzilib.crypto import (
    EMPTY_HASH,
    Packable,
    guzi_hash,
    is_valid_signature,
    unzip_positions,
    zip_positions,
)
from guzilib.errors import (
    FullBlockError,
    GuziError,
    InsufficientFundsError,
    InvalidBlockchainError,
    NegativeAmountError,
    NotRemovableTransactionError,
    UnsignedPreviousBlockError,
)
from guzilib.packer import BytePacker

VERSION = 1
MAX_TX_IN_BLOCK = 30


class Blockchain(list):
    def __init__(self, pubkey):
        self.pubkey = pubkey
        self.packer = BytePacker()

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, Blockchain):
            return False
        if len(self) != len(other):
            return False
        for b1, b2 in zip(self, other):
            if b1 != b2:
                return False
        return True

    def save_to_file(self, outfile):
        """
        Save the content of the Blockchain to the given file
        """
        self.packer.pack_bloockchain(self, outfile)

    def pack(self):
        return self.packer.pack_bloockchain(self)

    def from_file(self, infile):
        """Load data from given file into the instance

        :returns: None
        """
        hashed_blocks = umsgpack.unpack(infile)
        self._from_hashed_blocks(hashed_blocks)

    def from_bytes(self, b):
        """Load data from given bytes into the instance

        :returns: None
        """
        hashed_blocks = umsgpack.unpackb(b)
        self._from_hashed_blocks(hashed_blocks)

    def _find_tx(self, tx):
        """Return the block containing given transaction
        Return None if transaction was not found

        :returns: Block or None
        """
        for block in self:
            if block._contain_tx(tx):
                return block
        return None

    def new_block(self):
        """Create a new Block and add it to the Blockchain
        Previous block must be signed.

        :returns: None
        """
        if len(self) > 0 and not self.last_block().is_signed():
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

        :returns: Transaction or None
        """
        pass

    def _add_transaction(self, tx):
        """Add given transaction to the instance

        :tx: Transaction to add
        :returns: None
        """
        assert isinstance(tx, Transaction)

        if tx.tx_type == Transaction.GUZI_CREATE and self._contain_close_tx(tx):
            raise GuziError

        if len(self) == 0:
            self.new_block()
        self[0].add_transaction(tx)

    def refuse_transaction(self, tx):
        """Return a refusal transaction

        If Transaction was already added, remove it from current block.
        If Transaction is in a signed Block, raise Error

        :tx: Transaction to refuse
        :returns: Transaction
        """
        block_with_tx = self._find_tx(tx)
        if block_with_tx is None:
            pass
        elif block_with_tx != self[0]:
            raise NotRemovableTransactionError
        else:
            if self[0].is_signed():
                raise NotRemovableTransactionError
            self[0]._remove_tx(tx)
        return Transaction(
            VERSION,
            Transaction.REFUSAL,
            signer=tx.target_user,
            amount=tx.amount,
            tx_date=date.today().isoformat(),
            target_user=tx.signer,
            detail=tx.signature,
        )

    def is_valid(self):
        """Return True if blockchain seems valid
        False if an incoherence was detected

        :returns: bool
        """
        if len(self) == 0:
            return False
        for b in self:
            if not b.is_valid():
                return False
        return True

    def last_block(self):
        """Return the last in use block of the blockchain

        :returns: Block
        """
        return self[0]

    def _reduce(self, pubkey):
        """Reduce the Blockchain to the minimum size depending on target user

        If target user already had a Transaction with me, then I do not need to
        send him all my Blockchain, but only the part between now and the
        previous Transaction we had together.

        :returns: List
        """
        for index, block in list(enumerate(self)):
            if block._containUser(pubkey):
                return self[: index + 1]
        return self

    def _from_hashed_blocks(self, hashed_blocks):
        """Append Blocks created from given hashed_blocks.

        :returns: None

        """
        for b in hashed_blocks:
            block_as_list = umsgpack.unpackb(b)
            block = Block(*block_as_list)
            self.append(block)

    def _contain_tx(self, tx):
        """Return True if transaction is already in the blockchain

        :tx: Transaction we're looking for
        :returns: bool

        """
        for b in self:
            if b.close_date is not None and b.close_date < tx.date:
                return False
            elif b._contain_tx(tx):
                return True
        return False

    def _contain_close_tx(self, tx):
        """Return True if a Transaction looks the same (except for the
        signature) as given one.

        :tx: Transaction we're looking for
        :returns: bool
        """
        for b in self:
            if b.close_date is not None and b.close_date < tx.date:
                return False
            elif b._contain_close_tx(tx):
                return True
        return False


class UserBlockchain(Blockchain):
    def __init__(self, pubkey):
        super().__init__(pubkey)
        self.available_guzis = None

    def _add_transaction(self, transaction):
        super()._add_transaction(transaction)
        self.guzis_positions = None

    def make_birth_tx(self, birthdate=date.today()):
        """Return unsigned birth block with given birthdate or today

        :birthdate: datetime.date The date of birth of new user

        :returns: Unsigned Transaction

        """
        return Transaction(VERSION, Transaction.BIRTH, self.pubkey, 0, birthdate)

    def fill_init_block(self, dt=None):
        """Return the full init Block or raise error if something is missing

        :returns: Block
        """
        # TODO check len > 0
        # TODO check tx 0, 1 & 2 types and signatures
        last_block = self.last_block()
        last_block.balance = 0
        last_block.total = 0
        last_block.close_date = dt or date.today()
        last_block.previous_block_signature = EMPTY_HASH
        last_block.compute_merkle_root()
        return last_block

    def close_last_block(self, dt=date.today()):
        self[0].close_date = dt

    def sign_last_block(self, signature):
        # TODO : comment
        # TODO : check block == self.last_block
        # TODO : check block signature
        self[0].sign(signature)

    def _get_guzis_amount(self):
        """Return total guzis user can create each day.

        :returns: int
        """
        n = self[0].total if len(self) > 0 else 0
        if n < 0:
            raise InvalidBlockchainError("Total can never be negative")
        floatroot = n ** (1.0 / 3.0)
        introot = int(round(floatroot))
        if introot * introot * introot == n:
            return introot + 1
        return introot

    def make_daily_guzis_tx(self, dt=None):
        """Return int number of guzis availables

        A Guzi Creation Transaction is done by a user to himself, creating his own
        Guzis. This transaction only contains date, user id and the amount of
        created guzis.
        A user must create (total)^(1/3)+1 Guzis/day (rounded down)

        :dt: datetime.date To override "Today" for creation date
        :returns: Unsigned Transaction
        """
        amount = self._get_guzis_amount()
        dt = dt or date.today()
        guzis = [[[dt.isoformat()], list(range(amount))]]
        return Transaction(
            VERSION,
            Transaction.GUZI_CREATE,
            self.pubkey,
            amount,
            tx_date=dt.isoformat(),
            guzis_positions=guzis,
        )

    def make_daily_guzas_tx(self, dt=None):
        # TODO : check age > 18
        """Return int number of guzas availables

        A Guza Creation Transaction is done by a user to himself, creating his own
        Guzas. This transaction only contains date, user id and the amount of
        created guzas.
        A user must create (total)^(1/3)+1 Guzas/day (rounded down)

        :dt: datetime.date To override "Today" for creation date
        :returns: Transaction
        """
        amount = self._get_guzis_amount()
        dt = dt or date.today()
        guzas = [[[dt.isoformat()], list(range(amount))]]
        return Transaction(
            VERSION,
            Transaction.GUZA_CREATE,
            self.pubkey,
            amount,
            tx_date=dt.isoformat(),
            guzis_positions=guzas,
        )

    def make_pay_tx(self, target, amount):
        """Return Transaction to pay given target with given amount of Guzis

        Also add this Transaction to itself
        Return None and add no Transaction if amount == 0

        :returns: Unsigned Transaction or None
        """
        if amount < 0:
            raise NegativeAmountError
        if amount > self._get_available_guzis_amount():
            raise InsufficientFundsError
        guzis_positions = zip_positions(self._get_available_guzis()[:amount])
        return Transaction(
            VERSION,
            Transaction.PAYMENT,
            self.pubkey,
            amount,
            tx_date=date.today().isoformat(),
            target_user=target,
            guzis_positions=guzis_positions,
        )

    def pay_to_company(self, target, amount):
        pass

    def engage_guzis_to_user(self, target, days, daily_amount):
        pass

    def engage_guzis_to_company(self, target, days, daily_amount):
        pass

    def engage_guzas(self, target, days, daily_amount):
        pass

    def _get_available_guzis(self):
        """Return list of available Guzis
        with unziped format (see unzip_positions)

        :returns: list(tuple("iso_date", int))
        """
        if self.available_guzis is not None:
            return self.available_guzis
        res = []
        txs = itertools.chain.from_iterable([b.transactions for b in self])
        last_spend = None
        for tx in txs:
            if tx.tx_type == Transaction.GUZI_CREATE:
                guzis = unzip_positions(tx.guzis_positions)
                if last_spend is not None and last_spend in guzis:
                    res += [g for g in guzis if g > last_spend]
                    return sorted(res)
                else:
                    res += guzis
            elif tx.tx_type == Transaction.PAYMENT and last_spend is None:
                guzis = unzip_positions(tx.guzis_positions)
                if len(guzis) > 0:
                    last_spend = guzis[-1]
        return sorted(res)

    def _get_available_guzis_amount(self):
        """Return the total number of spendable Guzis

        :returns: int
        """
        return len(self._get_available_guzis())


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

    def refuse_transaction(self, tx):
        """Return Transaction"""
        pass


class Block(Packable):
    def __init__(
        self,
        version=VERSION,
        close_date=None,
        previous_block_signature=None,
        merkle_root=None,
        signer=None,
        balance=None,
        total=None,
        b_transactions=None,
        b_engagements=None,
        signature=None,
    ):
        self.version = version
        self.close_date = date.fromisoformat(close_date) if close_date else None
        self.previous_block_signature = previous_block_signature
        self.merkle_root = merkle_root
        self.signer = signer
        self.balance = balance
        self.total = total
        self.transactions = (
            [Transaction(*umsgpack.unpackb(b_tx)) for b_tx in b_transactions]
            if b_transactions
            else []
        )
        self.engagements = []
        self.signature = signature

        self.packer = BytePacker()

    def __str__(self):
        return "v{} at {} by {}... [{},{}]".format(
            self.version,
            self.close_date,
            self.signer.hex()[:10] if self.signer else "unsigned",
            self.balance,
            self.total,
        )

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            other is not None
            and isinstance(other, Block)
            and self.pack() == other.pack()
        )

    def add_transaction(self, tx):
        """Add given transaction to the instance transactions pool

        :returns: None
        """
        if self.is_signed():
            raise FullBlockError
        if len(self.transactions) >= MAX_TX_IN_BLOCK:
            raise FullBlockError
        if tx not in self.transactions:
            self.transactions.insert(0, tx)

    def add_transactions(self, txs):
        """Add given transactions to the instance transactions pool

        :returns: None
        """
        for t in txs:
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
            self.balance,
            self.total,
            len(self.transactions),
            len(self.engagements),
        ]

    def as_full_list(self):
        res = self.as_list()[:-2]
        res += [
            [t.pack() for t in self.transactions],
            [e.pack() for e in self.engagements],
            self.signature,
        ]
        return res

    def hash(self):
        self.compute_merkle_root()
        return self.packer.pack_block_without_hash(self)

    def pack(self):
        return self.packer.pack_block(self)

    def compute_merkle_root(self):
        self.merkle_root = self._merkle_root()
        return self.merkle_root

    def _merkle_root(self):
        return self._tx_list_to_merkle_root([t.to_hash() for t in self.transactions])

    def is_valid(self):
        for tx in self.transactions:
            if not tx.is_valid():
                return False
        if self.is_signed():
            return (
                is_valid_signature(self.signer, self.hash(), self.signature)
                and self._has_valid_merkleroot()
            )
        return True

    def _is_birthblock(self):
        return self.previous_block_signature == EMPTY_HASH

    def _has_valid_merkleroot(self):
        return self._merkle_root() == self.merkle_root

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
            if len(hashlist) % 2 == 1:
                hashlist.append(hashlist[-1])
            # [h0, h1, h2, h3] => [(h0, h1), (h2, h3)]
            hash_pairs = [
                (hashlist[i], hashlist[i + 1]) for i in range(0, len(hashlist), 2)
            ]
            new_hashlist = [self._hash_pair(h0, h1) for h0, h1 in hash_pairs]
            return self._tx_list_to_merkle_root(new_hashlist, False)

    def _hash_pair(self, hash0, hash1):
        return guzi_hash(hash0 + hash1)

    def _contain_tx(self, tx):
        return tx in self.transactions

    def _contain_close_tx(self, tx):
        for t in self.transactions:
            if t.almost_equal(tx):
                return True
        return False

    def _remove_tx(self, tx):
        self.transactions.remove(tx)

    def _containUser(self, pubkey):
        for t in self.transactions:
            if pubkey in (t.target_user, t.target_company, t.signer):
                return True
        return False


class Transaction(Packable):

    BIRTH = 0x00
    GUZI_CREATE = 0x01
    GUZA_CREATE = 0x02
    PAYMENT = 0x03
    GUZI_ENGAGEMENT = 0x04
    GUZA_ENGAGEMENT = 0x05
    REFUSAL = 0x06
    OWNER_SET = 0x10
    ADMIN_SET = 0x11
    WORKER_SET = 0x12
    PAYER_SET = 0x13
    PAY_ORDER = 0x14
    LEAVE_ORDER = 0x15

    def __init__(
        self,
        version,
        tx_type,
        signer,  # signer == source
        amount,
        tx_date=None,
        target_company=None,
        target_user=None,
        guzis_positions=[],
        detail=None,
        signature=None,
    ):
        self.version = version
        self.tx_type = tx_type
        if tx_date is None:
            self.date = date.today()
        elif isinstance(tx_date, date):
            self.date = tx_date
        else:
            self.date = date.fromisoformat(tx_date)
        self.signer = signer
        self.amount = int(amount)
        self.target_company = target_company
        self.target_user = target_user
        self.guzis_positions = guzis_positions
        self.detail = detail
        self.signature = signature

        self.packer = BytePacker()

    def __str__(self):
        return "{}, {}, {}, {}, {}".format(
            self.tx_type,
            self.date,
            self.signer.hex()[:10],
            self.amount,
            self.guzis_positions,
        )

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.almost_equal(other) and self.signature == other.signature

    def almost_equal(self, other):
        return (
            other is not None
            and isinstance(other, Transaction)
            and self.version == other.version
            and self.tx_type == other.tx_type
            and self.date == other.date
            and self.signer == other.signer
            and self.amount == other.amount
            and self.target_company == other.target_company
            and self.target_user == other.target_user
            and self.guzis_positions == other.guzis_positions
            and self.detail == other.detail
        )

    def as_list(self):
        return [
            self.version,
            self.tx_type,
            self.signer,
            self.amount,
            self.date.isoformat(),
            self.target_company,
            self.target_user,
            self.guzis_positions,
            self.detail,
        ]

    def as_full_list(self):
        res = self.as_list()
        res.append(self.signature)
        return res

    def hash(self):
        return self.packer.pack_tx_without_hash(self)

    def pack(self):
        return self.packer.pack_tx(self)

    def to_hash(self):
        return guzi_hash(self.hash())

    def is_signed(self):
        return self.signature is not None

    def is_valid(self):
        if self.is_signed():
            return is_valid_signature(self.signer, self.hash(), self.signature)
        return True
