import itertools
from datetime import date

import umsgpack

from guzilib.crypto import (
    EMPTY_HASH,
    Signable,
    guzi_hash,
    is_valid_signature,
    unzip_positions,
    zip_positions,
)
from guzilib.errors import (
    FullBlockError,
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
        if isinstance(other, Blockchain):
            if len(self) != len(other):
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
        """Load data from given file into the instance

        :returns: None
        """
        hashed_blocks = umsgpack.unpack(infile)
        self._from_hashed_blocks(hashed_blocks)

    def load_from_bytes(self, b):
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

        :returns: Transaction or None
        """
        pass

    def _add_transaction(self, tx):
        """Add given transaction to the instance

        :returns: None
        """
        assert isinstance(tx, Transaction)
        self[0].add_transaction(tx)

    def refuse_transaction(self, transaction):
        """Return a refusal transaction

        If Transaction was already added, remove it from current block.
        If Transaction is in a signed Block, raise Error

        :returns: Transaction
        """
        block_with_tx = self._find_tx(transaction)
        if block_with_tx is None:
            pass
        elif block_with_tx != self[0]:
            raise NotRemovableTransactionError
        else:
            if self[0].is_signed():
                raise NotRemovableTransactionError
            self[0]._remove_tx(transaction)
        return Transaction(
            VERSION,
            Transaction.REFUSAL,
            source=transaction.target_user,
            amount=transaction.amount,
            tx_date=date.today().isoformat(),
            target_user=transaction.source,
            detail=transaction.signature,
        )

    def is_valid(self):
        """Return True if given blockchain seems valid
        False if an incoherence was detected

        :returns: bool
        """
        if len(self) == 0:
            return True
        for b in self:
            if not b.is_valid(self.pubkey):
                return False
        return True

    def sign_last_block(self, pubkey, privkey):
        """Sign last Block of the Blockchain with given privkey

        :returns: None
        """
        self[0].close_date = date.today()
        self[0].sign(pubkey, privkey)

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
            if b._contain_tx(tx):
                return True
        return False


class UserBlockchain(Blockchain):
    def __init__(self, pubkey):
        super().__init__(pubkey)
        self.available_guzis = None

    def _add_transaction(self, transaction):
        super()._add_transaction(transaction)
        self.guzis_positions = None

    def start(self, birthdate, my_privkey, ref_pubkey):
        """Create a new blockchain. This blockchain won't be usable to pay or
        create guzis while it has not been validated by a referent.

        :birthdate: datetime.date The date of birth of new user
        :my_privkey: bytes New user private key
        :my_pubkey: bytes New user public key
        :returns: None

        """
        self.clear()
        self.insert(0, BirthBlock(birthdate, self.pubkey, my_privkey))
        init_block = Block(
            previous_block_signature=self[0].signature, signer=ref_pubkey
        )
        self.insert(0, init_block)

    def validate(self, ref_privkey, dt=None):
        """Validate a newly created blockchain. This method should be called by
        Referent to certify user blockchain

        :returns: None
        """
        init_block = self[0]
        init_block.balance = 0
        init_block.total = 0
        init_block.close_date = dt or date.today()
        self.make_daily_guzis(dt)
        self.make_daily_guzas(dt)
        init_block.compute_merkle_root()
        init_block.sign(init_block.signer, ref_privkey)

    def _get_guzis_amount(self):
        """Return total guzis user can create each day.

        :returns: int
        """
        n = self[0].total
        if n < 0:
            raise InvalidBlockchainError("Total can never be negative")
        floatroot = n ** (1.0 / 3.0)
        introot = int(round(floatroot))
        if introot * introot * introot == n:
            return introot + 1
        return introot

    def make_daily_guzis(self, dt=None):
        """Return int number of guzis availables

        A Guzi Creation Transaction is done by a user to himself, creating his own
        Guzis. This transaction only contains date, user id and the amount of
        created guzis.
        A user must create (total)^(1/3)+1 Guzis/day (rounded down)

        :dt: datetime.date To override "Today" for creation date
        :returns: Transaction
        """
        amount = self._get_guzis_amount()
        dt = dt or date.today()
        guzis = [[[dt.isoformat()], list(range(amount))]]
        tx = Transaction(
            VERSION,
            Transaction.GUZI_CREATE,
            self.pubkey,
            amount,
            tx_date=dt.isoformat(),
            guzis_positions=guzis,
        )
        if self._contain_tx(tx):
            return
        self._add_transaction(tx)
        return self[0].transactions[0]

    def make_daily_guzas(self, dt=None):
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
        self._add_transaction(
            Transaction(
                VERSION,
                Transaction.GUZA_CREATE,
                self.pubkey,
                amount,
                tx_date=dt.isoformat(),
                guzis_positions=guzas,
            )
        )
        return self[0].transactions[0]

    def pay_to_user(self, target, amount):
        """Return Transaction to pay given target with given amount of Guzis

        Also add this Transaction to itself
        Return None and add no Transaction if amount == 0

        :returns: Transaction or None
        """
        if amount < 0:
            raise NegativeAmountError
        if amount == 0:
            return
        if amount > self._get_available_guzis_amount():
            raise InsufficientFundsError
        guzis_positions = zip_positions(self._get_available_guzis()[:amount])
        tx = Transaction(
            VERSION,
            Transaction.PAYMENT,
            self.pubkey,
            amount,
            tx_date=date.today().isoformat(),
            target_user=target,
            guzis_positions=guzis_positions,
        )
        self._add_transaction(tx)
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


class Block(Signable):
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

    def sign(self, pub, priv):
        """
        pub : bytes
        priv : bytes

        :returns: bytes
        """
        self.signer = pub
        self.compute_merkle_root()
        return super().sign(priv)

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

    def pack_for_hash(self):
        return self.packer.pack_block_without_hash(self)

    def pack(self):
        return self.packer.pack_block(self)

    def compute_merkle_root(self):
        self.merkle_root = self._merkle_root()
        return self.merkle_root

    def _merkle_root(self):
        return self._tx_list_to_merkle_root([t.to_hash() for t in self.transactions])

    def as_email(self):
        pass

    def is_valid(self, owner):
        if self._is_birthblock(owner):
            return is_valid_signature(owner, self.pack_for_hash(), self.signature)
        if self.is_signed():
            return (
                is_valid_signature(self.signer, self.pack_for_hash(), self.signature)
                and self._has_valid_merkleroot()
            )
        return True

    def _is_birthblock(self, owner):
        return (
            self.merkle_root == EMPTY_HASH
            and self.previous_block_signature == EMPTY_HASH
            and self.signer == owner
        )

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

    def _remove_tx(self, tx):
        self.transactions.remove(tx)

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
        super().__init__(close_date=birthdate, signer=new_user_pub_key)
        self.previous_block_signature = EMPTY_HASH
        self.merkle_root = EMPTY_HASH
        self.sign(new_user_pub_key, new_user_priv_key)


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

    def __init__(
        self,
        version,
        tx_type,
        source,
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
        return "{}, {}, {}, {}, {}".format(
            self.tx_type,
            self.date,
            self.source.hex()[:10],
            self.amount,
            self.guzis_positions,
        )

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            other is not None
            and isinstance(other, Transaction)
            and self.version == other.version
            and self.tx_type == other.tx_type
            and self.date == other.date
            and self.source == other.source
            and self.amount == other.amount
            and self.target_company == other.target_company
            and self.target_user == other.target_user
            and self.guzis_positions == other.guzis_positions
            and self.detail == other.detail
            and self.signature == other.signature
        )

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
        res = self.as_list()
        res.append(self.signature)
        return res

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
