from datetime import date
from io import BytesIO

import ecdsa
import pytest
from freezegun import freeze_time
from hypothesis import given
from hypothesis import strategies as st

from guzilib.blockchain import (
    MAX_TX_IN_BLOCK,
    VERSION,
    Block,
    Blockchain,
    Transaction,
    UserBlockchain,
)
from guzilib.crypto import EMPTY_HASH, guzi_hash
from guzilib.errors import (
    FullBlockError,
    InsufficientFundsError,
    InvalidBlockchainError,
    NegativeAmountError,
    NotRemovableTransactionError,
    UnsignedPreviousBlockError,
)
from test.test_utils import (
    BIRTHDATE,
    KEY_POOL,
    NEW_USER_PRIV_KEY,
    NEW_USER_PUB_KEY,
    REF_PRIV_KEY,
    REF_PUB_KEY,
    make_blockchain,
    random_transaction,
)


class TestUserBlockchainStart:
    def test_create_empty_block(self):
        """

        When a user creates his account, he creates 2 blocks :
        1. The first block is called the birthday block and contains the public
        key of this newly created user plus his birthday date.
        2. The second block contains the first Guzis (and Guzas) creation, and
        is signed by the reference.
        A reference is a person or an entity in whose a group of user gives
        confidence.

        Blockchain.start() creates blocks with empty data to be filled by
        the reference (if reference accepts to sign, of course).

        """

        # Arrange
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        birthdate = date(1998, 12, 21).isoformat()

        # Act
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(birthdate, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        init_block, birthday_block = blockchain
        data = birthday_block.pack_for_hash()

        # Assert
        assert birthday_block.version == VERSION
        assert birthday_block.close_date == date(1998, 12, 21)
        assert birthday_block.previous_block_signature == EMPTY_HASH
        assert birthday_block.merkle_root is None
        assert birthday_block.signer == NEW_USER_PUB_KEY
        assert birthday_block.transactions == []
        assert birthday_block.engagements == []
        assert vk.verify(birthday_block.signature, data) is True

        assert init_block.version == VERSION
        assert init_block.close_date is None
        assert init_block.previous_block_signature == birthday_block.signature
        assert init_block.merkle_root is None
        assert init_block.signer == REF_PUB_KEY
        assert init_block.transactions == []
        assert init_block.engagements == []
        assert init_block.signature is None

    def test_empty_previous_blockchain(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        assert len(blockchain) == 2


class TestUserBlockchainValidate:
    @freeze_time("2011-12-13")
    def test_validate_fill_init_blocks(self):
        """

        When reference receive an empty init blocks (with birthday block and
        init block), he must fill the init block with correct data, sign the
        block and send it back to newly created user. And then, new user can
        have transactions, isn't that beautiful ? Yes it is !

        Data to fill :
        - signature date
        - initialisation transactions (1st Guzi & 1st Guza)
        - Merkle root associated
        - Signed hash of this block

        Content of Initialisation block after filling :
            Type : 1
            Date (1998/12/21): 914198400.0
            prv_hash : XXX
            merkle_root : XXX
            reference_public_key : REF_PUB_KEY
            guzis : 1
            guzas : 1
            balance : 0
            total : 0
            transactions count : 2
            transactions :
                - create 1 guzi
                - create 1 guza
            engagements count : 0
        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        birthdate = date(1998, 12, 21).isoformat()
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(birthdate, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        # Act
        blockchain.validate(REF_PRIV_KEY)
        init_block = blockchain[0]
        expected_merkle_root = guzi_hash(
            init_block.transactions[0].to_hash() + init_block.transactions[1].to_hash()
        )
        expected_data = init_block.pack_for_hash()

        # Assert
        assert init_block.version == VERSION
        assert init_block.close_date == date(2011, 12, 13)
        assert init_block.merkle_root == expected_merkle_root
        assert len(init_block.transactions) == 2
        assert vk.verify(init_block.signature, expected_data) is True

    def test_validate_with_given_date(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.start(date(2000, 1, 1).isoformat(), NEW_USER_PRIV_KEY, REF_PUB_KEY)
        bc.validate(REF_PRIV_KEY, date(2000, 1, 2))

        assert bc[0].close_date == date(2000, 1, 2)


class TestUserBlockchainPayToUser:
    @freeze_time("2011-12-13", auto_tick_seconds=60 * 60 * 24)
    def init(self, amount=2):
        self.blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        self.blockchain.new_block()
        self.blockchain.make_daily_guzis()
        self.blockchain.make_daily_guzis()

        return self.blockchain.pay_to_user(REF_PUB_KEY, amount)

    def test_transaction_is_correctly_created(self):
        result = self.init()
        expected_tx = Transaction(
            VERSION,
            Transaction.PAYMENT,
            source=NEW_USER_PUB_KEY,
            amount=2,
            tx_date=date(2011, 12, 15).isoformat(),
            target_user=REF_PUB_KEY,
            guzis_positions=[(["2011-12-13", "2011-12-14"], [0])],
        )

        assert result == expected_tx

    def test_transaction_is_added_to_blockchain(self):
        self.init()

        assert len(self.blockchain[0].transactions) == 3

    def test_guzis_have_been_spended(self):
        self.init()

        assert self.blockchain._get_available_guzis() == []

    def test_raise_error_for_negative_amount(self):
        with pytest.raises(NegativeAmountError):
            self.init(-2)

    def test_raise_error_for_to_big_amount(self):
        with pytest.raises(InsufficientFundsError):
            self.init(3)


class TestBlockchainEq:
    @given(d=st.dates(), me=st.sampled_from(KEY_POOL), ref=st.sampled_from(KEY_POOL))
    def test_two_identic_basic_bc_are_equals(self, d, me, ref):
        bc = UserBlockchain(me["pub"])
        bc.start(d.isoformat(), me["priv"], ref["pub"])

        assert bc == bc

    @freeze_time("2011-12-13")
    @given(
        d1=st.dates(),
        d2=st.dates(),
        u1=st.sampled_from(KEY_POOL),
        u2=st.sampled_from(KEY_POOL),
    )
    def test_different_birthdate(self, d1, d2, u1, u2):
        bc1 = UserBlockchain(u1["pub"])
        bc1.start(d1.isoformat(), u1["priv"], u2["pub"])
        bc2 = UserBlockchain(u2["pub"])
        bc2.start(d2.isoformat(), u2["priv"], u1["pub"])

        assert bc1 != bc2
        assert bc2 != bc1


class TestBlockchainSaveToFile:
    @freeze_time("2011-12-13")
    def test_all_blocks_be_in(self):

        # Arrange
        birthdate = date(1998, 12, 21).isoformat()
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(birthdate, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        block0 = blockchain[0].pack().hex()
        block1 = blockchain[1].pack().hex()
        outfile = BytesIO()

        # Act
        blockchain.save_to_file(outfile)
        outfile.seek(0)
        content = outfile.read().hex()

        # Assert
        assert block0 in content
        assert block1 in content


class TestBlockchainAddTransaction:
    def make_active_blockchain(self):
        birthdate = date(1998, 12, 21).isoformat()
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(birthdate, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        return blockchain

    def test_last_block_takes_the_transaction(self):

        # Arrange
        blockchain = self.make_active_blockchain()
        transaction = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)

        # Act
        blockchain._add_transaction(transaction)

        # Assert
        assert len(blockchain) == 3
        assert transaction in blockchain[0].transactions


class TestBlockchainNewBlock:
    def test_raise_exception_if_last_block_not_signed(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()

        # Act
        with pytest.raises(UnsignedPreviousBlockError):
            blockchain.new_block()

    def test_set_previous_block_hash(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.sign_last_block(REF_PUB_KEY, REF_PRIV_KEY)

        # Act
        blockchain.new_block()

        # Assert
        assert blockchain[1].previous_block_signature == blockchain[0].signature


class TestBlockchainReduce:
    def test_return_total_blockchain_at_first_contact(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[2]["pub"], 0)
        tx3 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[3]["pub"], 0)
        tx4 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[4]["pub"], 0)
        blockchain[0].add_transactions([tx0, tx1, tx2])
        blockchain.sign_last_block(REF_PUB_KEY, REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].add_transactions([tx3, tx4])

        # Act
        result = blockchain._reduce(KEY_POOL[5]["pub"])

        # Assert
        assert len(result) == len(blockchain)

    def test_return_part_of_blockchain_at_second_contact(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[2]["pub"], 0)
        tx3 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[3]["pub"], 0)
        tx4 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[4]["pub"], 0)
        blockchain[0].add_transactions([tx0, tx1, tx2])
        blockchain.sign_last_block(REF_PUB_KEY, REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].add_transactions([tx3, tx4])

        # Act
        result = blockchain._reduce(KEY_POOL[3]["pub"])

        # Assert
        assert len(result) == 1


class TestBlockchainSignLastBlock:
    def test_basic_ok(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()

        # Act
        blockchain.sign_last_block(REF_PUB_KEY, REF_PRIV_KEY)

        # Assert
        assert blockchain[0].is_signed() is True

    def test_signer_is_set(self):
        bc = Blockchain(NEW_USER_PUB_KEY)
        bc.new_block()

        # Act
        bc.sign_last_block(REF_PUB_KEY, REF_PRIV_KEY)

        # Assert
        assert bc[0].signer == REF_PUB_KEY


@freeze_time("2011-12-13")
class TestBlockchainLoadFromFile:
    def test_hex_format(self):

        # Arrange
        blockchain_ref = make_blockchain()
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)

        # Assert
        assert blockchain == blockchain_ref

    def test_transactions_are_the_same(self):

        # Arrange
        blockchain_ref = make_blockchain()
        ref_transactions = blockchain_ref[0].transactions

        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)
        transactions = blockchain[0].transactions

        # Assert
        assert len(transactions) == 2
        assert transactions[0] == ref_transactions[0]
        assert transactions[1] == ref_transactions[1]


@freeze_time("2011-12-13")
class TestBlockchainLoadFromBytes:
    def test_hex_format(self):

        # Arrange
        blockchain_ref = make_blockchain()
        b = blockchain_ref.pack()

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_bytes(b)

        # Assert
        assert blockchain == blockchain_ref

    def test_transactions_are_the_same(self):

        # Arrange
        blockchain_ref = make_blockchain()
        ref_transactions = blockchain_ref[0].transactions
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)
        transactions = blockchain[0].transactions

        # Assert
        assert len(transactions) == 2
        assert transactions[0] == ref_transactions[0]
        assert transactions[1] == ref_transactions[1]


class TestBlockchainGetAvailableGuzis:
    @freeze_time("2011-12-13")
    def test_base_case(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4 ** 3
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()

        # Assert
        expected = [
            ("2011-12-13", 0),
            ("2011-12-13", 1),
            ("2011-12-13", 2),
            ("2011-12-13", 3),
            ("2011-12-13", 4),
        ]
        assert expected == result

    @freeze_time("2011-12-13", auto_tick_seconds=60 * 60 * 24)
    def test_return_all_dates(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4 ** 3
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()
        expected = [
            ("2011-12-13", 0),
            ("2011-12-13", 1),
            ("2011-12-13", 2),
            ("2011-12-13", 3),
            ("2011-12-13", 4),
            ("2011-12-14", 0),
            ("2011-12-14", 1),
            ("2011-12-14", 2),
            ("2011-12-14", 3),
            ("2011-12-14", 4),
            ("2011-12-15", 0),
            ("2011-12-15", 1),
            ("2011-12-15", 2),
            ("2011-12-15", 3),
            ("2011-12-15", 4),
        ]

        # Assert
        assert expected == result

    @freeze_time("2011-12-13", auto_tick_seconds=60 * 60 * 24)
    def test_return_evolving_total(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4 ** 3
        blockchain.make_daily_guzis()
        blockchain[0].total = 5 ** 3
        blockchain.make_daily_guzis()
        blockchain[0].total = 6 ** 3
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()
        expected = [
            ("2011-12-13", 0),
            ("2011-12-13", 1),
            ("2011-12-13", 2),
            ("2011-12-13", 3),
            ("2011-12-13", 4),
            ("2011-12-14", 0),
            ("2011-12-14", 1),
            ("2011-12-14", 2),
            ("2011-12-14", 3),
            ("2011-12-14", 4),
            ("2011-12-14", 5),
            ("2011-12-15", 0),
            ("2011-12-15", 1),
            ("2011-12-15", 2),
            ("2011-12-15", 3),
            ("2011-12-15", 4),
            ("2011-12-15", 5),
            ("2011-12-15", 6),
        ]

        # Assert
        assert expected == result


class TestBlockchainMakeDailyGuzis:
    @freeze_time("1998-12-21", auto_tick_seconds=60 * 60 * 24)
    def test_create_GUZI_CREATE_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzis()
        tx = blockchain[0].transactions[0]

        # Assert
        assert tx.tx_type == Transaction.GUZI_CREATE

    @freeze_time("1998-12-21", auto_tick_seconds=60 * 60 * 24)
    def test_create_1_guzi_if_total_is_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzis()
        tx = blockchain[0].transactions[0]

        # Assert
        assert tx.guzis_positions == [[[date(1998, 12, 24).isoformat()], [0]]]

    def test_create_6_guzi_if_total_is_125(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 125

        # Act
        tx = blockchain.make_daily_guzis()

        # Assert
        assert tx.guzis_positions == [[[date.today().isoformat()], list(range(6))]]

    def test_use_given_date(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        dt = date(2001, 3, 22)

        # Act
        tx = blockchain.make_daily_guzis(dt)

        # Assert
        assert tx.guzis_positions == [[[dt.isoformat()], [0]]]


class TestBlockchainMakeDailyGuzas:
    def test_create_GUZA_CREATE_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzas()
        tx = blockchain[0].transactions[0]

        # Assert
        assert tx.tx_type == Transaction.GUZA_CREATE

    def test_create_1_guza_if_total_is_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzas()
        tx = blockchain[0].transactions[0]

        # Assert
        assert tx.guzis_positions == [[[date.today().isoformat()], [0]]]

    def test_create_6_guza_if_total_is_125(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 125

        # Act
        tx = blockchain.make_daily_guzas()

        # Assert
        assert tx.guzis_positions == [[[date.today().isoformat()], list(range(6))]]

    def test_use_given_date(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        dt = date(2001, 3, 22)

        # Act
        tx = blockchain.make_daily_guzas(dt)

        # Assert
        assert tx.guzis_positions == [[[dt.isoformat()], [0]]]


class TestBlockchainGetGuzisAmount:
    def test_return_0_for_total_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 0

        # Act
        result = blockchain._get_guzis_amount()

        # Assert
        assert result == 1

    def test_raise_error_for_negative_total(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = -125

        # Act
        # Assert
        with pytest.raises(InvalidBlockchainError):
            blockchain._get_guzis_amount()


class TestBlockchainFindTransaction:
    def test_return_None_if_not_found(self):
        # Arrange
        blockchain = make_blockchain()

        # Act
        result = blockchain._find_tx(random_transaction())

        # Assert
        assert result is None

    def test_return_block_containing_transaction(self):
        # Arrange
        blockchain = make_blockchain(days=2, tx_per_block=1)

        # Act
        result = blockchain._find_tx(blockchain[2].transactions[0])

        # Assert
        assert result == blockchain[2]


class TestBlockchainRefuseTransaction:
    def make_any_transaction(self):
        return Transaction(
            VERSION,
            Transaction.PAYMENT,
            REF_PUB_KEY,
            12,
            tx_date=date(1998, 12, 21).isoformat(),
            target_user=NEW_USER_PUB_KEY,
            signature=0x12,
        )

    @freeze_time("2011-12-13")
    def test_return_a_refusal_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4 ** 3
        blockchain.make_daily_guzis()

        # Action
        refused = self.make_any_transaction()
        refusal = blockchain.refuse_transaction(refused)

        # Assert
        assert refusal.tx_type == Transaction.REFUSAL
        assert refusal.date == date(2011, 12, 13)
        assert refusal.source == refused.target_user
        assert refusal.amount == refused.amount
        assert refusal.target_company is None
        assert refusal.target_user == refused.source
        assert refusal.guzis_positions == []
        assert refusal.detail == refused.signature

    def test_remove_tx_from_last_block(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain._add_transaction(refused)

        # Action
        blockchain.refuse_transaction(refused)

        # Assert
        assert len(blockchain[0].transactions) == 0

    def test_raise_error_if_transaction_is_sealed(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain._add_transaction(refused)
        blockchain.sign_last_block(NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)

        # Action
        # Assert
        with pytest.raises(NotRemovableTransactionError):
            blockchain.refuse_transaction(refused)

    def test_raise_error_if_transaction_is_sealed_in_old_block(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain._add_transaction(refused)
        blockchain.sign_last_block(NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
        blockchain.new_block()

        # Action
        # Assert
        with pytest.raises(NotRemovableTransactionError):
            blockchain.refuse_transaction(refused)


class TestBlockchainContainTransaction:
    def test_transaction_found(self):
        # Arrange
        # Act
        bc = make_blockchain(days=2, tx_per_block=1)

        # Assert
        assert bc._contain_tx(bc[2].transactions[0]) is True

    def test_transaction_not_found(self):
        # Arrange
        # Act
        bc = make_blockchain()

        # Assert
        assert bc._contain_tx(random_transaction()) is False


class TestBLockchainIsValid:
    def test_empty_ok(self):
        bc = Blockchain(NEW_USER_PUB_KEY)

        result = bc.is_valid()

        assert result is True

    def test_birth_only_ok(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.start(date(2000, 1, 1).isoformat(), NEW_USER_PRIV_KEY, REF_PUB_KEY)

        result = bc.is_valid()

        assert result is True

    def test_birth_false_signature_ko(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        # Fails because REF_PRIV_KEY should be NEW_USER_PRIV_KEY
        bc.start(date(2000, 1, 1).isoformat(), REF_PRIV_KEY, REF_PUB_KEY)

        result = bc.is_valid()

        assert result is False

    def test_validated_blockchain_ok(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.start(date(2000, 1, 1).isoformat(), NEW_USER_PRIV_KEY, REF_PUB_KEY)
        bc.validate(REF_PRIV_KEY, date(2000, 1, 2))

        result = bc.is_valid()

        assert result is True

    def test_blockchain_with_some_transactions_ok(self):
        bc = make_blockchain(days=5, tx_per_block=1)

        result = bc.is_valid()

        assert result is True

    def test_blockchain_with_empty_ending_block_ok(self):
        bc = make_blockchain(days=1, tx_per_block=1, end_with_empty_block=True)

        result = bc.is_valid()

        assert result is True

    def test_blockchain_with_multiple_tx_per_block(self):
        bc = make_blockchain(days=4, tx_per_block=4)

        result = bc.is_valid()

        assert result is True

    def test_change_transactions_after_signed_ko(self):
        bc = make_blockchain(days=4, tx_per_block=4)
        bc[0].transactions[0].amount = 12

        result = bc.is_valid()

        assert result is False


class TestBlockContains:
    def test_transaction_found(self):

        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1, tx2])

        # Assert
        assert b._contain_tx(tx0) is True
        assert b._contain_tx(tx1) is True
        assert b._contain_tx(tx2) is True

    def test_transaction_not_found(self):

        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, Transaction.GUZA_CREATE, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, Transaction.PAYMENT, NEW_USER_PUB_KEY, 0)
        b = Block()

        # Act
        b.add_transactions([tx1, tx2])

        # Assert
        assert b._contain_tx(tx0) is False


class TestBlockContainUser:
    def test_return_false_if_transaction_not_in(self):

        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[2]["pub"], 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1, tx2])

        # Assert
        assert b._containUser(KEY_POOL[0]["pub"]) is True
        assert b._containUser(KEY_POOL[1]["pub"]) is True
        assert b._containUser(KEY_POOL[2]["pub"]) is True

    def test_return_true_if_transaction_in(self):

        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, KEY_POOL[1]["pub"], 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1])

        # Assert
        assert b._containUser(KEY_POOL[2]["pub"]) is False


class TestBlockPack:
    def test_pack_for_hash(self):
        """
        Type: 1
        Date (1998/12/21): 914198400.0
        Previous_block_hash: 0
        Merkle_root: 0
        Signer: 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        guzis: 0
        guzas: 0
        balance: 0
        total: 0
        transactions count: 0
        engagements count: 0
        """
        pass
        # A# rrange
        # data = bytes.fromhex(
        # "9b01cb41cb3ec7c00000000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000000000"
        # )
        # block = Block(
        #     close_date=date(1998, 12, 21).isoformat(),
        #     previous_block_signature=EMPTY_HASH,
        #     merkle_root=EMPTY_HASH,
        #     signer=NEW_USER_PUB_KEY,
        #     balance=0,
        #     total=0,
        # )

        # # Act
        # result = block.pack_for_hash()

        # # Assert
        # # TODO When library will be stable
        # # assert result == data


class TestBlock:
    def test_to_hash(self):

        pass
        # A# rrange
        # block = Block(
        #     date(1998, 12, 21).isoformat(),
        #     previous_block_signature=EMPTY_HASH,
        #     merkle_root=EMPTY_HASH,
        #     signer=NEW_USER_PUB_KEY,
        #     balance=0,
        #     total=0,
        # )

        # # Act
        # result = block.to_hash()

        # # Assert
        # # TODO When library will be stable
        # # assert result == bytes.fromhex('f8a98021264759eec491272b2d4939dcbc5f69ff3fba441ca6e05e1bc8daf4b5')

    def test_sign(self):

        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        block = Block(
            date(1998, 12, 21).isoformat(),
            previous_block_signature=EMPTY_HASH,
            merkle_root=EMPTY_HASH,
            balance=0,
            total=0,
        )

        # Act
        signature = block.sign(REF_PUB_KEY, REF_PRIV_KEY)
        data = block.pack_for_hash()

        # Assert
        assert vk.verify(signature, data) is True

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_0_tx(self):
        """
        If there is 0 transaction, merkle root should be None
        """
        # Arrange
        block = Block()

        # Act
        result = block.compute_merkle_root()

        # Assert
        assert result is None

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_1_tx(self):
        """
        If there is only 1 transaction, merkle root should be :
        hash(hash0 + hash0)
        """
        # Arrange
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        block = Block()
        block.add_transaction(tx)

        expected_merkle_root = guzi_hash(tx.to_hash() + tx.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        assert result == expected_merkle_root

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_2_tx(self):
        """
        If there are 2 transactions, merkle root should be :
        hash(hash0 + hash1)
        """
        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        block = Block()
        block.add_transactions([tx0, tx1])

        expected_merkle_root = guzi_hash(tx0.to_hash() + tx1.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        assert result == expected_merkle_root

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_3_tx(self):
        """
        If there are 3 transactions, merkle root should be :
        hash(hash(hash0 + hash1) + hash(hash3 + hash3))
        """
        # Arrange
        tx0 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, Transaction.GUZA_CREATE, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, Transaction.GUZA_CREATE, REF_PUB_KEY, 0)
        block = Block()
        block.add_transactions([tx0, tx1, tx2])

        hash21 = guzi_hash(tx2.to_hash() + tx1.to_hash())
        hash00 = guzi_hash(tx0.to_hash() + tx0.to_hash())
        expected_merkle_root = guzi_hash(hash21 + hash00)

        # Act
        result = block.compute_merkle_root()

        # Assert
        assert result == expected_merkle_root


class TestBlockIsSigned:
    def test_signed_block_return_true(self):

        # Arrange
        block = Block()
        block.sign(REF_PUB_KEY, REF_PRIV_KEY)

        # Assert
        assert block.is_signed() is True

    def test_unsigned_block_return_false(self):

        # Arrange
        block = Block()

        # Assert
        assert block.is_signed() is False


class TestBlockAddTransactions:
    def test_increase_transaction_count(self):

        # Arrange
        block = Block()
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, EMPTY_HASH, 0)

        # Act
        block.add_transaction(tx)

        # Assert
        assert len(block.transactions) == 1

    def test_shouldnt_add_existing_transaction_twice(self):

        # Arrange
        block = Block()
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, EMPTY_HASH, 0)

        # Act
        block.add_transaction(tx)
        block.add_transaction(tx)
        block.add_transaction(tx)

        # Assert
        assert len(block.transactions) == 1

    def test_raise_exception_if_too_much_transactions_in_last_block(self):

        # Arrange
        block = Block()
        tx = Transaction(VERSION, Transaction.PAYMENT, NEW_USER_PUB_KEY, 0)

        for i in range(MAX_TX_IN_BLOCK):
            block.add_transaction(
                Transaction(VERSION, Transaction.PAYMENT, NEW_USER_PUB_KEY, i)
            )

        # Act
        with pytest.raises(FullBlockError):
            block.add_transaction(tx)

    def test_raise_exception_if_block_is_already_signed(self):

        # Arrange
        block = Block()
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, EMPTY_HASH, 0)

        block.sign(REF_PUB_KEY, REF_PRIV_KEY)

        # Act
        with pytest.raises(FullBlockError):
            block.add_transaction(tx)


class TestBlockFindTransaction:
    def test_found_transaction(self):
        block = Block()
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1.date = date(2011, 12, 13)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx2.date = date(2012, 11, 14)
        tx3 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx3.date = date(2013, 10, 15)

        # Act
        block.add_transactions([tx1, tx2, tx3])
        result = block.find_transaction(Transaction.GUZI_CREATE, date(2012, 11, 14))

        # Assert
        assert result == tx2

    def test_unfound_transaction(self):
        block = Block()
        tx1 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx1.date = date(2011, 12, 13)
        tx2 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx2.date = date(2012, 11, 14)
        tx3 = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)
        tx3.date = date(2013, 10, 15)

        # Act
        block.add_transactions([tx1, tx2, tx3])
        result = block.find_transaction(Transaction.GUZI_CREATE, date(2014, 11, 14))

        # Assert
        assert result is None


class TestTransactionSign:
    @freeze_time("2011-12-13")
    def test_signature_be_valid(self):

        # Arrange
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        # Act
        tx = Transaction(
            VERSION,
            Transaction.GUZI_CREATE,
            NEW_USER_PUB_KEY,
            0,
            date(2011, 12, 13).isoformat(),
        )
        data = tx.pack_for_hash()
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        assert vk.verify(tx.signature, data) is True
