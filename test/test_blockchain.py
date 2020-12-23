from datetime import date
from io import BytesIO
from test.test_utils import (
    KEY_POOL,
    NEW_USER_PRIV_KEY,
    NEW_USER_PUB_KEY,
    REF_PRIV_KEY,
    REF_PUB_KEY,
    make_blockchain,
    random_sign,
    random_transaction,
    sign,
)

import ecdsa
import pytest
from freezegun import freeze_time

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
    GuziError,
    InsufficientFundsError,
    InvalidBlockchainError,
    NegativeAmountError,
    NotRemovableTransactionError,
    UnsignedPreviousBlockError,
)


class TestUserBlockchainMakeBirthTx:
    def test_create_base_block(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        birth_tx = bc.make_birth_tx(date(1998, 12, 21).isoformat())
        random_sign(birth_tx, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
        bc._add_transaction(birth_tx)
        init_block = bc.last_block()

        assert init_block.version == VERSION
        assert init_block.close_date is None
        assert init_block.previous_block_signature is None
        assert init_block.merkle_root is None
        assert init_block.signer is None
        assert len(init_block.transactions) == 1
        assert len(init_block.engagements) == 0
        assert init_block.is_signed() is False
        assert init_block.is_valid() is True


class TestUserBlockchainFillInitBlock:
    @freeze_time("2011-12-13")
    def test_fill_init_block(self):
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        bc = make_blockchain()

        init_block = bc.last_block()
        expected_data = init_block.hash()

        assert init_block.version == VERSION
        assert init_block.close_date == date(2000, 1, 1)
        assert len(init_block.transactions) == 3  # 1.birth, 2.guzis 3.guzas
        assert bc.is_valid() is True
        assert vk.verify(init_block.signature, expected_data) is True


class TestUserBlockchainPayToUser:
    def init(self, amount=2):
        self.bc = make_blockchain(days=1, close_last_block=False)

        return self.bc.make_pay_tx(REF_PUB_KEY, amount)

    def test_transaction_is_correctly_created(self):
        result = self.init()
        expected_tx = Transaction(
            VERSION,
            Transaction.PAYMENT,
            signer=NEW_USER_PUB_KEY,
            amount=2,
            tx_date=date.today().isoformat(),
            target_user=REF_PUB_KEY,
            guzis_positions=[(["2000-01-01", "2000-01-02"], [0])],
        )

        assert result == expected_tx

    def test_transaction_is_added_to_blockchain(self):
        tx = self.init()
        self.bc._add_transaction(tx)

        assert len(self.bc.last_block().transactions) == 2

    def test_guzis_have_been_spended(self):
        tx = self.init()
        self.bc._add_transaction(tx)

        assert self.bc._get_available_guzis() == []

    def test_raise_error_for_negative_amount(self):
        with pytest.raises(NegativeAmountError):
            self.init(-2)

    def test_raise_error_for_to_big_amount(self):
        with pytest.raises(InsufficientFundsError):
            self.init(3)


class TestBlockchainEq:
    def test_equal_itself(self):
        bc = make_blockchain()

        assert bc == bc

    def test_different_signature(self):
        bc1 = make_blockchain()
        bc2 = make_blockchain()

        assert bc1 != bc2
        assert bc2 != bc1


class TestBlockchainSaveToFile:
    def test_all_blocks_be_in(self):
        bc = make_blockchain(days=2, tx_per_block=1)
        block0 = bc[0].pack().hex()
        block1 = bc[1].pack().hex()
        outfile = BytesIO()

        bc.save_to_file(outfile)
        outfile.seek(0)
        content = outfile.read().hex()

        assert block0 in content
        assert block1 in content


class TestBlockchainAddTransaction:
    def test_last_block_takes_the_transaction(self):
        bc = make_blockchain(days=1, tx_per_block=2, close_last_block=False)
        tx = Transaction(VERSION, Transaction.GUZI_CREATE, NEW_USER_PUB_KEY, 0)

        bc._add_transaction(tx)

        assert len(bc.last_block().transactions) == 3
        assert tx in bc.last_block().transactions

    def test_raise_error_for_existing_guzi_creation(self):
        bc = make_blockchain(days=1, close_last_block=False)
        tx = bc.make_daily_guzis_tx(date(2000, 1, 2))

        with pytest.raises(GuziError):
            bc._add_transaction(tx)

    def test_raise_error_for_existing_guzi_creation_bis(self):
        bc = make_blockchain()
        tx = bc.make_daily_guzis_tx(date(2000, 1, 1))

        with pytest.raises(GuziError):
            bc._add_transaction(tx)


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
        random_sign(blockchain.last_block())

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
        random_sign(blockchain.last_block())
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
        random_sign(blockchain.last_block())
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
        random_sign(blockchain.last_block())

        # Assert
        assert blockchain[0].is_signed() is True

    def test_signer_is_set(self):
        bc = Blockchain(NEW_USER_PUB_KEY)
        bc.new_block()

        random_sign(bc.last_block())

        assert bc[0].signer == REF_PUB_KEY


class TestBlockchainLoadFromFile:
    def test_hex_format(self):
        blockchain_ref = make_blockchain()
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.from_file(outfile)

        assert blockchain == blockchain_ref

    def test_transactions_are_the_same(self):
        blockchain_ref = make_blockchain()
        ref_transactions = blockchain_ref[0].transactions

        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.from_file(outfile)
        transactions = blockchain[0].transactions

        assert len(transactions) == 3
        assert transactions[0] == ref_transactions[0]
        assert transactions[1] == ref_transactions[1]
        assert transactions[2] == ref_transactions[2]


class TestBlockchainLoadFromBytes:
    def test_hex_format(self):

        # Arrange
        blockchain_ref = make_blockchain()
        b = blockchain_ref.pack()

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.from_bytes(b)

        # Assert
        assert blockchain == blockchain_ref

    def test_transactions_are_the_same(self):
        blockchain_ref = make_blockchain()
        ref_transactions = blockchain_ref[0].transactions
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.from_file(outfile)
        transactions = blockchain[0].transactions

        assert len(transactions) == 3
        assert transactions[0] == ref_transactions[0]
        assert transactions[1] == ref_transactions[1]
        assert transactions[2] == ref_transactions[2]


class TestBlockchainGetAvailableGuzis:
    @freeze_time("2011-12-13")
    def test_base_case(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.new_block()
        bc.last_block().total = 4 ** 3
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))

        result = bc._get_available_guzis()

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
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.new_block()
        bc.last_block().total = 4 ** 3
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))

        # Act
        result = bc._get_available_guzis()
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
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        bc.new_block()
        bc.last_block().total = 4 ** 3
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))
        bc.last_block().total = 5 ** 3
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))
        bc.last_block().total = 6 ** 3
        bc._add_transaction(random_sign(bc.make_daily_guzis_tx()))

        # Act
        result = bc._get_available_guzis()
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
        bc = UserBlockchain(NEW_USER_PUB_KEY)

        tx = bc.make_daily_guzis_tx()

        assert tx.tx_type == Transaction.GUZI_CREATE

    def test_create_1_guzi_if_total_is_0(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc.last_block().total = 0
        tx = bc.make_daily_guzis_tx(date(2000, 1, 2))

        assert tx.guzis_positions == [[[date(2000, 1, 2).isoformat()], [0]]]

    def test_create_6_guzi_if_total_is_125(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc.last_block().total = 125

        tx = bc.make_daily_guzis_tx()

        assert tx.guzis_positions == [[[date.today().isoformat()], list(range(6))]]

    def test_use_given_date(self):
        bc = make_blockchain(end_with_empty_block=True)
        dt = date(2001, 3, 22)

        tx = bc.make_daily_guzis_tx(dt)

        assert tx.guzis_positions == [[[dt.isoformat()], [0]]]


class TestBlockchainMakeDailyGuzas:
    def test_create_GUZA_CREATE_transaction(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        tx = bc.make_daily_guzas_tx()

        assert tx.tx_type == Transaction.GUZA_CREATE

    def test_create_1_guza_if_total_is_0(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc.last_block().total = 0
        tx = bc.make_daily_guzas_tx(date(2000, 1, 2))

        assert tx.guzis_positions == [[[date(2000, 1, 2).isoformat()], [0]]]

    def test_create_6_guza_if_total_is_125(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc.last_block().total = 125

        tx = bc.make_daily_guzas_tx()

        assert tx.guzis_positions == [[[date.today().isoformat()], list(range(6))]]

    def test_use_given_date(self):
        bc = make_blockchain(end_with_empty_block=True)
        dt = date(2001, 3, 22)

        tx = bc.make_daily_guzas_tx(dt)

        assert tx.guzis_positions == [[[dt.isoformat()], [0]]]


class TestBlockchainGetGuzisAmount:
    def test_return_0_for_total_0(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc[0].total = 0

        result = bc._get_guzis_amount()

        assert result == 1

    def test_raise_error_for_negative_total(self):
        bc = make_blockchain(end_with_empty_block=True)
        bc.last_block().total = -125

        with pytest.raises(InvalidBlockchainError):
            bc._get_guzis_amount()


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
    @freeze_time("2011-12-13")
    def test_return_a_refusal_transaction(self):
        bc = make_blockchain(days=1, close_last_block=False)

        refused = bc[0].transactions[0]
        refusal = bc.refuse_transaction(refused)

        assert refusal.tx_type == Transaction.REFUSAL
        assert refusal.date == date(2011, 12, 13)
        assert refusal.signer == refused.target_user
        assert refusal.amount == refused.amount
        assert refusal.target_company is None
        assert refusal.target_user == refused.signer
        assert refusal.guzis_positions == []
        assert refusal.detail == refused.signature

    def test_remove_tx_from_last_block(self):
        bc = make_blockchain(days=1, tx_per_block=1, close_last_block=False)
        assert len(bc[0].transactions) == 1

        bc.refuse_transaction(bc[0].transactions[0])
        assert len(bc[0].transactions) == 0

    def test_raise_error_if_transaction_is_sealed(self):
        bc = make_blockchain(days=1)

        with pytest.raises(NotRemovableTransactionError):
            bc.refuse_transaction(bc[0].transactions[0])

    def test_raise_error_if_transaction_is_sealed_in_old_block(self):
        bc = make_blockchain(days=2)

        with pytest.raises(NotRemovableTransactionError):
            bc.refuse_transaction(bc[1].transactions[0])


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
    def test_empty_ko(self):
        bc = Blockchain(NEW_USER_PUB_KEY)

        result = bc.is_valid()

        assert result is False

    def test_birth_only_ok(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        birth_tx = bc.make_birth_tx()
        random_sign(birth_tx, REF_PUB_KEY, REF_PRIV_KEY)
        bc._add_transaction(birth_tx)

        result = bc.is_valid()

        assert result is True

    def test_birth_false_signature_ko(self):
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        birth_tx = bc.make_birth_tx()
        # Fails because REF_PRIV_KEY should be NEW_USER_PRIV_KEY
        random_sign(birth_tx, NEW_USER_PUB_KEY, REF_PRIV_KEY)
        bc._add_transaction(birth_tx)

        result = bc.is_valid()

        assert result is False

    def test_validated_blockchain_ok(self):
        bc = make_blockchain()

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

    def test_blockchain_with_multiple_tx_per_block_ok(self):
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
    def test_hash(self):
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
        # result = block.hash()

        # # Assert
        # # TODO When library will be stable
        # # assert result == data


class TestECDSASignature:
    def test_sign(self):

        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        block = Block()
        data = block.hash()

        # Act
        signature = sign(data, REF_PRIV_KEY)

        # Assert
        assert vk.verify(signature, data) is True


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
        random_sign(block, REF_PUB_KEY, REF_PRIV_KEY)

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
        random_sign(block, REF_PUB_KEY, REF_PRIV_KEY)

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
    def test_signature_is_set(self):

        tx = random_transaction()
        random_sign(tx)

        assert tx.signature is not None
