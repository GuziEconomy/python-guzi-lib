import unittest
import pytz
import ecdsa
import os
import random

from io import BytesIO
from freezegun import freeze_time
from datetime import date, timedelta

from guzilib.blockchain import *

KEY_POOL = [
    {'priv': bytes.fromhex('cdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6'),
    'pub': bytes.fromhex('02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b')},
    {'priv': bytes.fromhex('7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca'),
    'pub': bytes.fromhex('031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d')},
    {'priv': bytes.fromhex('1f77f037236b5a6763b2a18de13855b3d4a893c06bd004ba0f739c8d2f281103'),
    'pub': bytes.fromhex('032a2eefc84ff6fd6a15eb1e920254cd02725350c67080a00970f535a762417cbb')},
    {'priv': bytes.fromhex('f7aa7d91e5b6f82302f82d6c20346cc442729e5ceae6bdb26ea4bd4367a07c4d'),
    'pub': bytes.fromhex('034dffbff09cd2ca67fc9ea67ad4c23e29d9e7febd6c82e8a82ae5e52df4220f6f')},
    {'priv': bytes.fromhex('4768e8b37d07ff15bf2149f1fcbf0788be1f00e6b8f365ecbb751b6260d711dc'),
    'pub': bytes.fromhex('02e490be01204314c0918ce6c781b3e6a1ef76f337344a4605589a8185379cd9ac')},
    {'priv': bytes.fromhex('2c81a0b8bf49a4dd5a0ddb8b34f63fee0fe1c4d7673ed6376a07ed7a33430d18'),
    'pub': bytes.fromhex('03ef500f14cfdafc25b88c9d054844bd50cf37fd12a374d08e06d8e92fe751471c')},
    {'priv': bytes.fromhex('15a9e23b4bce92ee78b556c53dce720a5f538cb94719280e6bfb8dfbde33d049'),
    'pub': bytes.fromhex('036ca32ba58cebf40dee409ddab41263afd1d5a3a74ab4ea317d9cadf32b8a530c')},
    {'priv': bytes.fromhex('99184560439a716ab85316e6884ea901f076ca678d4f38f295f9201a7bccaa7e'),
    'pub': bytes.fromhex('02b141e661a3beb6c251502f1ed2c1d3d00a65f3a2aae6c557980df6f8e7fb89ba')},
    {'priv': bytes.fromhex('8428ef9ae38b229f2d36379d08e5b35c2c0443000e1d052e987da3a85269bc2c'),
    'pub': bytes.fromhex('0284dd75d374c23f8a783fc7bb4f1f5268b59ff3264c23cf54ac0baa4567fc7362')},
    {'priv': bytes.fromhex('a08f8b3e23129287cf24a973da9e6ad5ce5558a7ba2ff1b913c197351966f5af'),
    'pub': bytes.fromhex('03ce3f8e980235165f5fc690f7c08eac3d0c7ba09541122f182f6b8c81431583d5')},
    {'priv': bytes.fromhex('53ddf4b6fbf29ffb44192e15f87daf83dbf92f4bf6e609ddff60e2aa7f6125ed'),
    'pub': bytes.fromhex('036cb8ac481bcd55cc876889be9e262a45da5612433bb34c0c5826703140dc6580')},
    {'priv': bytes.fromhex('b69dda00c4cc3721ee056096a7f51283d9793fb1f8326cf2d3c47d50ce860a5a'),
    'pub': bytes.fromhex('02fb673d955d41debc1c09fc889730038adecc1bab653bf39ebbeda57cc03ff455')}
]
NEW_USER_PUB_KEY = KEY_POOL[0]['pub']
NEW_USER_PRIV_KEY = KEY_POOL[0]['priv']
REF_PUB_KEY =  KEY_POOL[1]['pub']
REF_PRIV_KEY = KEY_POOL[1]['priv']

BIRTHDATE = date(1998, 12, 21).isoformat()

def random_transaction():
    return Transaction(VERSION, TxType.PAYMENT, REF_PUB_KEY, 12, tx_date=date(1998, 12, 21).isoformat(), target_user=NEW_USER_PUB_KEY, signature=0x12)

@freeze_time("1998-12-21", auto_tick_seconds=60*60*24)
def make_blockchain():
    blockchain = UserBlockchain(NEW_USER_PUB_KEY)
    blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
    blockchain.validate(REF_PRIV_KEY)
    blockchain.new_block()
    blockchain[0].total = 4**3
    blockchain.make_daily_guzis()
    blockchain.sign_last_block(REF_PRIV_KEY)
    blockchain.new_block()
    blockchain.make_daily_guzis()
    blockchain.sign_last_block(REF_PRIV_KEY)
    blockchain.new_block()
    return blockchain


class TestUserBlockchainStart(unittest.TestCase):

    def test_should_create_empty_block(self):
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

        Content of Birthday block :
            In bytes :
            Type : 1
            Date (1998/12/21): 914198400.0
            empty hash : EMPTY_HASH
            empty merkle : EMPTY_HASH
            user id : NEW_USER_PUB_KEY
            guzis : 0
            guzas : 0
            balance : 0
            total : 0
            transactions count : 0
            engagements count : 0 
        Initialisation block :
            type : 01
            date : None
            hash_of_birthday_block : XXX
            empty_merkle_root : EMPTY_HASH
            reference_public_key : REF_PUB_KEY
            guzis : 0
            guzas : 0
            balance : 0
            total : 0
            transactions count : 0
            engagements count : 0 

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
        self.assertEqual(birthday_block.version, VERSION)
        self.assertEqual(birthday_block.close_date, date(1998, 12, 21))
        self.assertEqual(birthday_block.previous_block_signature, EMPTY_HASH)
        self.assertEqual(birthday_block.merkle_root, EMPTY_HASH)
        self.assertEqual(birthday_block.signer, NEW_USER_PUB_KEY)
        self.assertEqual(birthday_block.transactions, [])
        self.assertEqual(birthday_block.engagements, [])
        self.assertTrue(vk.verify(birthday_block.signature, data))

        self.assertEqual(init_block.version, VERSION)
        self.assertIsNone(init_block.close_date)
        self.assertEqual(init_block.previous_block_signature, birthday_block.signature)
        self.assertEqual(init_block.merkle_root, EMPTY_HASH)
        self.assertEqual(init_block.signer, REF_PUB_KEY)
        self.assertEqual(init_block.transactions, [])
        self.assertEqual(init_block.engagements, [])
        self.assertIsNone(init_block.signature)

    def test_should_empty_previous_blockchain(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        self.assertEqual(len(blockchain), 2)


class TestUserBlockchainValidate(unittest.TestCase):

    @freeze_time("2011-12-13")
    def test_validate_should_fill_init_blocks(self):
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
        expected_merkle_root = guzi_hash(init_block.transactions[0].to_hash()+init_block.transactions[1].to_hash())
        expected_data = init_block.pack_for_hash()
        
        # Assert
        self.assertEqual(init_block.version, VERSION)
        self.assertEqual(init_block.close_date, date(2011, 12, 13))
        self.assertEqual(init_block.merkle_root, expected_merkle_root)
        self.assertEqual(len(init_block.transactions), 2)
        self.assertTrue(vk.verify(init_block.signature, expected_data))


class TestUserBlockchainPayToUser(unittest.TestCase):

    def test_should_create_payment_transaction(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        result = blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(result.tx_type, TxType.PAYMENT.value)

    def test_should_set_correct_amount(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()

        result = blockchain.pay_to_user(REF_PUB_KEY, 2)

        self.assertEqual(result.amount, 2)

    @freeze_time("2011-12-13")
    def test_should_set_correct_date(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        result = blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(result.date, date(2011,12,13))

    def test_should_set_correct_source(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        result = blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(result.source, NEW_USER_PUB_KEY)

    def test_should_set_correct_target(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        result = blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(result.target_user, REF_PUB_KEY)

    def test_should_set_correct_guzis(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()

        expected = blockchain._get_available_guzis(2)
        result = blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(result.guzis_positions, expected)

    def test_should_add_the_transaction_to_blockchain(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        blockchain.pay_to_user(REF_PUB_KEY, 1)

        self.assertEqual(len(blockchain[0].transactions), 2)

    def test_should_remove_used_guzis_from_availables(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.make_daily_guzis()

        blockchain.pay_to_user(REF_PUB_KEY, 1)
        guzis = blockchain._get_available_guzis()

        self.assertEqual(guzis, [])


class TestBlockchainEq(unittest.TestCase):

    @freeze_time("2011-12-13")
    def test_two_identic_basic_bc_are_equals(self):
        # Arrange
        birthdate = date(1998, 12, 21).isoformat()
        bc1 = UserBlockchain(NEW_USER_PUB_KEY)
        bc1.start(birthdate, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertEqual(bc1, bc1)

    @freeze_time("2011-12-13")
    def test_different_birthdate(self):
        # Arrange
        birthdate1 = date(1998, 12, 21).isoformat()
        bc1 = UserBlockchain(NEW_USER_PUB_KEY)
        bc1.start(birthdate1, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = date(1999, 11, 23).isoformat()
        bc2 = UserBlockchain(NEW_USER_PUB_KEY)
        bc2.start(birthdate2, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)

    @freeze_time("2011-12-13")
    def test_different_keys(self):
        # Arrange
        birthdate1 = date(1998, 12, 21).isoformat()
        bc1 = UserBlockchain(NEW_USER_PUB_KEY)
        bc1.start(birthdate1, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = date(1999, 11, 23).isoformat()
        bc2 = UserBlockchain(NEW_USER_PUB_KEY)
        bc2.start(birthdate2, REF_PRIV_KEY, NEW_USER_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)


class TestBlockchainSaveToFile(unittest.TestCase):

    @freeze_time("2011-12-13")
    def test_all_blocks_should_be_in(self):
         
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
        self.assertIn(block0, content)
        self.assertIn(block1, content)


class TestBlockchainAddTransaction(unittest.TestCase):

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
        transaction = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)

        # Act
        blockchain.add_transaction(transaction)

        # Assert
        self.assertEqual(len(blockchain), 3)
        self.assertIn(transaction, blockchain[0].transactions)


class TestBlockchainNewBlock(unittest.TestCase):

    def test_should_raise_exception_if_last_block_not_signed(self):
         
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()

        # Act
        with self.assertRaises(UnsignedPreviousBlockError):
            blockchain.new_block()

    def test_should_set_previous_block_hash(self):
         
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain.sign_last_block(REF_PRIV_KEY)

        # Act
        blockchain.new_block()

        # Assert
        self.assertEqual(blockchain[1].previous_block_signature, blockchain[0].signature)


class TestBlockchainReduce(unittest.TestCase):

    def test_should_return_total_blockchain_at_first_contact(self):
        
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[2]["pub"], 0)
        tx3 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[3]["pub"], 0)
        tx4 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[4]["pub"], 0)
        blockchain[0].add_transactions([tx0, tx1, tx2])
        blockchain.sign_last_block(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].add_transactions([tx3, tx4])

        # Act
        result = blockchain._reduce(KEY_POOL[5]["pub"])

        # Assert
        self.assertEqual(len(result), len(blockchain))

    def test_should_return_part_of_blockchain_at_second_contact(self):
        
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[2]["pub"], 0)
        tx3 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[3]["pub"], 0)
        tx4 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[4]["pub"], 0)
        blockchain[0].add_transactions([tx0, tx1, tx2])
        blockchain.sign_last_block(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].add_transactions([tx3, tx4])

        # Act
        result = blockchain._reduce(KEY_POOL[3]["pub"])

        # Assert
        self.assertEqual(len(result), 1)


class TestBlockchainReduceToDate(unittest.TestCase):

    @freeze_time("2011-12-13", tick=True)
    def test_should_return_total_blockchain_for_old_date(self):
        
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[2]["pub"], 0)
        tx3 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[3]["pub"], 0)
        tx4 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[4]["pub"], 0)
        blockchain[0].add_transactions([tx0, tx1, tx2])
        blockchain.sign_last_block(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].add_transactions([tx3, tx4])

        # Act
        result = blockchain._reduce_to_date(date(2011, 12, 13))

        # Assert
        self.assertEqual(len(result), len(blockchain))

    def test_should_return_only_block_after_date(self):
        
        # Arrange
        blockchain = make_blockchain()

        # Act
        result = blockchain._reduce_to_date(date(1998, 12, 24))

        # Assert
        self.assertEqual(len(result), 3)

    def test_should_return_last_block_for_later_date(self):
        
        # Arrange
        blockchain = make_blockchain()

        # Act
        result = blockchain._reduce_to_date(date(1998, 12, 28))

        # Assert
        self.assertEqual(len(result), 1)


class TestBlockchainSignLastBlock(unittest.TestCase):

    def test_basic_ok(self):

        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        
        # Act
        blockchain.sign_last_block(REF_PRIV_KEY)

        # Assert
        self.assertTrue(blockchain[0].is_signed())


@freeze_time("2011-12-13")
class TestBlockchainLoadFromFile(unittest.TestCase):

    def make_blockchain(self):
        blockchain_ref = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain_ref.start(
                birthdate=date(1998, 12, 21).isoformat(),
                my_privkey=NEW_USER_PRIV_KEY,
                ref_pubkey=REF_PUB_KEY)
        return blockchain_ref

    def test_hex_format(self):
         
        # Arrange
        blockchain_ref = self.make_blockchain()
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)

        # Assert
        self.assertEqual(blockchain, blockchain_ref)

    def test_transactions_are_the_same(self):
         
        # Arrange
        blockchain_ref = self.make_blockchain()
        blockchain_ref.validate(REF_PRIV_KEY)
        ref_transactions = blockchain_ref[0].transactions
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)
        transactions = blockchain[0].transactions

        # Assert
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions[0], ref_transactions[0])
        self.assertEqual(transactions[1], ref_transactions[1])


@freeze_time("2011-12-13")
class TestBlockchainLoadFromBytes(unittest.TestCase):

    def make_blockchain(self):
        blockchain_ref = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain_ref.start(
                birthdate=date(1998, 12, 21).isoformat(),
                my_privkey=NEW_USER_PRIV_KEY,
                ref_pubkey=REF_PUB_KEY)
        return blockchain_ref

    def test_hex_format(self):
         
        # Arrange
        blockchain_ref = self.make_blockchain()
        b = blockchain_ref.pack()

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_bytes(b)

        # Assert
        self.assertEqual(blockchain, blockchain_ref)

    def test_transactions_are_the_same(self):
         
        # Arrange
        blockchain_ref = self.make_blockchain()
        blockchain_ref.validate(REF_PRIV_KEY)
        ref_transactions = blockchain_ref[0].transactions
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.load_from_file(outfile)
        transactions = blockchain[0].transactions

        # Assert
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions[0], ref_transactions[0])
        self.assertEqual(transactions[1], ref_transactions[1])


class TestBlockchainGetAvailableGuzis(unittest.TestCase):

    @freeze_time("2011-12-13")
    def test_base_case(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4**3
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()

        # Assert
        self.assertEqual([["2011-12-13", [0, 1, 2, 3, 4]]], result)

    @freeze_time("2011-12-13", auto_tick_seconds=60*60*24)
    def test_should_return_all_dates(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4**3
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()
        expected = [
            ["2011-12-15", [0, 1, 2, 3, 4]],
            ["2011-12-14", [0, 1, 2, 3, 4]],
            ["2011-12-13", [0, 1, 2, 3, 4]]
        ]

        # Assert
        self.assertEqual(expected, result)

    @freeze_time("2011-12-13", auto_tick_seconds=60*60*24)
    def test_should_return_evolving_total(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4**3
        blockchain.make_daily_guzis()
        blockchain[0].total = 5**3
        blockchain.make_daily_guzis()
        blockchain[0].total = 6**3
        blockchain.make_daily_guzis()

        # Act
        result = blockchain._get_available_guzis()
        expected = [
            ["2011-12-15", [0, 1, 2, 3, 4, 5, 6]],
            ["2011-12-14", [0, 1, 2, 3, 4, 5]],
            ["2011-12-13", [0, 1, 2, 3, 4]]
        ]

        # Assert
        self.assertEqual(expected, result)

class TestUserBlockchainSpendGuzisFromAvailables(unittest.TestCase):

    @freeze_time("2011-12-13", auto_tick_seconds=60*60*24)
    def test_should_remove_older_guzis(self):
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4**3
        blockchain.make_daily_guzis()

        blockchain._spend_guzis_from_availables(blockchain._get_available_guzis(), 2)
        expected = [
            ["2011-12-13", [0, 1, 2]],
        ]

        self.assertEqual(expected, blockchain._get_available_guzis())


class TestBlockchainMakeDailyGuzis(unittest.TestCase):

    @freeze_time("1998-12-21", auto_tick_seconds=60*60*24)
    def test_should_create_GUZI_CREATE_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzis()
        tx = blockchain[0].transactions[0]

        # Assert
        self.assertEqual(tx.tx_type, TxType.GUZI_CREATE.value)

    @freeze_time("1998-12-21", auto_tick_seconds=60*60*24)
    def test_should_create_1_guzi_if_total_is_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzis()
        tx = blockchain[0].transactions[0]

        # Assert
        self.assertEqual(tx.guzis_positions, [[date(1998,12,24).isoformat(), [0]]])

    def test_should_create_6_guzi_if_total_is_125(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 125

        # Act
        tx = blockchain.make_daily_guzis()

        # Assert
        self.assertEqual(tx.guzis_positions, [[date.today().isoformat(), list(range(6))]])

    def test_should_use_given_date(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        dt = date(2001, 3, 22)

        # Act
        tx = blockchain.make_daily_guzis(dt)

        # Assert
        self.assertEqual(tx.guzis_positions, [[dt.isoformat(), [0]]])


class TestBlockchainMakeDailyGuzas(unittest.TestCase):

    def test_should_create_GUZA_CREATE_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzas()
        tx = blockchain[0].transactions[0]

        # Assert
        self.assertEqual(tx.tx_type, TxType.GUZA_CREATE.value)

    def test_should_create_1_guza_if_total_is_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()

        # Act
        blockchain.make_daily_guzas()
        tx = blockchain[0].transactions[0]

        # Assert
        self.assertEqual(tx.guzis_positions, [[date.today().isoformat(), [0]]])

    def test_should_create_6_guza_if_total_is_125(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 125

        # Act
        tx = blockchain.make_daily_guzas()

        # Assert
        self.assertEqual(tx.guzis_positions, [[date.today().isoformat(), list(range(6))]])

    def test_should_use_given_date(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        dt = date(2001, 3, 22)

        # Act
        tx = blockchain.make_daily_guzas(dt)

        # Assert
        self.assertEqual(tx.guzis_positions, [[dt.isoformat(), [0]]])


class TestBlockchainGetGuzisAmount(unittest.TestCase):

    def test_should_return_0_for_total_0(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = 0

        # Act
        result = blockchain._get_guzis_amount()

        # Assert
        self.assertEqual(result, 1)

    def test_should_raise_error_for_negative_total(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.start(BIRTHDATE, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        blockchain.validate(REF_PRIV_KEY)
        blockchain.new_block()
        blockchain[0].total = -125

        # Act
        # Assert
        with self.assertRaises(InvalidBlockchainError):
            blockchain._get_guzis_amount()


class TestBlockchainFindTransaction(unittest.TestCase):

    def test_should_return_None_if_not_found(self):
        # Arrange
        blockchain = make_blockchain()

        # Act
        result = blockchain._find_transaction(random_transaction())

        # Assert
        self.assertIsNone(result)

    def test_should_return_block_containing_transaction(self):
        # Arrange
        blockchain = make_blockchain()

        # Act
        result = blockchain._find_transaction(blockchain[2].transactions[0])
        for block in blockchain:
            print(block)
            print(block.transactions)

        # Assert
        self.assertEqual(result, blockchain[2])


class TestBlockchainRefuseTransaction(unittest.TestCase):

    def make_any_transaction(self):
        return Transaction(VERSION, TxType.PAYMENT.value, REF_PUB_KEY, 12, tx_date=date(1998, 12, 21).isoformat(), target_user=NEW_USER_PUB_KEY, signature=0x12)

    @freeze_time("2011-12-13")
    def test_should_return_a_refusal_transaction(self):
        # Arrange
        blockchain = UserBlockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        blockchain[0].total = 4**3
        blockchain.make_daily_guzis()

        # Action
        refused = self.make_any_transaction()
        refusal = blockchain.refuse_transaction(refused)
        
        # Assert
        self.assertEqual(refusal.tx_type, TxType.REFUSAL.value)
        self.assertEqual(refusal.date, date(2011, 12, 13))
        self.assertEqual(refusal.source, refused.target_user)
        self.assertEqual(refusal.amount, refused.amount)
        self.assertEqual(refusal.target_company, None)
        self.assertEqual(refusal.target_user, refused.source)
        self.assertEqual(refusal.guzis_positions, [])
        self.assertEqual(refusal.detail, refused.signature)

    def test_should_remove_transaction_from_last_block(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain.add_transaction(refused)

        # Action
        refusal = blockchain.refuse_transaction(refused)
        
        # Assert
        self.assertEqual(len(blockchain[0].transactions), 0)

    def test_should_raise_error_if_transaction_is_sealed(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain.add_transaction(refused)
        blockchain.sign_last_block(NEW_USER_PRIV_KEY)

        # Action
        # Assert
        with self.assertRaises(NotRemovableTransactionError):
            blockchain.refuse_transaction(refused)

    def test_should_raise_error_if_transaction_is_sealed_in_old_block(self):
        # Arrange
        blockchain = Blockchain(NEW_USER_PUB_KEY)
        blockchain.new_block()
        refused = self.make_any_transaction()
        blockchain.add_transaction(refused)
        blockchain.sign_last_block(NEW_USER_PRIV_KEY)
        blockchain.new_block()

        # Action
        # Assert
        with self.assertRaises(NotRemovableTransactionError):
            blockchain.refuse_transaction(refused)


class TestBlockchainContainTransaction(unittest.TestCase):

    def test_transaction_found(self):
        # Arrange
        # Act
        bc = make_blockchain()


        # Assert
        self.assertTrue(bc._contain_transaction(bc[2].transactions[0]))

    def test_transaction_not_found(self):
        # Arrange
        # Act
        bc = make_blockchain()


        # Assert
        self.assertFalse(bc._contain_transaction(random_transaction()))


class TestBlockContains(unittest.TestCase):

    def test_transaction_found(self):
         
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1, tx2])

        # Assert
        self.assertTrue(b._contain_transaction(tx0))
        self.assertTrue(b._contain_transaction(tx1))
        self.assertTrue(b._contain_transaction(tx2))


    def test_transaction_not_found(self):
         
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, TxType.GUZA_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, TxType.PAYMENT.value, NEW_USER_PUB_KEY, 0)
        b = Block()

        # Act
        b.add_transactions([tx1, tx2])

        # Assert
        self.assertFalse(b._contain_transaction(tx0))


class TestBlockContainUser(unittest.TestCase):

    def test_should_return_false_if_transaction_not_in(self):
         
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[1]["pub"], 0)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[2]["pub"], 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1, tx2])

        # Assert
        self.assertTrue(b._containUser(KEY_POOL[0]["pub"]))
        self.assertTrue(b._containUser(KEY_POOL[1]["pub"]))
        self.assertTrue(b._containUser(KEY_POOL[2]["pub"]))


    def test_should_return_true_if_transaction_in(self):
         
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[0]["pub"], 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, KEY_POOL[1]["pub"], 0)
        b = Block()

        # Act
        b.add_transactions([tx0, tx1])

        # Assert
        self.assertFalse(b._containUser(KEY_POOL[2]["pub"]))


class TestBlockPack(unittest.TestCase):

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
        # Arrange
        data = bytes.fromhex('9b01cb41cb3ec7c00000000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000000000')
        block = Block(
                close_date=date(1998, 12, 21).isoformat(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                balance=0, total=0)

        # Act
        result = block.pack_for_hash()

        # Assert
        # TODO When library will be stable
        # self.assertEqual(result, data)


class TestBlock(unittest.TestCase):

    def test_to_hash(self):
         
        # Arrange
        block = Block(
                date(1998, 12, 21).isoformat(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                balance=0, total=0)

        # Act
        result = block.to_hash()

        # Assert
        # TODO When library will be stable
        # self.assertEqual(result, bytes.fromhex('f8a98021264759eec491272b2d4939dcbc5f69ff3fba441ca6e05e1bc8daf4b5'))

    def test_sign(self):
         
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        block = Block(
                date(1998, 12, 21).isoformat(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                balance=0, total=0)
        data = block.pack_for_hash()

        # Act
        signature = block.sign(REF_PRIV_KEY)

        # Assert
        self.assertTrue(vk.verify(signature, data))

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
        self.assertIsNone(result)

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_1_tx(self):
        """
        If there is only 1 transaction, merkle root should be :
        hash(hash0 + hash0)
        """
        # Arrange
        tx = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        block = Block()
        block.add_transaction(tx)

        expected_merkle_root = guzi_hash(tx.to_hash()+tx.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_2_tx(self):
        """
        If there are 2 transactions, merkle root should be :
        hash(hash0 + hash1)
        """
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        block = Block()
        block.add_transactions([tx0, tx1])

        expected_merkle_root = guzi_hash(tx0.to_hash()+tx1.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    @freeze_time("2011-12-13")
    def test_compute_merkle_root_3_tx(self):
        """
        If there are 3 transactions, merkle root should be :
        hash(hash(hash0 + hash1) + hash(hash3 + hash3))
        """
        # Arrange
        tx0 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1 = Transaction(VERSION, TxType.GUZA_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx2 = Transaction(VERSION, TxType.GUZA_CREATE.value, REF_PUB_KEY, 0)
        block = Block()
        block.add_transactions([tx0, tx1, tx2])

        hash21 = guzi_hash(tx2.to_hash()+tx1.to_hash())
        hash00 = guzi_hash(tx0.to_hash()+tx0.to_hash())
        expected_merkle_root = guzi_hash(hash21+hash00)

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)


class TestBlockIsSigned(unittest.TestCase):

    def test_signed_block_should_return_true(self):
         
        # Arrange
        block = Block()
        block.sign(REF_PRIV_KEY)

        # Assert
        self.assertTrue(block.is_signed())

    def test_unsigned_block_should_return_false(self):
         
        # Arrange
        block = Block()

        # Assert
        self.assertFalse(block.is_signed())


class TestBlockAddTransactions(unittest.TestCase):

    def test_should_increase_transaction_count(self):
         
        # Arrange
        block = Block()
        tx = Transaction(VERSION, TxType.GUZI_CREATE.value, EMPTY_HASH, 0)

        # Act
        block.add_transaction(tx)

        # Assert
        self.assertEqual(len(block.transactions), 1)

    def test_shouldnt_add_existing_transaction_twice(self):
         
        # Arrange
        block = Block()
        tx = Transaction(VERSION, TxType.GUZI_CREATE.value, EMPTY_HASH, 0)

        # Act
        block.add_transaction(tx)
        block.add_transaction(tx)
        block.add_transaction(tx)

        # Assert
        self.assertEqual(len(block.transactions), 1)

    def test_should_raise_exception_if_too_much_transactions_in_last_block(self):
         
        # Arrange
        block = Block()
        tx = Transaction(VERSION, TxType.PAYMENT.value, NEW_USER_PUB_KEY, 0)

        for i in range(MAX_TX_IN_BLOCK):
           block.add_transaction(Transaction(VERSION, TxType.PAYMENT.value, NEW_USER_PUB_KEY, i))

        # Act
        with self.assertRaises(FullBlockError):
            block.add_transaction(tx)

    def test_should_raise_exception_if_block_is_already_signed(self):
         
        # Arrange
        block = Block()
        tx = Transaction(VERSION, TxType.GUZI_CREATE.value, EMPTY_HASH, 0)

        block.sign(REF_PRIV_KEY)

        # Act
        with self.assertRaises(FullBlockError):
            block.add_transaction(tx)


class TestBlockFindTransaction(unittest.TestCase):

    def test_found_transaction(self):
        block = Block()
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1.date = date(2011, 12, 13)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx2.date = date(2012, 11, 14)
        tx3 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx3.date = date(2013, 10, 15)

        # Act
        block.add_transactions([tx1, tx2, tx3])
        result = block.find_transaction(TxType.GUZI_CREATE.value, date(2012, 11, 14))

        # Assert
        self.assertEqual(result, tx2)

    def test_unfound_transaction(self):
        block = Block()
        tx1 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx1.date = date(2011, 12, 13)
        tx2 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx2.date = date(2012, 11, 14)
        tx3 = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0)
        tx3.date = date(2013, 10, 15)

        # Act
        block.add_transactions([tx1, tx2, tx3])
        result = block.find_transaction(TxType.GUZI_CREATE.value, date(2014, 11, 14))

        # Assert
        self.assertIsNone(result)


class TestTransactionSign(unittest.TestCase):

    @freeze_time("2011-12-13")
    def test_signature_should_be_valid(self):
         
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        # Act
        tx = Transaction(VERSION, TxType.GUZI_CREATE.value, NEW_USER_PUB_KEY, 0,
                date(2011, 12, 13).isoformat())
        data = tx.pack_for_hash()
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertTrue(vk.verify(tx.signature, data))



from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize, precondition
from hypothesis import note, strategies as st

class UserBlockchainStateMachine(RuleBasedStateMachine):

    bc = None
    
    @initialize(birthdate=st.dates(),
            my_key_pair=st.sampled_from(KEY_POOL),
            ref_key_pair=st.sampled_from(KEY_POOL))
    def init_blockchain(self, birthdate, my_key_pair, ref_key_pair):
        self.bc = UserBlockchain(my_key_pair['pub'])
        self.bc.start(birthdate.isoformat(), my_key_pair['priv'], ref_key_pair['pub'])
        self.bc.validate(ref_key_pair['priv'], birthdate)
        self.bc.new_block()

        self.guzis = 1
        self.current_date = birthdate
        self.guzis_made_today = True

    @rule()
    def new_day(self):
        self.current_date += timedelta(days=1)
        self.guzis_made_today = False

    @rule()
    def create_guzis(self):
        if not self.guzis_made_today:
            note(self.guzis)
            note(self.bc._get_guzis_amount())
            self.guzis += self.bc._get_guzis_amount()
            self.guzis_made_today = True
        self.bc.make_daily_guzis(self.current_date)

    @precondition(lambda self: self.bc is not None)
    @invariant()
    def check_guzis(self):
        assert self.guzis == self.bc._get_available_guzis_amount()


UserBlockchainTests = UserBlockchainStateMachine.TestCase
