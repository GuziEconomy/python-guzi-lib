import unittest
import pytz
import ecdsa
import os
import random

from io import BytesIO
from freezegun import freeze_time
import datetime

from guzi_lib import *

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


def make_block(length):
    block = Block()
    for i in range(length):
        block.add_transaction(Transaction(
            version=VERSION, tx_type=1, source=os.urandom(33),
            amount=random.randint(1,10),
            tx_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
            target_user=us.urandom(33)))
    return block

def make_blockchain(length):
    pass


class TestBlockchainStart(unittest.TestCase):

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

        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        
        # Act
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthday_block, init_block = bc
        data = birthday_block.pack_for_hash()

        # Assert
        self.assertEqual(birthday_block.version, VERSION)
        self.assertEqual(birthday_block.close_date, datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc))
        self.assertEqual(birthday_block.previous_block_signature, EMPTY_HASH)
        self.assertEqual(birthday_block.merkle_root, EMPTY_HASH)
        self.assertEqual(birthday_block.signer, NEW_USER_PUB_KEY)
        self.assertEqual(birthday_block.guzis, 0)
        self.assertEqual(birthday_block.guzas, 0)
        self.assertEqual(birthday_block.balance, 0)
        self.assertEqual(birthday_block.total, 0)
        self.assertEqual(birthday_block.transactions, [])
        self.assertEqual(birthday_block.engagements, [])
        self.assertTrue(vk.verify(birthday_block.signature, data))

        self.assertEqual(init_block.version, VERSION)
        self.assertEqual(init_block.close_date, None)
        self.assertEqual(init_block.previous_block_signature, birthday_block.signature)
        self.assertEqual(init_block.merkle_root, EMPTY_HASH)
        self.assertEqual(init_block.signer, REF_PUB_KEY)
        self.assertEqual(init_block.guzis, 0)
        self.assertEqual(init_block.guzas, 0)
        self.assertEqual(init_block.balance, 0)
        self.assertEqual(init_block.total, 0)
        self.assertEqual(init_block.transactions, [])
        self.assertEqual(init_block.engagements, [])
        self.assertEqual(init_block.signature, EMPTY_HASH)


class TestBlockchainValidate(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
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

        birthdate = datetime(1998, 12, 21).timestamp()
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        # Act
        bc.validate(REF_PRIV_KEY)
        init_block = bc[1]
        expected_merkle_root = guzi_hash(init_block.transactions[0].to_hash()+init_block.transactions[1].to_hash())
        expected_data = init_block.pack_for_hash()
        
        # Assert
        self.assertEqual(init_block.version, VERSION)
        self.assertEqual(init_block.close_date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(init_block.merkle_root, expected_merkle_root)
        self.assertEqual(init_block.guzis, 1)
        self.assertEqual(init_block.guzas, 1)
        self.assertEqual(init_block.balance, 0)
        self.assertEqual(init_block.total, 0)
        self.assertEqual(len(init_block.transactions), 2)
        self.assertTrue(vk.verify(init_block.signature, expected_data))
        

class TestBlockchainEq(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_two_identic_basic_bc_are_equals(self):
        # Arrange
        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc1 = Blockchain()
        bc1.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertEqual(bc1, bc1)

    @freeze_time("2011-12-13 12:34:56")
    def test_different_birthdate(self):
        # Arrange
        birthdate1 = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc1 = Blockchain()
        bc1.start(birthdate1, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = datetime(1999, 11, 23,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc2 = Blockchain()
        bc2.start(birthdate2, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)

    @freeze_time("2011-12-13 12:34:56")
    def test_different_keys(self):
        # Arrange
        birthdate1 = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc1 = Blockchain()
        bc1.start(birthdate1, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = datetime(1999, 11, 23,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc2 = Blockchain()
        bc2.start(birthdate2, REF_PUB_KEY, REF_PRIV_KEY, NEW_USER_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)


class TestBlockchainSaveToFile(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_all_blocks_should_be_in(self):
        # Arrange
        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        bc.validate(REF_PRIV_KEY)
        block0 = bc[0].pack().hex()
        block1 = bc[1].pack().hex()
        outfile = BytesIO()

        # Act
        bc.save_to_file(outfile)
        outfile.seek(0)
        content = outfile.read().hex()

        # Assert
        self.assertIn(block0, content)
        self.assertIn(block1, content)


class TestBlockchainAddTransaction(unittest.TestCase):

    def test_previous_block_is_full(self):
        pass


@freeze_time("2011-12-13 12:34:56")
class TestBlockchainLoadFromFile(unittest.TestCase):

    def make_blockchain(self):
        blockchain_ref = Blockchain()
        blockchain_ref.start(
                birthdate=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                new_pubkey=NEW_USER_PUB_KEY,
                new_privkey=NEW_USER_PRIV_KEY,
                ref_pubkey=REF_PUB_KEY)
        return blockchain_ref

    def test_hex_format(self):
        """
        """
        # Arrange
        blockchain_ref = self.make_blockchain()
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain()
        blockchain.load_from_file(outfile)

        # Assert
        self.assertEqual(blockchain, blockchain_ref)

    def test_transactions_are_the_same(self):
        """
        """
        # Arrange
        blockchain_ref = self.make_blockchain()
        blockchain_ref.validate(REF_PRIV_KEY)
        ref_transactions = blockchain_ref[1].transactions
        outfile = BytesIO()
        blockchain_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        blockchain = Blockchain()
        blockchain.load_from_file(outfile)
        transactions = blockchain[1].transactions

        # Assert
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions[0], ref_transactions[0])
        self.assertEqual(transactions[1], ref_transactions[1])


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
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)

        # Act
        result = block.pack_for_hash()

        # Assert
        self.assertEqual(result, data)


class TestBlock(unittest.TestCase):

    def test_to_hash(self):
        """
        """
        # Arrange
        block = Block(
                datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)

        # Act
        result = block.to_hash()

        # Assert
        self.assertEqual(result, bytes.fromhex('f8a98021264759eec491272b2d4939dcbc5f69ff3fba441ca6e05e1bc8daf4b5'))

    def test_sign(self):
        """
        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        block = Block(
                datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)
        data = block.pack_for_hash()

        # Act
        signature = block.sign(REF_PRIV_KEY)

        # Assert
        self.assertTrue(vk.verify(signature, data))

    def test_add_transaction(self):
        """
        """
        # Arrange
        block = Block()
        tx = GuziCreationTransaction(EMPTY_HASH, Block())

        # Act
        block.add_transaction(tx)

        # Assert
        self.assertEqual(len(block.transactions), 1)

    @freeze_time("2011-12-13 12:34:56")
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

    @freeze_time("2011-12-13 12:34:56")
    def test_compute_merkle_root_1_tx(self):
        """
        If there is only 1 transaction, merkle root should be :
        hash(hash0 + hash0)
        """
        # Arrange
        tx = GuziCreationTransaction(NEW_USER_PUB_KEY, Block())
        block = Block()
        block.add_transaction(tx)

        expected_merkle_root = guzi_hash(tx.to_hash()+tx.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    @freeze_time("2011-12-13 12:34:56")
    def test_compute_merkle_root_2_tx(self):
        """
        If there are 2 transactions, merkle root should be :
        hash(hash0 + hash1)
        """
        # Arrange
        tx0 = GuziCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx1 = GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        block = Block()
        block.add_transactions([tx0, tx1])

        expected_merkle_root = guzi_hash(tx0.to_hash()+tx1.to_hash())

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    @freeze_time("2011-12-13 12:34:56")
    def test_compute_merkle_root_3_tx(self):
        """
        If there are 3 transactions, merkle root should be :
        hash(hash(hash0 + hash1) + hash(hash3 + hash3))
        """
        # Arrange
        tx0 = GuziCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx1 = GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx2 = GuzaCreationTransaction(REF_PUB_KEY, Block())
        block = Block()
        block.add_transactions([tx0, tx1, tx2])

        hash01 = guzi_hash(tx0.to_hash()+tx1.to_hash())
        hash22 = guzi_hash(tx2.to_hash()+tx2.to_hash())
        expected_merkle_root = guzi_hash(hash01+hash22)

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    def test_compute_transactions_with_1_guzis(self):
        # Arrange
        block = Block(guzis=0)
        block.add_transaction(GuziCreationTransaction(NEW_USER_PUB_KEY, Block()))

        # Act
        block.compute_transactions(None)

        # Assert
        self.assertEqual(block.guzis, 1)

    def test_compute_transactions_with_1_guzas(self):
        # Arrange
        block = Block(guzas=0)
        block.add_transaction(GuzaCreationTransaction(NEW_USER_PUB_KEY, Block()))

        # Act
        block.compute_transactions()

        # Assert
        self.assertEqual(block.guzas, 1)


class TestGuziCreationTransaction(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_init_should_create_1_guzi_for_empty_total(self):
        """

        bytes : 
        - version : 1
        - type : 0
        - datetime : 1323779696.0
        - source : 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        - amount : 1

        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        # Act
        tx = GuziCreationTransaction(NEW_USER_PUB_KEY, Block())
        data = tx.pack_for_hash()
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.tx_type, 0x00)
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.signature, data))


class TestGuzaCreationTransaction(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_init_should_create_1_guza_for_empty_total(self):
        """

        bytes : 
        - version : 1
        - type : 1
        - datetime : 1323779696.0
        - source : 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        - amount : 1

        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(NEW_USER_PUB_KEY, curve=ecdsa.SECP256k1)

        # Act
        tx = GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        data = tx.pack_for_hash()
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.signature, data))
