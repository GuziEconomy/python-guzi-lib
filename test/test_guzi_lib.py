import unittest
import pytz
import ecdsa

from io import BytesIO
from freezegun import freeze_time
import datetime

from guzi_lib import *

NEW_USER_PUB_KEY = bytes.fromhex("02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b")
NEW_USER_PRIV_KEY = bytes.fromhex("cdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6")
REF_PUB_KEY =  bytes.fromhex("031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d")
REF_PRIV_KEY = bytes.fromhex("7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca")
EMPTY_HASH = 0
TEST_HASH = bytes.fromhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") # Hash of "test"

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
        data = bytes.fromhex('9b01cb41cb3ec7c00000000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000000000')

        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
        
        # Act
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthday_block, init_block = bc

        # Assert
        self.assertEqual(birthday_block.version, 0x01)
        self.assertEqual(birthday_block.close_date, birthdate)
        self.assertEqual(birthday_block.previous_block_hash, EMPTY_HASH)
        self.assertEqual(birthday_block.merkle_root, EMPTY_HASH)
        self.assertEqual(birthday_block.signer, NEW_USER_PUB_KEY)
        self.assertEqual(birthday_block.guzis, 0)
        self.assertEqual(birthday_block.guzas, 0)
        self.assertEqual(birthday_block.balance, 0)
        self.assertEqual(birthday_block.total, 0)
        self.assertEqual(birthday_block.transactions, [])
        self.assertEqual(birthday_block.engagements, [])
        self.assertTrue(vk.verify(birthday_block.hash, data))

        self.assertEqual(init_block.version, 0x01)
        self.assertEqual(init_block.close_date, None)
        self.assertEqual(init_block.previous_block_hash, birthday_block.hash)
        self.assertEqual(init_block.merkle_root, EMPTY_HASH)
        self.assertEqual(init_block.signer, REF_PUB_KEY)
        self.assertEqual(init_block.guzis, 0)
        self.assertEqual(init_block.guzas, 0)
        self.assertEqual(init_block.balance, 0)
        self.assertEqual(init_block.total, 0)
        self.assertEqual(init_block.transactions, [])
        self.assertEqual(init_block.engagements, [])
        self.assertEqual(init_block.hash, EMPTY_HASH)


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
        expected_merkle_root = bytes.fromhex("dde4a7d066bcbb3d6a25bd6f1517b535f470503117cba613c2b05c112a8f0aa8")

        birthdate = datetime(1998, 12, 21)
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        data = bytes.fromhex('9b01cb41d3b9d19c000000c440'+bc[0].hash.hex()+'c420dde4a7d066bcbb3d6a25bd6f1517b535f470503117cba613c2b05c112a8f0aa8c421031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d010100000200')
        # Act
        bc.validate(REF_PRIV_KEY)
        init_block = bc[1]
        
        # Assert
        self.assertEqual(init_block.version, 1)
        self.assertEqual(init_block.close_date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(init_block.merkle_root, expected_merkle_root)
        self.assertEqual(init_block.guzis, 1)
        self.assertEqual(init_block.guzas, 1)
        self.assertEqual(init_block.balance, 0)
        self.assertEqual(init_block.total, 0)
        self.assertEqual(len(init_block.transactions), 2)
        self.assertTrue(vk.verify(init_block.hash, data))
        

class TestBlockchainEq(unittest.TestCase):
    @freeze_time("2011-12-13 12:34:56")
    def test_two_identic_basic_bc_are_equals(self):
        # Arrange
        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
        bc1 = Blockchain()
        bc1.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertEqual(bc1, bc1)

    @freeze_time("2011-12-13 12:34:56")
    def test_different_birthdate(self):
        # Arrange
        birthdate1 = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
        bc1 = Blockchain()
        bc1.start(birthdate1, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = datetime(1999, 11, 23,0,0,0,0, tzinfo=pytz.utc)
        bc2 = Blockchain()
        bc2.start(birthdate2, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)

    @freeze_time("2011-12-13 12:34:56")
    def test_different_keys(self):
        # Arrange
        birthdate1 = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
        bc1 = Blockchain()
        bc1.start(birthdate1, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthdate2 = datetime(1999, 11, 23,0,0,0,0, tzinfo=pytz.utc)
        bc2 = Blockchain()
        bc2.start(birthdate2, REF_PUB_KEY, REF_PRIV_KEY, NEW_USER_PUB_KEY)

        # Assert
        self.assertNotEqual(bc1, bc2)
        self.assertNotEqual(bc2, bc1)


#class TestBlockchainSaveToFile(unittest.TestCase):
#    @freeze_time("2011-12-13 12:34:56")
#    def test_hex_format(self):
#        # Arrange
#        data1 = bytes.fromhex('01367d8f800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b0000000000000000000000000000000100000000')
#        data2 = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d000000000000000000000000000000')
#        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
#        bc = Blockchain()
#        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
#
#        outfile = BytesIO()
#
#        # Act
#        bc.save_to_file(outfile)
#        outfile.seek(0)
#        content = outfile.read()
#
#        # Assert
#        self.assertIn(data1, content)
#        self.assertIn(data2, content)


#class TestBlockchainLoadFromFile(unittest.TestCase):
#    @freeze_time("2011-12-13 12:34:56")
#    def test_hex_format(self):
#        # Arrange
#        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc)
#        bc_ref = Blockchain()
#        bc_ref.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
#        outfile = BytesIO()
#        bc_ref.save_to_file(outfile)
#
#        # Act
#        bc = Blockchain()
#        bc.load_from_file(outfile)
#
#        # Assert
#        self.assertEqual(bc, bc_ref)


class TestBlock(unittest.TestCase):

    def test___bytes__(self):
        """
        Type: 01
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
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        result = bytes(block)

        # Assert
        self.assertEqual(result, data)

    def test_to_hash(self):
        # Arrange
        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        result = block.to_hash()

        # Assert
        self.assertEqual(result, bytes.fromhex('e7cd2f787d81df4ee7df7a31631f915f1e64fe51e5cdffa68a370e939b6a1681'))

    def test_sign(self):
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)
        data = bytes.fromhex('9b01cb41cb3ec7c00000000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000000000')

        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        signature = block.sign(REF_PRIV_KEY)

        # Assert
        self.assertTrue(vk.verify(signature, data))

    def test_add_transaction(self):
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
        block = Block(transactions=[
            GuziCreationTransaction(NEW_USER_PUB_KEY, Block()),
        ])

        expected_merkle_root = bytes.fromhex("69bb88f1ca872e50f65c167bccb3049a09c98d6a2c002725328fbfc4652cb974")

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
        block = Block(transactions=[
            GuziCreationTransaction(NEW_USER_PUB_KEY, Block()),
            GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        ])

        expected_merkle_root = bytes.fromhex("dde4a7d066bcbb3d6a25bd6f1517b535f470503117cba613c2b05c112a8f0aa8")

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
        block = Block(transactions=[
            GuziCreationTransaction(NEW_USER_PUB_KEY, Block()),
            GuzaCreationTransaction(NEW_USER_PUB_KEY, Block()),
            GuzaCreationTransaction(REF_PUB_KEY, Block())
        ])

        expected_merkle_root = bytes.fromhex("00ceedb26795490a27dfe9c2d605c52af32e1681ac161e55f9430972b9ff3147")

        # Act
        result = block.compute_merkle_root()

        # Assert
        self.assertEqual(result, expected_merkle_root)

    def test_compute_transactions_with_1_guzis(self):
        # Arrange
        block = Block(previous_block=Block(guzis=0), transactions=[
            GuziCreationTransaction(NEW_USER_PUB_KEY, Block()),
        ])

        # Act
        block.compute_transactions()

        # Assert
        self.assertEqual(block.guzis, 1)

    def test_compute_transactions_with_1_guzas(self):
        # Arrange
        block = Block(previous_block=Block(guzas=0), transactions=[
            GuzaCreationTransaction(NEW_USER_PUB_KEY, Block()),
        ])

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
        data = bytes.fromhex('950100cb41d3b9d19c000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b01')

        # Act
        tx = GuziCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.tx_type, 0x00)
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.hash, data))


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
        data = bytes.fromhex('950101cb41d3b9d19c000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b01')

        # Act
        tx = GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.tx_type, 0x01)
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.hash, data))
