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

        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        
        # Act
        bc = Blockchain()
        bc.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthday_block, init_block = bc
        data = birthday_block.pack()

        # Assert
        self.assertEqual(birthday_block.version, 0x01)
        self.assertEqual(birthday_block.close_date, datetime(1998, 12, 21,0,0,0,0))
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

        self.assertEqual(init_block.version, 0x01)
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
        expected_data = init_block.pack()
        
        # Assert
        self.assertEqual(init_block.version, 1)
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
        block0 = bc[0].pack()
        block1 = bc[1].pack()
        outfile = BytesIO()

        # Act
        bc.save_to_file(outfile)
        outfile.seek(0)
        content = outfile.read()

        # Assert
        self.assertIn(block0, content)
        self.assertIn(block1, content)


class TestBlockchainLoadFromFile(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_hex_format(self):
        # Arrange
        birthdate = datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp()
        bc_ref = Blockchain()
        bc_ref.start(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        outfile = BytesIO()
        bc_ref.save_to_file(outfile)
        outfile.seek(0)

        # Act
        bc = Blockchain()
        bc.load_from_file(outfile)

        # Assert
        self.assertEqual(bc, bc_ref)


class TestBlockPack(unittest.TestCase):

    def test_pack(self):
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
        data = bytes.fromhex('9b01cb41cb3ec0b80000000000c42102071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000009090')
        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)

        # Act
        result = block.pack()

        # Assert
        self.assertEqual(result, data)


class TestBlock(unittest.TestCase):

    def test_to_hash(self):
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
        self.assertEqual(result, bytes.fromhex('a12ecf46006b5b720af5731364b835ad2261d3acdd9ca44763562d8e5f036a51'))

    def test_sign(self):
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(REF_PUB_KEY, curve=ecdsa.SECP256k1)

        block = Block(
                datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc).timestamp(),
                previous_block_signature=EMPTY_HASH,
                merkle_root=EMPTY_HASH,
                signer=NEW_USER_PUB_KEY,
                guzis=0, guzas=0, balance=0, total=0)
        data = block.pack()

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
        data = tx.pack()
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
        data = tx.pack()
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.tx_type, 0x01)
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.signature, data))
