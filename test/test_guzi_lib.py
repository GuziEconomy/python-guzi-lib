import unittest
import pytz
import ecdsa
from freezegun import freeze_time
import datetime
from guzi_lib import *

NEW_USER_PUB_KEY = 0x02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
NEW_USER_PRIV_KEY = 0xcdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6
REF_PUB_KEY =  0x031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d
REF_PRIV_KEY = 0x7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca
EMPTY_HASH = 0x0000000000000000000000000000000000000000000000000000000000000000
TEST_HASH = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 # Hash of "test"

class TestBlock(unittest.TestCase):

    def test_to_hex(self):
        """
        Type: 01
        Date (1998/12/21): 367D8F80
        Previous_block_hash: 0000000000000000000000000000000000000000000000000000000000000000 
        Merkle_root: 0000000000000000000000000000000000000000000000000000000000000000 
        Signer: 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        guzis: 0000
        guzas: 0000
        balance: 000000
        total: 00000000
        transactions count: 0000
        engagements count: 0000 
        """
        # Arrange
        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0,
                guzas=0,
                balance=0,
                total=0
                )
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        result = block.to_hex()

        # Assert
        self.assertEqual(result, '01367d8f800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b000000000000000000000000000000')

    def test_to_hash(self):
        # Arrange
        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0,
                guzas=0,
                balance=0,
                total=0
                )
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        result = block.to_hash()

        # Assert
        self.assertEqual(result, 'f2fd3898d6a01cf33d71b08c5af00d62edb39570cb04392a3adea7addf207e7f')


    def test_sign(self):
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(f"{REF_PUB_KEY:066x}"), curve=ecdsa.SECP256k1)
        hash = "f2fd3898d6a01cf33d71b08c5af00d62edb39570cb04392a3adea7addf207e7f" 
        data = hash.encode()

        block = Block(
                close_date=datetime(1998, 12, 21,0,0,0,0, tzinfo=pytz.utc),
                signer=NEW_USER_PUB_KEY,
                guzis=0,
                guzas=0,
                balance=0,
                total=0
                )
        block.previous_block_hash = EMPTY_HASH
        block.merkle_root = EMPTY_HASH

        # Act
        signature = block.sign(REF_PRIV_KEY)

        # Assert
        self.assertTrue(vk.verify(signature, data))



class TestGuzi(unittest.TestCase):

    def test_create_empty_block(self):
        # Arrange
        previous_block = Block()
        previous_block.hash = "aaa"
        previous_block.guzis = 1
        previous_block.guzas = 2
        previous_block.balance = 3
        previous_block.total = 4
        
        # Act
        new_block = create_empty_block(previous_block)
        
        # Assert
        self.assertEqual(new_block.version, 0x01)
        self.assertEqual(new_block.close_date, None)
        self.assertEqual(new_block.previous_block_hash, "aaa")
        self.assertEqual(new_block.merkle_root, None)
        self.assertEqual(new_block.signer, None)
        self.assertEqual(new_block.guzis, 1)
        self.assertEqual(new_block.guzas, 2)
        self.assertEqual(new_block.balance, 3)
        self.assertEqual(new_block.total, 4)
        self.assertEqual(new_block.transactions, [])
        self.assertEqual(new_block.engagements, [])
        self.assertEqual(new_block.hash, None)

    def test_create_empty_init_blocks(self):
        """

        When a user creates his account, he creates 2 blocks :
        1. The first block is called the birthday block and contains the public
        key of this newly created user plus his birthday date.
        2. The second block contains the first Guzis (and Guzas) creation, and
        is signed by the reference.
        A reference is a person or an entity in whose a group of user gives
        confidence.

        create_empty_init_blocks create blocks with empty data to be filled by
        the reference (if reference accepts to sign, of course).

        Content of Birthday block :
            In bytes :
            - type : 01
            - date : 367D8F80
            - empty hash : EMPTY_HASH
            - empty merkle : EMPTY_HASH
            - user id : NEW_USER_PUB_KEY
            - guzis : 0000
            - guzas : 0000
            - balance : 000000
            - total : 00000000
            - transactions count : 0000
            - engagements count : 0000 
        Initialisation block :
            - type : 01
            - date : None
            - hash_of_birthday_block : ae0810100c034105cab7df985befd1d7042333682bcab09397b5bcadf370e146
            - empty_merkle_root : EMPTY_HASH
            - reference_public_key : REF_PUB_KEY
            - guzis : 0000
            - guzas : 0000
            - balance : 000000
            - total : 00000000
            - transactions count : 0000
            - engagements count : 0000 

        """

        # Arrange
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(f"{NEW_USER_PUB_KEY:066x}"), curve=ecdsa.SECP256k1)
        hash = "ae0810100c034105cab7df985befd1d7042333682bcab09397b5bcadf370e146" 
        data = hash.encode()

        birthdate = datetime(1998, 12, 21)

        # Act
        blocks = create_empty_init_blocks(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)
        birthday_block, init_block = blocks
        
        # Assert
        self.assertEqual(len(blocks), 2)

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

    @freeze_time("2011-12-13 12:34:56")
    def test_fill_init_blocks(self):
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
            - type : 01
            - date : Today's date
            - hash_of_birthday_block : ae0810100c034105cab7df985befd1d7042333682bcab09397b5bcadf370e146
            - empty_merkle_root : TODO
            - reference_public_key : REF_PUB_KEY
            - guzis : 0001
            - guzas : 0001
            - balance : 000000
            - total : 00000000
            - transactions count : 0002
            - transactions :
                - create 1 guzi
                - create 1 guza
            - engagements count : 0000 

        """
        # Arrange
        # vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(f"{NEW_USER_PUB_KEY:066x}"), curve=ecdsa.SECP256k1)
        # hash = "ae0810100c034105cab7df985befd1d7042333682bcab09397b5bcadf370e146" 
        # data = hash.encode()

        birthdate = datetime(1998, 12, 21)
        blocks = create_empty_init_blocks(birthdate, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY, REF_PUB_KEY)

        # Act
        _, init_block = fill_init_blocks(blocks, REF_PRIV_KEY)
        
        # Assert
        self.assertEqual(init_block.version, 0x01)
        self.assertEqual(init_block.close_date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        # self.assertEqual(init_block.merkle_root, EMPTY_HASH)
        # self.assertEqual(init_block.guzis, 1)
        # self.assertEqual(init_block.guzas, 1)
        # self.assertEqual(init_block.balance, 0)
        # self.assertEqual(init_block.total, 0)
        # self.assertEqual(init_block.transactions, [])
        # self.assertEqual(init_block.engagements, [])
        # self.assertEqual(init_block.hash, EMPTY_HASH)


class TestGuziCreationTransaction(unittest.TestCase):

    @freeze_time("2011-12-13 12:34:56")
    def test_init_should_create_1_guzi_for_empty_total(self):
        """

        bytes : 
        - version : 01
        - type : 00
        - datetime : 4ee74670
        - source : 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        - amount : 0001

         01004ee7467002071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b0001

        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(f"{NEW_USER_PUB_KEY:066x}"), curve=ecdsa.SECP256k1)
        hash = "c472bbbe7b2424aaa9b159e181aac5df954f8ea5d6b362c17201facf8b1cf217" 
        data = hash.encode()

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
        - version : 01
        - type : 01
        - datetime : 4ee74670
        - source : 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
        - amount : 0001

         01014ee7467002071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b0001

        """
        # Arrange
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(f"{NEW_USER_PUB_KEY:066x}"), curve=ecdsa.SECP256k1)
        hash = "9fed68e125157c6aa1607e51e5f3589de850eb4c1e817d829906ce9c86b689ff" 
        data = hash.encode()

        # Act
        tx = GuzaCreationTransaction(NEW_USER_PUB_KEY, Block())
        tx.sign(NEW_USER_PRIV_KEY)

        # Assert
        self.assertEqual(tx.tx_type, 0x01)
        self.assertEqual(tx.source, NEW_USER_PUB_KEY)
        self.assertEqual(tx.date, datetime(2011, 12, 13, 12, 34, 56, tzinfo=pytz.utc))
        self.assertEqual(tx.amount, 1)
        self.assertTrue(vk.verify(tx.hash, data))
