import unittest
import pytz
import ecdsa
from datetime import datetime
from guzi_lib import Block, create_empty_block, create_empty_init_blocks

NEW_USER_PUB_KEY = 0x02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b
NEW_USER_PRIV_KEY = 0xcdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6
REF_PUB_KEY =  0x031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d
REF_PRIV_KEY = 0x7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca
EMPTY_HASH = 0x0000000000000000000000000000000000000000000000000000000000000000
TEST_HASH = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 # Hash of "test"

class TestBlock(unittest.TestCase):

    def test_to_hex(self):
        """
        "01;birthday_date;random_hash;useless_merkle_root;
        new_user_public_key;0;0;0;0;0;(no transaction);0;
        (no engagement);hash0"
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
                close_date=datetime(1998, 12, 21,0,0,0,0,tzinfo=pytz.utc),
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
                close_date=datetime(1998, 12, 21,0,0,0,0,tzinfo=pytz.utc),
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
                close_date=datetime(1998, 12, 21,0,0,0,0,tzinfo=pytz.utc),
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
        Birthday block :
            "01;birthday_date;random_hash;useless_merkle_root;
            new_user_public_key;0;0;0;0;0;(no transaction);0;
            (no engagement);hash0"
            01 367D8F80 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b 0000 0000 0000 00000000 0000 0000 
            => hash = 0x2921cf75ae9246f8492d5781109a135106fe49daa626dd2239c6674c0330e16f
            => signed hash = 
        Initialisation block ;
            "01;today_date;hash0;merkle_root;
            reference_public_key;0;0;0;0;2;transactions_init;
            0;(no engagement);hash"
        """

        # Arrange
        birthdate = datetime(1998, 12, 21)

        # Act
        blocks = create_empty_init_blocks(birthdate, NEW_USER_PUB_KEY, REF_PUB_KEY)
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
        #self.assertEqual(birthday_block.hash, "")

        self.assertEqual(init_block.version, 0x01)
