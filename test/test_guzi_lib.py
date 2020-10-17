import unittest
from guzi_lib import Block, create_empty_block

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
        self.assertEqual(new_block.version, 1)
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
