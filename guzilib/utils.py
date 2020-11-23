import hashlib
import ecdsa
import umsgpack
from enum import Enum




EMPTY_HASH = 0
VERSION = 1
MAX_TX_IN_BLOCK = 30


def guzi_hash(data):
    return hashlib.sha256(data).digest()


class TxType(Enum):

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


class GuziError(Exception):
    """ Base class for Guzi exceptions """
    pass
class UnsignedPreviousBlockError(GuziError):
    pass
class FullBlockError(GuziError):
    pass
class NotRemovableTransactionError(GuziError):
    pass
class InvalidBlockchainError(GuziError):
    pass


class Packer:
    def pack_transaction(self, transaction):
        return NotImplemented

    def pack_transaction_without_hash(self, transaction):
        return NotImplemented

    def pack_block(self, block):
        return NotImplemented

    def pack_block_without_hash(self, block):
        return NotImplemented

    def pack_bloockchain(self, blockchain, outfile=None):
        return NotImplemented


class BytePacker(Packer):

    def pack_transaction(self, transaction):
        return umsgpack.packb(transaction.as_full_list())

    def pack_transaction_without_hash(self, transaction):
        return umsgpack.packb(transaction.as_list())

    def pack_block(self, block):
        return umsgpack.packb(block.as_full_list())

    def pack_block_without_hash(self, block):
        return umsgpack.packb(block.as_list())

    def pack_bloockchain(self, blockchain, outfile=None):
        if outfile is not None:
            umsgpack.pack([b.pack() for b in blockchain], outfile)
        else:
            return umsgpack.packb([b.pack() for b in blockchain])


class Packable:
    def pack_for_hash(self):
        return NotImplemented


class Signable(Packable):

    def to_hash(self):
        return guzi_hash(self.pack_for_hash())

    def sign(self, privkey):
        """
        privkey : int
        return bytes
        """
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        self.signature = sk.sign(self.pack_for_hash())
        return self.signature


class Company:

    def __init__(self, company_pubkey, my_pubkey):
        pass

    def set_owner_order(self, my_privkey, owner, value, detail=""):
        pass

    def set_admin_order(self, my_privkey, admin, value, detail=""):
        pass

    def set_worker_order(self, my_privkey, worker, value, detail=""):
        pass

    def set_payer_order(self, my_privkey, payer, value, detail=""):
        pass

    def leave_order(self, my_privkey, detail=""):
        pass

    def pay_order(self, my_privkey, target, amount):
        pass
