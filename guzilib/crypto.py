import hashlib
import itertools

import ecdsa

EMPTY_HASH = 0


class Packable:
    def hash(self):
        return NotImplemented

    def sign(self, signature):
        """
        signature : bytes

        :returns: bytes
        """
        # TODO : Raise error if signature is invalid
        self.signature = signature


def is_valid_signature(pubkey, data, signature):
    """Return True if given data from given pubkey has a valid signature

    pubkey : bytes
    data : bytes
    signature : bytes

    :returns: bool
    """
    try:
        vk = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        vk.verify(signature, data)
        return True
    except ecdsa.keys.BadSignatureError:
        return False


def guzi_hash(data):
    return hashlib.sha256(data).digest()


def zip_positions(positions):
    """
    From [('2020-12-22',0),('2020-12-23',0),('2020-12-23',1),('2020-12-24',0)]
    To   [(['2020-12-22'], [0]),(['2020-12-23'], [0, 1]),(['2020-12-24'], [0])]
    """
    # 1. [('2020-12-22',0),('2020-12-22',1),('2020-12-23',0),('2020-12-23',1)]
    # => [(['2020-12-22'], [0, 1]), (['2020-12-23'], [0, 1])]
    tmp_result = []
    for key, group in itertools.groupby(positions, lambda x: x[0]):
        tmp_result += [(key, [g[1] for g in group])]

    # 2. [(['2020-12-22'], [0, 1]), (['2020-12-23'], [0, 1])]
    # => [(['2020-12-22', '2020-12-23'], [0, 1])]
    result = []
    for key, group in itertools.groupby(tmp_result, lambda x: x[1]):
        result += [([g[0] for g in group], key)]

    return result


def unzip_positions(positions):
    """
    From [(['2020-12-22'], [0]),(['2020-12-23'], [0, 1]),(['2020-12-24'], [0])]
    To   [('2020-12-22',0),('2020-12-23',0),('2020-12-23',1),('2020-12-24',0)]
    """
    result = []
    for p in positions:
        result += itertools.product(p[0], p[1])
    result.sort()
    return result
