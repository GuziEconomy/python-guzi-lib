import itertools
import hashlib
import ecdsa

EMPTY_HASH = 0

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


def guzi_hash(data):
    return hashlib.sha256(data).digest()


def zip_positions(positions):
    # 1. [("2020-12-22",0),("2020-12-22",1),("2020-12-23",0),("2020-12-23",1)]
    # => [(['2020-12-22'], [0, 1]), (['2020-12-23'], [0, 1])]
    tmp_result = []
    for key, group in itertools.groupby(positions, lambda x: x[0] ): 
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
    To   [("2020-12-22",0),("2020-12-23",0),("2020-12-23",1),("2020-12-24",0)]
    """
    result = []
    for p in positions:
        result += itertools.product(p[0], p[1])
    result.sort()
    return result
