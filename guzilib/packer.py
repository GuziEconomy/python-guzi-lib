import umsgpack


class Packer:
    def pack_tx(self, transaction):
        return NotImplemented

    def pack_tx_without_hash(self, transaction):
        return NotImplemented

    def pack_block(self, block):
        return NotImplemented

    def pack_block_without_hash(self, block):
        return NotImplemented

    def pack_bloockchain(self, blockchain, outfile=None):
        return NotImplemented


class BytePacker(Packer):
    def pack_tx(self, transaction):
        return umsgpack.packb(transaction.as_full_list())

    def pack_tx_without_hash(self, transaction):
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
