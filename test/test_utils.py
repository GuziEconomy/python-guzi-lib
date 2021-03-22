from datetime import date

import ecdsa
from freezegun import freeze_time

from guzilib.blockchain import VERSION, Transaction, UserBlockchain

KEY_POOL = [
    {
        "priv": bytes.fromhex(
            "cdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6"
        ),
        "pub": bytes.fromhex(
            "02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b"
        ),
    },
    {
        "priv": bytes.fromhex(
            "7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca"
        ),
        "pub": bytes.fromhex(
            "031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d"
        ),
    },
    {
        "priv": bytes.fromhex(
            "1f77f037236b5a6763b2a18de13855b3d4a893c06bd004ba0f739c8d2f281103"
        ),
        "pub": bytes.fromhex(
            "032a2eefc84ff6fd6a15eb1e920254cd02725350c67080a00970f535a762417cbb"
        ),
    },
    {
        "priv": bytes.fromhex(
            "f7aa7d91e5b6f82302f82d6c20346cc442729e5ceae6bdb26ea4bd4367a07c4d"
        ),
        "pub": bytes.fromhex(
            "034dffbff09cd2ca67fc9ea67ad4c23e29d9e7febd6c82e8a82ae5e52df4220f6f"
        ),
    },
    {
        "priv": bytes.fromhex(
            "4768e8b37d07ff15bf2149f1fcbf0788be1f00e6b8f365ecbb751b6260d711dc"
        ),
        "pub": bytes.fromhex(
            "02e490be01204314c0918ce6c781b3e6a1ef76f337344a4605589a8185379cd9ac"
        ),
    },
    {
        "priv": bytes.fromhex(
            "2c81a0b8bf49a4dd5a0ddb8b34f63fee0fe1c4d7673ed6376a07ed7a33430d18"
        ),
        "pub": bytes.fromhex(
            "03ef500f14cfdafc25b88c9d054844bd50cf37fd12a374d08e06d8e92fe751471c"
        ),
    },
    {
        "priv": bytes.fromhex(
            "15a9e23b4bce92ee78b556c53dce720a5f538cb94719280e6bfb8dfbde33d049"
        ),
        "pub": bytes.fromhex(
            "036ca32ba58cebf40dee409ddab41263afd1d5a3a74ab4ea317d9cadf32b8a530c"
        ),
    },
    {
        "priv": bytes.fromhex(
            "99184560439a716ab85316e6884ea901f076ca678d4f38f295f9201a7bccaa7e"
        ),
        "pub": bytes.fromhex(
            "02b141e661a3beb6c251502f1ed2c1d3d00a65f3a2aae6c557980df6f8e7fb89ba"
        ),
    },
    {
        "priv": bytes.fromhex(
            "8428ef9ae38b229f2d36379d08e5b35c2c0443000e1d052e987da3a85269bc2c"
        ),
        "pub": bytes.fromhex(
            "0284dd75d374c23f8a783fc7bb4f1f5268b59ff3264c23cf54ac0baa4567fc7362"
        ),
    },
    {
        "priv": bytes.fromhex(
            "a08f8b3e23129287cf24a973da9e6ad5ce5558a7ba2ff1b913c197351966f5af"
        ),
        "pub": bytes.fromhex(
            "03ce3f8e980235165f5fc690f7c08eac3d0c7ba09541122f182f6b8c81431583d5"
        ),
    },
    {
        "priv": bytes.fromhex(
            "53ddf4b6fbf29ffb44192e15f87daf83dbf92f4bf6e609ddff60e2aa7f6125ed"
        ),
        "pub": bytes.fromhex(
            "036cb8ac481bcd55cc876889be9e262a45da5612433bb34c0c5826703140dc6580"
        ),
    },
    {
        "priv": bytes.fromhex(
            "b69dda00c4cc3721ee056096a7f51283d9793fb1f8326cf2d3c47d50ce860a5a"
        ),
        "pub": bytes.fromhex(
            "02fb673d955d41debc1c09fc889730038adecc1bab653bf39ebbeda57cc03ff455"
        ),
    },
]
NEW_USER_PUB_KEY = KEY_POOL[0]["pub"]
NEW_USER_PRIV_KEY = KEY_POOL[0]["priv"]
REF_PUB_KEY = KEY_POOL[1]["pub"]
REF_PRIV_KEY = KEY_POOL[1]["priv"]

BIRTHDATE = date(1998, 12, 21).isoformat()


def random_transaction():
    return Transaction(
        VERSION,
        Transaction.PAYMENT,
        REF_PUB_KEY,
        12,
        tx_date=date(1998, 12, 21).isoformat(),
        target_user=NEW_USER_PUB_KEY,
        signature=0x12,
    )


def random_sign(packable, signer=REF_PUB_KEY, pk=REF_PRIV_KEY):
    packable.signer = signer
    signature = sign(packable.hash(), pk)
    packable.sign(signature)
    return packable


def make_blockchain(
    start=date(2000, 1, 1),
    days=0,
    tx_per_block=1,
    total=0,
    end_with_empty_block=False,
    close_last_block=True,
):
    """Make a Blockchain with given informations

    :start: The starting date (and birthdate) of the blockchain
    :days: Number of days that occurs
    :tx_per_block: Number of transactions created per block.
    :total: Accumulated total of the blockchain after init
    :end_with_empty_block: Append an empty block to the end of the blockchain
    if set to True.
    :returns: Blockchain

    Note: This method makes always one day per block

    """
    with freeze_time(start) as frozen_date:
        bc = UserBlockchain(NEW_USER_PUB_KEY)
        birth_tx = bc.make_birth_tx(frozen_date.time_to_freeze.date())
        tx_guzis = bc.make_daily_guzis_tx(frozen_date.time_to_freeze.date())
        tx_guziboxes = bc.make_daily_guziboxes_tx(frozen_date.time_to_freeze.date())
        random_sign(birth_tx, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
        random_sign(tx_guzis, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
        random_sign(tx_guziboxes, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
        bc._add_transaction(birth_tx)
        bc._add_transaction(tx_guzis)
        bc._add_transaction(tx_guziboxes)
        init_block = bc.fill_init_block()
        random_sign(init_block)
        for i in range(days):
            frozen_date.tick(60 * 60 * 24) # +1 day
            bc.new_block()
            if tx_per_block > 0:
                tx = bc.make_daily_guzis_tx(frozen_date.time_to_freeze.date())
                random_sign(tx, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
                bc._add_transaction(tx)
            for _ in range(1, tx_per_block):
                tx = bc.make_pay_tx(REF_PUB_KEY, bc._get_available_guzis_amount())
                random_sign(tx, NEW_USER_PUB_KEY, NEW_USER_PRIV_KEY)
                bc._add_transaction(tx)
            if i < days - 1 or (i == days - 1 and close_last_block is True):
                bc.close_last_block()
                random_sign(bc.last_block())
    if end_with_empty_block:
        bc.new_block()
    if total > 0:
        bc[0].total = total
    return bc


def sign(data, privkey):
    """Sign the given data and return the signature

    :data: bytes
    :returns: bytes

    """
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    return sk.sign(data)
