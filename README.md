# python-guzi-lib
A library writen in Python to use Guzi as payment method through emails.

## Install
The commands run with pipenv.
``` bash
git clone https://github.com/GuziEconomy/python-guzi-lib.git
make init
```

## Run tests
``` bash
pipenv run pytest
# or
make test
```

## Format code before commit
``` bash
make format
```

## Usage
### User Blockchain
Create a basic Blockchain for a new user :
```Python
# 1. Create an empty Blockchain
PRIVKEY = bytes.fromhex("cdb162375e04db352c1474802b42ac9c972c34708411629074248e241f60ddd6")
PUBKEY = bytes.fromhex("02071205369c6131b7abaafebedfda83fae72232746bdf04601290a76caebc521b")
bc = UserBlockchain(PUBKEY)

# 2. Create and add init transaction
user_birthdate = datetime.date.today()
birth_tx = bc.make_birth_tx(user_birthdate)
bc._add_transaction(birth_tx)

# 3. Add first Guzis and Guzas
tx_guzis = bc.make_daily_guzis_tx(user_birthdate)
tx_guzas = bc.make_daily_guzas_tx(user_birthdate)
bc._add_transaction(tx_guzis)
bc._add_transaction(tx_guzas)

# 4. Fill init block and make it signed by a reference user
REF_PRIVKEY = bytes.fromhex("7b2a9dac572a0952fa78597e3a456ecaa201ce753a93d14ff83cb48762134bca")
REF_PUBKEY = bytes.fromhex("031f34e8aa8488358a81ef61d901e77e9237d19f9f6bff306c8938c748ef45623d")

init_block = bc.fill_init_block()
init_block.signer = REF_PUBKEY
sk = ecdsa.SigningKey.from_string(REF_PRIVKEY, curve=ecdsa.SECP256k1)
signature = sk.sign(init_block.hash())
init_block.sign(signature)
```

To add transactions to a Blockchain :
```Python
bc.new_block()
tx = bc.make_daily_guzis_tx(datetime.date.today())
sk = ecdsa.SigningKey.from_string(PRIVKEY, curve=ecdsa.SECP256k1)
signature = sk.sign(tx.hash())
tx.sign(signature)
bc._add_transaction(tx)
```
