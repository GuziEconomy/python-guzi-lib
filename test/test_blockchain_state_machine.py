from datetime import timedelta
from test.test_blockchain import KEY_POOL
from test.test_utils import random_sign

from hypothesis import note
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
)

from guzilib.blockchain import UserBlockchain
from guzilib.errors import GuziError, InsufficientFundsError, NegativeAmountError


class UserBlockchainStateMachine(RuleBasedStateMachine):
    """This class runs tests to simulate random usages of Blockchain.
    It relies on hypothesis which allows to create rules. Each rule simulates
    one behavious of the Blockchain (creating guzis, making a payment, etc)
    At the end of the simulation, checks all methods having the @invariant()
    decorator
    """

    bc = None

    @initialize(
        birthdate=st.dates(),
        my_key_pair=st.sampled_from(KEY_POOL),
        ref_key_pair=st.sampled_from(KEY_POOL),
    )
    def init_blockchain(self, birthdate, my_key_pair, ref_key_pair):
        """Created a validated Blockchain and initialize some control
        attributes
        """
        self.bc = UserBlockchain(my_key_pair["pub"])

        birth_tx = self.bc.make_birth_tx(birthdate)
        random_sign(birth_tx, my_key_pair["pub"], my_key_pair["priv"])
        self.bc._add_transaction(birth_tx)

        tx_guzis = self.bc.make_daily_guzis_tx(birthdate)
        random_sign(tx_guzis, my_key_pair["pub"], my_key_pair["priv"])
        self.bc._add_transaction(tx_guzis)

        tx_guzas = self.bc.make_daily_guzas_tx(birthdate)
        random_sign(tx_guzas, my_key_pair["pub"], my_key_pair["priv"])
        self.bc._add_transaction(tx_guzas)

        init_block = self.bc.fill_init_block(birthdate)
        random_sign(init_block, ref_key_pair["pub"], ref_key_pair["priv"])

        self.bc.new_block()

        self.guzis = 1
        self.current_date = birthdate
        self.guzis_made_today = True
        self.key_pair = my_key_pair

    @rule()
    def new_day(self):
        """ Simulate a date change, which has strong impact in Guzis"""
        self.current_date += timedelta(days=1)
        self.guzis_made_today = False

    @rule()
    def make_daily_guzis(self):
        """Simulates the creation of daily Guzis for the blockchain.
        Note that if it was already made today, it shouldn't create those
        again.
        """
        try:
            tx = self.bc.make_daily_guzis_tx(self.current_date)
            random_sign(tx, self.key_pair["pub"], self.key_pair["priv"])
            self.bc._add_transaction(tx)
            if not self.guzis_made_today:
                self.guzis += self.bc._get_guzis_amount()
                self.guzis_made_today = True
        except GuziError:
            pass

    @rule(target_user=st.sampled_from(KEY_POOL), amount=st.integers())
    def pay_to(self, target_user, amount):
        """Simulates a payment to another user."""
        try:
            note("paying amount {}".format(amount))
            tx = self.bc.make_pay_tx(target_user, amount)
            random_sign(tx, self.key_pair["pub"], self.key_pair["priv"])
            self.bc._add_transaction(tx)
            self.guzis -= amount
        except (InsufficientFundsError, NegativeAmountError):
            pass

    @precondition(lambda self: self.bc is not None)
    @invariant()
    def check_guzis(self):
        """Check that blockchain guzis amount is correct"""
        assert self.guzis >= 0
        note(self.bc._get_available_guzis())
        assert self.guzis == self.bc._get_available_guzis_amount()


UserBlockchainTests = UserBlockchainStateMachine.TestCase
