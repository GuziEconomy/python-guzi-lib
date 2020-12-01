from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize, precondition
from hypothesis import note, strategies as st
from tests.test_blockchain import KEY_POOL
from guzilib.blockchain import *
from datetime import date, timedelta

class UserBlockchainStateMachine(RuleBasedStateMachine):
    """This class runs tests to simulate random usages of Blockchain.
    It relies on hypothesis which allows to create rules. Each rule simulates
    one behavious of the Blockchain (creating guzis, making a payment, etc)
    At the end of the simulation, checks all methods having the @invariant() 
    decorator
    """

    bc = None
    
    @initialize(birthdate=st.dates(),
            my_key_pair=st.sampled_from(KEY_POOL),
            ref_key_pair=st.sampled_from(KEY_POOL))
    def init_blockchain(self, birthdate, my_key_pair, ref_key_pair):
        """Created a validated Blockchain and initialize some control
        attributes
        """
        self.bc = UserBlockchain(my_key_pair['pub'])
        self.bc.start(birthdate.isoformat(), my_key_pair['priv'], ref_key_pair['pub'])
        self.bc.validate(ref_key_pair['priv'], birthdate)
        self.bc.new_block()

        self.guzis = 1
        self.current_date = birthdate
        self.guzis_made_today = True

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
        if not self.guzis_made_today:
            self.guzis += self.bc._get_guzis_amount()
            self.guzis_made_today = True
        self.bc.make_daily_guzis(self.current_date)

    @rule(target_user=st.sampled_from(KEY_POOL), amount=st.integers())
    def pay_to(self, target_user, amount):
        """Simulates a payment to another user."""
        try:
            self.bc.pay_to_user(target_user['pub'], amount)
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
