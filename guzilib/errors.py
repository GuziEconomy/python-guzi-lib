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
class NegativeAmountError(GuziError):
    pass
class InsufficientFundsError(GuziError):
    pass
