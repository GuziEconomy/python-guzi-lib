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
