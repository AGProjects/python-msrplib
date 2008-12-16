import random
import string

def new_transaction_id():
    return random_string(12)

def new_message_id():
    return random_string(10)

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

