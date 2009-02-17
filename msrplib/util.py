import random
import string

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

