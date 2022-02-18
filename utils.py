def dht_hash(text, seed=0, maximum=2**10):
    """ FNV-1a Hash Function. """
    fnv_prime = 16777619
    offset_basis = 2166136261
    h = offset_basis + seed
    for char in text:
        h = h ^ ord(char)
        h = h * fnv_prime
    return h % maximum


def contains(begin, end, node):
    """Check node is contained between begin and end in a ring."""
    if not end:
        return False
    if not begin:
        return False

    if begin > end: # circle around
        #   [begin ,1024[   or  [0 , end]
        if (node > begin and node < 1024) or (node >= 0 and node <= end):
            return True
        else:
            return False
    else:
        # simplest case
        if node <= end and node > begin:
            return True
        else:
            return False
    return False
