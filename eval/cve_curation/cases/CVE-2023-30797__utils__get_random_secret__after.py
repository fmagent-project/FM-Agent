def get_random_secret(length):
    """ Similar to get_pseudo_random_string, but accepts a length parameter. """
    secret_key = ''.join(secrets.choice(string.ascii_uppercase) for x in range(round(length / 4)))
    secret_key = secret_key + ''.join(secrets.choice("~!@#$%^&*()_+") for x in range(round(length / 4)))
    secret_key = secret_key + ''.join(secrets.choice(string.ascii_lowercase) for x in range(round(length / 4)))
    return secret_key + ''.join(secrets.choice(string.digits) for x in range(round(length / 4)))
