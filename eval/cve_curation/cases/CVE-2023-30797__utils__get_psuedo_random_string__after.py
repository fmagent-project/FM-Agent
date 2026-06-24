def get_psuedo_random_string():
    """
    Create a random and strongish challenge.
    """
    challenge = "".join(secrets.choice(string.ascii_uppercase) for x in range(6))  # noqa
    challenge += "".join(secrets.choice("~!@#$%^&*()_+") for x in range(6))  # noqa
    challenge += "".join(secrets.choice(string.ascii_lowercase) for x in range(6))
    challenge += "".join(secrets.choice(string.digits) for x in range(6))  # noqa
    return challenge
