from ecdsa import SigningKey, SECP256k1


def generate_ecc_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    with open('ecc_private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key.to_pem())

    with open('ecc_public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key.to_pem())
        key = {"public_key": public_key, "private_key": private_key}
    return private_key.to_pem(), public_key.to_pem()
