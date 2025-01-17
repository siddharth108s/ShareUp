from Crypto.PublicKey import DSA


def generate_dsa_keys():
    key = DSA.generate(2048)

    with open('dsa_private_key.pem', 'wb') as private_file:
        private_file.write(key.export_key(format='PEM'))

    with open('dsa_public_key.pem', 'wb') as public_file:
        public_file.write(key.publickey().export_key(format='PEM'))


if __name__ == "__main__":
    generate_dsa_keys()
