#!/usr/bin/env python3
from elgamal.main import Elgamal

import argparse
import random
from math import gcd


class Signature(Elgamal):

    MARK = '\n\n---signature---\n'

    def __init__(self):
        super().__init__()

    def handle_input(self):
        if self.generate_key:
            super().handle_input()

        elif self.file_to_encrypt is not None:
            keys = Signature.read_from_file(
                    self.key_file_name + '.pub').split('\n')
            p, q, y = [int(x)for x in keys]

            data = Signature.read_from_file(self.file_to_encrypt)
            hsh, key = Elgamal.encrypt(str(hash(data)), p, q, y)

            data = '{}{}{}\n{}'.format(data,
                                       Signature.MARK,
                                       '\n'.join([str(x) for x in hsh]),
                                       key)

            Signature.save_to_file(self.output_file, data)

        elif self.file_to_decrypt is not None:
            p, x = Signature.read_from_file(
                    self.key_file_name + '.prv').split('\n')
            data, sig = Signature.read_from_file(
                    self.file_to_decrypt).split(Signature.MARK)
            sig = sig.split('\n')
            a = int(sig[-1])
            sig = [int(char) for char in sig[:-1]]

            hsh = int(''.join(Elgamal.decrypt(sig, a, int(x), int(p))))

            if hsh == hash(data):
                print('Signature verified')
                Signature.save_to_file(self.output_file, data)

            else:
                print('SIGNATURE NOT VERIFIED')
                data += Signature.MARK + 'SIGNATURE NOT VERIFIED\n'
                Signature.save_to_file(self.output_file, data)

        else:
            raise RuntimeError('invalid input')


if __name__ == "__main__":
    Signature().handle_input()
    # PYTHONHASHSEED=0
