from typing import Tuple
import ctypes


KEY = b'troqkddmtroqkcdm'
POSTFIX = b'\xe8\xb1\x0c\x1f\x8b\xc3\x59\xbe\xe8\xb1\x0c\x1f\x8b\xc3\x59\x5b'


def _encipher(v: Tuple[int, int], k: Tuple[int, int, int, int]) -> Tuple[int, int]:
    '''
    A TEA-Like algorithm used in DNF server database.
    '''

    delta = 0x9E3779B9

    v0, v1 = (ctypes.c_uint32(n) for n in v)
    t0, t1 = ctypes.c_uint32(0), ctypes.c_uint32(0)

    s = ctypes.c_uint32(0)

    for _ in range(32):
        t0.value = (v1.value << 4) ^ (v1.value >> 5)
        t1.value = k[s.value & 3]

        v0.value += (s.value + t1.value) ^ (t0.value + v1.value)

        s.value += delta

        t0.value = (v0.value << 4) ^ (v0.value >> 5)
        t1.value = k[(s.value >> 11) & 3]

        v1.value += (s.value + t1.value) ^ (t0.value + v0.value)

    return v0.value, v1.value


def _decipher(v: Tuple[int, int], k: Tuple[int, int, int, int]) -> Tuple[int, int]:
    '''
    A TEA-Like algorithm used in DNF server database.
    '''

    delta = 0x9E3779B9

    v0, v1 = (ctypes.c_uint32(n) for n in v)
    t0, t1 = ctypes.c_uint32(0), ctypes.c_uint32(0)

    s = ctypes.c_uint32(0xC6EF3720)

    for _ in range(32):
        t0.value = (v0.value << 4) ^ (v0.value >> 5)
        t1.value = k[s.value >> 11 & 3]

        v1.value -= (s.value + t1.value) ^ (t0.value + v0.value)

        s.value -= delta

        t0.value = (v1.value << 4) ^ (v1.value >> 5)
        t1.value = k[s.value & 3]

        v0.value -= (s.value + t1.value) ^ (t0.value + v1.value)

    return v0.value, v1.value


def encode(p: bytes) -> bytes:
    '''
    Encode a given plain password to the server required one.
    '''

    # 8 means sizeof(uint32) * 2, 16 means sizeof(uint32) * 4
    assert len(p) == 8 and len(KEY) == 16

    k = tuple((int.from_bytes(KEY[i: i+4], byteorder='little')
               for i in range(0, 16, 4)))

    p = tuple((int.from_bytes(p[i: i+4], byteorder='big')
               for i in range(0, 8, 4)))

    e = _encipher(p, k)

    return bytes((b for n in e for b in n.to_bytes(4, byteorder='big'))) + POSTFIX


def decode(e: bytes) -> bytes:
    '''
    Decode a password used in database to plain.
    '''

    # 24 means sizeof(uint32) * 2 + len(POSTFIX), 16 means sizeof(uint32) * 4
    assert len(e) == 24 and e.endswith(POSTFIX) and len(KEY) == 16

    k = tuple((int.from_bytes(KEY[i: i+4], byteorder='little')
               for i in range(0, 16, 4)))

    e = tuple((int.from_bytes(e[i: i+4], byteorder='big')
               for i in range(0, 8, 4)))

    p = _decipher(e, k)

    return bytes((b for n in p for b in n.to_bytes(4, byteorder='big')))



if __name__ == "__main__":

    e = encode(b'uu5!^%jg')
    p = decode(e)
    print(e.hex(), p)

    e = encode(b'12345678')
    p = decode(e)
    print(e.hex(), p)
