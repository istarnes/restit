import binascii
import io
import string
import struct
import hmac
import os

from .arc4 import crypt
from hashlib import sha1, sha512, sha256
import base64

import re

from django.conf import settings

from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import random as crypt_random
from Crypto import Random
from hashids import Hashids


try:
    import M2Crypto
    from M2Crypto import BIO, RSA
except:
    pass

from Crypto.PublicKey import RSA

BLOCK_SIZE = 32

AES_SALT_PREFIX = b"Salted__"

def toHex(value):
    value = toBytes(value)
    return binascii.hexlify(value).upper().decode('utf-8')

def toBase64(value):
    return toString(base64.b64encode(toBytes(value)))

def fromBase64(value):
    return base64.b64decode(value)

def hexToByteArray(value):
    return bytearray.fromhex(value)

def toString(value):
    if isinstance(value, bytes):
        value = value.decode()
    elif isinstance(value, bytearray):
        value = value.decode("utf-8")
    return value

def toBytes(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    elif isinstance(value, bytearray):
        value = bytes(value)
    return value

def getSSHSignature(pub_key):
    data = pub_key.strip()
    # accept either base64 encoded data or full pub key file,
    # same as `fingerprint_from_ssh_pub_key
    if (re.search(r'^ssh-(?:rsa|dss|ed25519) ', data)):
        data = data.split(None, 2)[1]
    # Python 2/3 hack. May be a better solution but this works.
    data = toBytes(data)
    digest = sha256(binascii.a2b_base64(data)).digest()
    encoded = toString(base64.b64encode(digest).rstrip(b'='))  # ssh-keygen strips this
    return "SHA256:" + encoded

def rsaPrivateKey(size=2048):
    key = RSA.generate(size)
    return key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)

def rsaPublicKey(key_pem):
    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)

# I'm sure you'll want this wrapped in a class,
# will let you do because I don't know how you would want it done
def rsa_gen_keys():
    rsa = M2Crypto.RSA.gen_key(1024, 65537)
    bio = BIO.MemoryBuffer()
    rsa.save_pub_key_bio(bio)
    rsa.save_key_bio(bio, cipher=None)
    return bio

def rsa_encrypt(clear_text, key_pair):
    rsa = M2Crypto.RSA.load_pub_key_bio(key_pair)
    cipher_text = rsa.public_encrypt(clear_text, M2Crypto.RSA.pkcs1_oaep_padding)
    return base64.b64encode(cipher_text)

def rsa_decrypt(cipher_text, key_pair):
    raw_cipher_text = base64.b64decode(cipher_text)
    rsa_private_key = M2Crypto.RSA.load_key_bio(key_pair)
    plain_text = rsa_private_key.private_decrypt(raw_cipher_text, M2Crypto.RSA.pkcs1_oaep_padding)
    return plain_text


def get_random_bits(bit_size=128):
    return crypt_random.getrandbits(bit_size)

def get_random_string(str_size=128):
    return ''.join([crypt_random.choice(string.ascii_letters + string.digits) for n in range(str_size)])

def get_key_and_iv(password, salt, klen=32, ilen=16, msgdgst='md5'):
    '''
    Derive the key and the IV from the given password and salt.
    klen (size of key) - The secret key to use in the symmetric cipher. It must be
        16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long.
    This is a niftier implementation than my direct transliteration of
    the C++ code although I modified to support different digests.

    CITATION: http://stackoverflow.com/questions/13907841/implement-openssl-aes-encryption-in-python

    @param password  The password to use as the seed.
    @param salt      The salt.
    @param klen      The key length.
    @param ilen      The initialization vector length.
    @param msgdgst   The message digest algorithm to use.
    '''
    # equivalent to:
    #   from hashlib import <mdi> as mdf
    #   from hashlib import md5 as mdf
    #   from hashlib import sha512 as mdf
    mdf = getattr(__import__('hashlib', fromlist=[msgdgst]), msgdgst)
    password = toBytes(password)  # convert to ASCII
    salt = toBytes(salt)

    try:
        maxlen = klen + ilen
        keyiv = mdf(password + salt).digest()
        tmp = [keyiv]
        while len(tmp) < maxlen:
            tmp.append( mdf(tmp[-1] + password + salt).digest() )
            keyiv += tmp[-1]  # append the last byte
            key = keyiv[:klen]
            iv = keyiv[klen:klen+ilen]
        return key, iv
    except UnicodeDecodeError:
        return None, None


# BEGIN SIMPLE AES ENCRYPTION
# THIS WORKS WITH CryptoJS Library
def aes_encrypt(message, passphrase):
    return aes_simple_encrypt(message, passphrase)


def aes_decrypt(message, passphrase):
    return aes_simple_decrypt(message, passphrase)


def pad(data, block_size=16):
    # if isinstance(data, str):
    #     data = str(data)
    length = block_size - (len(data) % block_size)
    return data + (chr(length) * length).encode()


def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]


def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def aes_simple_encrypt(message, passphrase, format="b64"):
    # format: b64, hex, bytes
    if isinstance(message, dict) or isinstance(message, list):
        message = json.dumps(message)
    message = toBytes(message)
    passphrase = toBytes(passphrase)
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_data = AES_SALT_PREFIX + salt + aes.encrypt(pad(message))
    if format == "b64":
        return toBase64(enc_data)
    elif format == "hex":
        return toHex(enc_data)
    return enc_data


def aes_simple_decrypt(encrypted, passphrase):
    # because some are b64 and others are not we check
    b64_encoded = not (isinstance(encrypted, (bytes, bytearray)) and encrypted.startswith(AES_SALT_PREFIX))
    if b64_encoded:
        encrypted = base64.b64decode(encrypted)
    assert encrypted.startswith(AES_SALT_PREFIX)

    passphrase = toBytes(passphrase)
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))


def aes_hex_encrypt(message, passphrase):
    return aes_simple_encrypt(message, passphrase, format="hex")


def aes_hex_decrypt(encrypted, passphrase):
    encrypted = hexToByteArray(encrypted)
    return toString(aes_simple_decrypt(encrypted, passphrase))

# END SIMPLE AES DECRYPTION


def aes_encrypt(password, plaintext, chunkit=True, msgdgst='md5'):
    '''
    Encrypt the plaintext using the password using an openssl
    compatible encryption algorithm. It is the same as creating a file
    with plaintext contents and running openssl like this:

    $ cat plaintext
    <plaintext>
    $ openssl enc -e -aes-256-cbc -base64 -salt \\
        -pass pass:<password> -n plaintext

    @param password  The password.
    @param plaintext The plaintext to encrypt.
    @param chunkit   Flag that tells encrypt to split the ciphertext
                     into 64 character (MIME encoded) lines.
                     This does not affect the decrypt operation.
    @param msgdgst   The message digest algorithm.
    '''
    password = toString(password)
    plaintext = toString(plaintext)
    salt = os.urandom(8)
    key, iv = get_key_and_iv(password, salt, msgdgst=msgdgst)
    if key is None:
        return None

    # PKCS#7 padding
    padding_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + (chr(padding_len) * padding_len)
    # print "iv: {}".format(len(iv))
    # print "key: {}".format(len(key))
    # Encrypt
    # key (size of key) - The secret key to use in the symmetric cipher. It must be
    # 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long.

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(toBytes(padded_plaintext))

    # Make openssl compatible.
    # I first discovered this when I wrote the C++ Cipher class.
    # CITATION: http://projects.joelinoff.com/cipher-1.1/doxydocs/html/
    openssl_ciphertext = AES_SALT_PREFIX + salt + ciphertext
    b64 = toString(base64.b64encode(openssl_ciphertext))
    if not chunkit:
        return b64

    LINELEN = 64
    chunk = lambda s: '\n'.join(s[i:min(i+LINELEN, len(s))]
                                for i in range(0, len(s), LINELEN))
    return chunk(b64)

def aes_decrypt(password, ciphertext, msgdgst='md5'):
    '''
    Decrypt the ciphertext using the password using an openssl
    compatible decryption algorithm. It is the same as creating a file
    with ciphertext contents and running openssl like this:

    $ cat ciphertext
    # ENCRYPTED
    <ciphertext>
    $ egrep -v '^#|^$' | \\
        openssl enc -d -aes-256-cbc -base64 -salt -pass pass:<password> -in ciphertext
    @param password   The password.
    @param ciphertext The ciphertext to decrypt.
    @param msgdgst    The message digest algorithm.
    @returns the decrypted data.
    '''
    password = toString(password)
    # unfilter -- ignore blank lines and comments
    filtered = ''
    for line in ciphertext.split('\n'):
        line = line.strip()
        if re.search('^\s*$', line) or re.search('^\s*#', line):
            continue
        filtered += line + '\n'
    # Base64 decode
    raw = base64.b64decode(filtered)
    if len(raw) < 8 or raw[:8] != AES_SALT_PREFIX:
        print("invalid salt")
        return None

    salt = raw[8:16]  # get the salt

    # Now create the key and iv.
    key, iv = get_key_and_iv(password, salt, msgdgst=msgdgst)
    if key is None:
        return None

    # The original ciphertext
    ciphertext = raw[16:]

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    padding_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_len]
    return toString(plaintext)

PADDING='#'
BPADDING=b'#'

def _pad(data, pad_with=PADDING):
    """
    Data to be encrypted should be on 16, 24 or 32 byte boundaries.
    So if you have 'hi', it needs to be padded with 30 more characters
    to make it 32 bytes long. Similary if something is 33 bytes long,
    31 more bytes are to be added to make it 64 bytes long which falls
    on 32 boundaries.
    - BLOCK_SIZE is the boundary to which we round our data to.
    - PADDING is the character that we use to padd the data.
    """
    return toBytes(data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * PADDING)


def pad_pkcs7(data):
    padder = PKCS7Encoder()
    return padder.pad(data)


def unpad_pkcs7(data):
    padder = PKCS7Encoder()
    return padder.unpad(data)


def encrypt(secret_key, data, strong=False):
    """
    Encrypts the given data with given secret key.
    """
    if not strong:
        cipher = AES.new(_pad(settings.SECRET_KEY + secret_key, '@')[:32], AES.MODE_CBC)
        edata = cipher.iv + cipher.encrypt(_pad(data))
        return toString(base64.b64encode(edata))
    rdata = data + toString(get_random_string(128))
    return toString(aes_encrypt(secret_key, rdata, False))


def decrypt(secret_key, encrypted_data, strong=False):
    """
    Decryptes the given data with given key.
    """
    if not strong:
        edata = base64.b64decode(toBytes(encrypted_data))
        iv = edata[:16]
        edata = edata[16:]
        cipher = AES.new(_pad(settings.SECRET_KEY + secret_key, '@')[:32], AES.MODE_CBC, iv=iv)
        dec = cipher.decrypt(edata)
        return toString(dec.rstrip(BPADDING))
    res = aes_decrypt(secret_key, encrypted_data)
    if res:
        return res[:-128]
    return res

def hashit(data, salt=None):
    bdat = toBytes(data)
    if salt != None:
        bdat = toBytes(salt) + bdat
    return sha512(bdat).hexdigest()


class PKCS7Encoder(object):
    def __init__(self, kv=16):
       self.kv = kv

    def unpad(self, text):
        '''
        Remove the PKCS#7 padding from a text string
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.kv:
            raise ValueError('Input is not padded or padding is corrupt')
        tl = nl - val
        return text[:tl]

    ## @param text The text to encode.
    def pad(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        tl = len(text)
        output = io.StringIO()
        val = self.kv - (tl % self.kv)
        for _ in range(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())


class ObfuscateId(object):
    @classmethod
    def obfuscate_id(cls, int_id):
        return obfuscate_id(cls.__name__, int_id)

    @classmethod
    def unobfuscate_id(cls, obfuscated_id):
        return unobfuscate_id(cls.__name__, obfuscated_id)

    @classmethod
    def get_by_id(cls, obfuscated_id):
        id = cls.unobfuscate_id(obfuscated_id)
        return cls.objects.get(pk=id)

    @classmethod
    def get_by_id_or_404(cls, obfuscated_id):
        try:
            return cls.get_by_id(obfuscated_id)
        except cls.DoesNotExist:
            raise Http404


class SignedId(ObfuscateId):
    @classmethod
    def obfuscate_id(cls, int_id):
        return sign_id(cls.__name__, int_id)

    @classmethod
    def unobfuscate_id(cls, obfuscated_id):
        return unsign_id(cls.__name__, obfuscated_id)


def obfuscateID(label, int_id):
    return Hashids(label).encode(int_id)


def unobfuscateID(label, obfuscated_id):
    res = Hashids(label).decode(obfuscated_id)
    if len(res):
        return res[0]
    return None


def obfuscate_id(label, int_id):
    return obfuscateID(label, int_id)


def unobfuscate_id(label, obfuscated_id):
    return unobfuscateID(label, obfuscated_id)


def do_hmac(label, val, length, encoding="base32"):
    ret = hmac.new(toBytes(settings.SECRET_KEY + label), toBytes(val), sha512)
    if encoding == "base32":
        retstr = toString(base64.b32encode(ret.digest()))
    else:
        retstr = toHex(ret.digest())
    return retstr[:length].lower()


def sign_id(label, int_id, length=6):
    ob = obfuscate_id(label, int_id)
    ret = do_hmac(label, ob + str(int_id), length)
    return ret + ob


def unsign_id(label, obfuscated_id, length=6):
    try:
        ob = obfuscated_id[length:]
    except Exception:
        return None
    int_id = unobfuscate_id(label, ob)
    ret = do_hmac(label, ob + toString(obfuscated_id), length)
    if ret == obfuscated_id[:length]:
        return int_id
    return None


def hash512(data):
    return sha512(data).hexdigest()


def obfuscate_id_to_int(id):
    return Optimus().encode(id)


def unobfuscate_id_from_int(oid):
    return Optimus().decode(oid)


class Optimus:
    """ Arguments -
        prime - Prime number lower than 2147483647
        inverse - The inverse of prime such that (prime * inverse) & 2**31-1 == 1
        xor - A large random integer lower than 2147483647"""
    def __init__(self, prime=936318091, inverse=760853283, xor=525555):
        self.prime = int(prime)
        self.inverse = int(inverse)
        self.xor = int(xor)
        self.max = int((2**31) - 1)
        self.__validate(prime=self.prime, inverse=self.inverse, random=self.xor)

    def encode(self, value):
        """
        Accepts a integer value and returns obfuscated integer
        """
        self.__check_arg(value)
        return (int(value * self.prime) & self.max) ^ self.xor

    def decode(self, value):
        """
        Accepts obfuscated integer generated via encode method and returns the original integer
        """
        self.__check_arg(value)
        return ((value ^ self.xor) * self.inverse) & self.max

    def __check_arg(self, value):
        if not isinstance(value, int):
            raise Exception('Argument should be an integer')

    def __validate(self, **kwargs):
        if kwargs['prime'] >= 2147483647:
            raise Exception('The prime number should be less than 2147483647')
        if ((kwargs['prime'] * kwargs['inverse']) & (2 ** 31 -1)) != 1:
            raise Exception('The inverse does not satisfy the condition "(prime * inverse) & 2**31-1 == 1"')
        if kwargs['random'] >= 2147483647:
            raise Exception('The random integer should be less than 2147483647')
