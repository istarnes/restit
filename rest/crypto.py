import binascii
import StringIO
import string
import struct
import hmac
import os

from arc4 import crypt
from hashlib import sha1, sha512
import base64

import re

from django.conf import settings

from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import random as crypt_random
from Crypto import Random


try:
    import M2Crypto
    from M2Crypto import BIO, RSA
except:
    pass

from Crypto.PublicKey import RSA

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
    return ''.join([crypt_random.choice(string.ascii_letters + string.digits) for n in xrange(str_size)])

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
    password = password.encode('ascii','ignore')  # convert to ASCII
 
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
    if type(password) is unicode:
        password = password.encode('ascii','ignore')
    if type(plaintext) is unicode:
        plaintext = plaintext.encode('ascii','ignore')
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
    ciphertext = cipher.encrypt(padded_plaintext)
 
    # Make openssl compatible.
    # I first discovered this when I wrote the C++ Cipher class.
    # CITATION: http://projects.joelinoff.com/cipher-1.1/doxydocs/html/
    openssl_ciphertext = 'Salted__' + salt + ciphertext
    b64 = base64.b64encode(openssl_ciphertext)
    if not chunkit:
        return b64
 
    LINELEN = 64
    chunk = lambda s: '\n'.join(s[i:min(i+LINELEN, len(s))]
                                for i in xrange(0, len(s), LINELEN))
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
    if type(password) is unicode:
        password = password.encode('ascii','ignore')
    # unfilter -- ignore blank lines and comments
    filtered = ''
    for line in ciphertext.split('\n'):
        line = line.strip()
        if re.search('^\s*$', line) or re.search('^\s*#', line):
            continue
        filtered += line + '\n'
 
    # Base64 decode
    raw = base64.b64decode(filtered)
    if len(raw) < 8 or raw[:8] != 'Salted__':
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
 
    padding_len = ord(padded_plaintext[-1])
    plaintext = padded_plaintext[:-padding_len]
    return plaintext

BLOCK_SIZE = 32
PADDING='#'

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
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * PADDING

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
        cipher = AES.new(_pad(settings.SECRET_KEY + secret_key, '@')[:32])
        return base64.b64encode(cipher.encrypt(_pad(data)))
    rdata = data + str(get_random_string(128))
    return aes_encrypt(secret_key, rdata, False)


def decrypt(secret_key, encrypted_data, strong=False):
    """
    Decryptes the given data with given key.
    """
    if not strong:
        cipher = AES.new(_pad(settings.SECRET_KEY + secret_key, '@')[:32])
        return cipher.decrypt(base64.b64decode(encrypted_data)).rstrip(PADDING)
    res = aes_decrypt(secret_key, encrypted_data)
    if res:
        return res[:-128]
    return res

def hashit(data, salt=None):
    return sha512(data).hexdigest()


class PKCS7Encoder(object):
    def __init__(self, k=16):
       self.k = k

    ## @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.
    def unpad(self, text):
        '''
        Remove the PKCS#7 padding from a text string
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]

    ## @param text The text to encode.
    def pad(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO.StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())

class ObfuscateId(object):
    @classmethod
    def obfuscate_id(cls, intid):
        return obfuscate_id(cls.__name__, intid)

    @classmethod
    def unobfuscate_id(cls, strid):
        return unobfuscate_id(cls.__name__, strid)

    @classmethod
    def get_by_id(cls, strid):
        id = cls.unobfuscate_id(strid)
        return cls.objects.get(pk = id)

    @classmethod
    def get_by_id_or_404(cls, strid):
        try:
            return cls.get_by_id(strid)
        except cls.DoesNotExist:
            raise Http404

class SignedId(ObfuscateId):
    @classmethod
    def obfuscate_id(cls, intid):
        return sign_id(cls.__name__, intid)

    @classmethod
    def unobfuscate_id(cls, strid):
        return unsign_id(cls.__name__, intid)





def obfuscate_id(label, intid):
    if intid >= 2**32:
        mode = "<Q"
    else:
        mode = "<L"

    r = struct.pack(mode, intid)

    return base64.b32encode(crypt(r, settings.SECRET_KEY + label, 1)).rstrip("=").lower()

def unobfuscate_id(label, strid):
    strid = strid.upper() + (8 - (len(strid) % 8)) * '='

    try:
        d = base64.b32decode(strid)
    except TypeError:
        return None

    r = crypt(d, settings.SECRET_KEY + label, 0)
        
    if len(r) == 8:
        mode = "<Q"
    else:
        mode = "<L"
        
    return struct.unpack(mode, r)[0]

def do_hmac(label, val, length):
    ret = hmac.new(settings.SECRET_KEY + label, val, sha512)
    retstr = base64.b32encode(ret.digest())
    return retstr[:length].lower()

def sign_id(label, intid, length=6):
    ob = obfuscate_id(label, intid)
    ret = do_hmac(label, ob + str(intid), length)
    return ret + ob

def unsign_id(label, strid, length=6):
    try:
        ob = strid[length:]
    except:
        return None
    intid = unobfuscate_id(label, ob)
    ret = do_hmac(label, ob + str(intid), length)
    if ret == strid[:length]:
        return intid
    return None

def hash512(data):
    return sha512(data).hexdigest()



