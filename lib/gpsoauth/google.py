import base64
import hashlib

# BEGIN - Copied from plugin.video.M6Replay
import sys,os,struct

# xbmc modules
import xbmc
import xbmcaddon

__addon__ = xbmcaddon.Addon( "script.module.gpsoauth" )
__addonDir__ = __addon__.getAddonInfo( "path" )

# Get the platform and architecture
SYSTEM_PLATFORM = 'Unknown'
architecture = ''

# struct.calcsize("P") is 4 or 8 for 32 or 64 bit Python repectively
# sys.maxsize > 2**32 would be nice to use but is only available from Pyton 2.6
if struct.calcsize("P") == 8:
    architecture = '64bit'
else:
    architecture = '32bit'
if xbmc.getCondVisibility( "system.platform.linux" ):
    SYSTEM_PLATFORM = 'Linux'
    if 'arm' in os.uname()[4]:
        architecture = 'arm'
elif xbmc.getCondVisibility( "system.platform.xbox" ):
    SYSTEM_PLATFORM = 'Xbox'
    # No architecture directory for Xbox
    architecture = ''
elif xbmc.getCondVisibility( "system.platform.windows" ):
    SYSTEM_PLATFORM = 'Windows'
elif xbmc.getCondVisibility( "system.platform.osx" ):
    SYSTEM_PLATFORM = 'Darwin'
    if 'RELEASE_ARM' in os.uname()[3]:
        architecture = 'ios'
    else:
        # Crypto can be compiled as universal library with multiple
        # architectures for osx
        architecture = 'osx'
elif xbmc.getCondVisibility( "system.platform.ios" ):
    # Need to check system.platform.osx for eden
    # Changed to system.platform.ios for frodo
    SYSTEM_PLATFORM = 'Darwin'
    architecture = 'ios'

CRYPTO_PATH = os.path.join( __addonDir__, "platform_libraries", SYSTEM_PLATFORM, architecture)
sys.path.append(CRYPTO_PATH)
# END - Copied from plugin.video.M6Replay

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from .util import bytes_to_long, long_to_bytes


def key_from_b64(b64_key):
    binaryKey = base64.b64decode(b64_key)

    i = bytes_to_long(binaryKey[:4])
    mod = bytes_to_long(binaryKey[4:4+i])

    j = bytes_to_long(binaryKey[i+4:i+4+4])
    exponent = bytes_to_long(binaryKey[i+8:i+8+j])

    key = RSA.construct((mod, exponent))

    return key


def key_to_struct(key):
    mod = long_to_bytes(key.n)
    exponent = long_to_bytes(key.e)

    return '\x00\x00\x00\x80' + mod + '\x00\x00\x00\x03' + exponent


def parse_auth_response(text):
    response_data = {}
    for line in text.split('\n'):
        if not line:
            continue

        key, _, val = line.partition('=')
        response_data[key] = val

    return response_data


def signature(email, password, key):
    signature = []
    signature.append('\x00')

    struct = key_to_struct(key)
    signature.extend(hashlib.sha1(struct).digest()[:4])

    cipher = PKCS1_OAEP.new(key)
    encrypted_login = cipher.encrypt((email + u'\x00' + password).encode('utf-8'))

    signature.extend(encrypted_login)

    return base64.urlsafe_b64encode(''.join(signature))
