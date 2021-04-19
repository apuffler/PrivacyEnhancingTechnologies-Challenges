#!/usr/bin/env python3

import logging
import argparse
import requests
from trumpet_axolotl.ecc.curve import Curve
from trumpet_axolotl.protocol.keyexchangemessage import KeyExchangeMessage
from trumpet_axolotl.protocol.whispermessage import WhisperMessage

# Global variable which (un)arms the script.
# If False no requests will be sent. Can be set via program args.
armed = False


def init(key_exchange_message: KeyExchangeMessage):
    logging.debug('Sending key exchange message to initialize session.')
    if armed:
        res = requests.post(url='http://pets.ifs.tuwien.ac.at:8081/init-session/01225268',
                            data=key_exchange_message.serialize(),
                            headers={'Content-Type': 'application/octet-stream'})
        if res.status_code == 200:
            logging.debug('Sending session-init message was successful.')
            return KeyExchangeMessage(serialized=res.content)
        else:
            logging.error('Response content: ' + res.content.decode("utf-8"))
            raise Exception('Session-Init with Mr. Cipher failed.')
    else:
        logging.warning('Script unarmed. No requests are sent. Enable via program arguments or modify global variable.')


def send(message: WhisperMessage):
    logging.debug('Sending encrypted message.')
    if armed:
        res = requests.post(url='http://pets.ifs.tuwien.ac.at:8081/send/01225268',
                            data=message.serialize(),
                            headers={'Content-Type': 'application/octet-stream'})
        if res.status_code == 200:
            logging.debug('Sending encrypted message was successful.')
            return WhisperMessage(serialized=res.content)
        else:
            logging.error('Response content: ' + res.content.decode("utf-8"))
            raise Exception('Encrypted communication with Mr. Cipher failed.')
    else:
        logging.warning('Script unarmed. No requests are sent. Enable via program arguments or modify global variable.')


def spoof():
    mr_paranoid_public_bin = b'\x05\x1d\xf4\xc6\xe7Uau\x15\xc5\xd1\x13\xc7\xf3g\xefE\xa5{\x1em\xe6o\xbc\x13>N\xbf\x95<\xf4\xb4\x1b'
    mr_paranoid_public_key = Curve.decodePoint(mr_paranoid_public_bin, 0)

    # TODO - YOUR CODE HERE!
    # - The public key of Mr. Paranoid is provided above.
    # - Find out what's the problem with the fingerprinting in the Trumpet Messenger.
    # - Get familiar with the trumpet-axolotl library.
    #   - Take a look at the tests package in the trumpet-axolotl source code, especially SessionBuilderTest and
    #     SessionCipherTest.
    #   - Do not implement any interfaces on your own, you can just re-use the InMemoryAxolotlStore and any other
    #     classes in there.
    # - Create an IdentityKeyPair which has the same fingerprint as Mr. Paranoid's.
    # - Create a KeyExchangeMessage to initiate a session with Mr. Cipher (who should think you're Mr. Paranoid).
    # - Send the KeyExchangeMessage using init(key_exchange_message).
    # - Finish the session building process with the response.
    # - Create an encrypted message asking for a meeting with him.
    # - Send the WhisperMessage using send(message).
    # - Find out where's the meeting point. We'll just wait there to de-anonymize him!


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

    parser = argparse.ArgumentParser(description='Trumpet Messenger Identity Spoofer')
    parser.add_argument('-a', '--arm',
                        help='Arm the script to actually target Mr. Paranoid\'s communication partner Mr. Cipher',
                        action="store_true", default=False)
    args = parser.parse_args()
    if args.arm:
        global armed
        armed = True
        logging.warning('Your script is armed! Be aware that there\'s a pretty strict rate limit. Implement and test '
                        'your solution offline first!')
    spoof()


if __name__ == '__main__':
    main()
