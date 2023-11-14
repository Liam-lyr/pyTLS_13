import os
import sys
import io
import threading
import queue

import connection
from type import Uint8, Uint16, OpaqueUint16, OpaqueLength
from disp import hexdump

from protocol_tlscontext import TLSContext
from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext, TLSCiphertext, TLSInnerPlaintext
from protocol_handshake import Handshake
from protocol_hello import ClientHello
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_authentication import Finished, Hash, OpaqueHash
from protocol_alert import Alert, AlertLevel, AlertDescription

from crypto_x25519 import x25519
import crypto_hkdf as hkdf


ctx = TLSContext('client')


# === Key Exchange Parameters ===

# ECDH with X25519, with Forward Secrecy available
dhkex_class = x25519
# client_private_key
secret_key = os.urandom(32)
# client_public_key
public_key = dhkex_class(secret_key)


# === Client Hello ====

client_hello = Handshake(
    msg_type=HandshakeType.client_hello,
    msg=ClientHello(
        # Cipher Suites
        cipher_suites=CipherSuites([
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ]),
        # Extensions
        extensions=Extensions([
            # Supported-Versions ext
            # Here, we only support TLS 1.3
            Extension(
                extension_type=ExtensionType.supported_versions,
                extension_data=SupportedVersions(
                    versions=ProtocolVersions([
                        ProtocolVersion.TLS13
                    ])
                )
            ),
            # Supported-Groups ext
            # Here, we only support X25519 as key exchange algorithm
            Extension(
                extension_type=ExtensionType.supported_groups,
                extension_data=NamedGroupList(
                    named_group_list=NamedGroups([
                        NamedGroup.x25519
                    ])
                )
            ),
            # Signature-Algorithms ext
            # Here,
            Extension(
                extension_type=ExtensionType.signature_algorithms,
                extension_data=SignatureSchemeList(
                    supported_signature_algorithms=SignatureSchemes([
                        SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_rsae_sha384,
                        SignatureScheme.rsa_pss_rsae_sha512,
                    ])
                )
            ),
            # Key-Share ext
            # Here, we only support X25519 as key exchange algorithm
            Extension(
                extension_type=ExtensionType.key_share,
                extension_data=KeyShareHello(
                    shares=KeyShareEntrys([
                        KeyShareEntry(
                            group=NamedGroup.x25519,
                            key_exchange=OpaqueUint16(public_key)
                        )
                    ])
                )
            )
        ])
    )
)
ctx.append_msg(client_hello)

# Create TLSPlaintext to include Handshake message
tlsplaintext = TLSPlaintext.create(ContentType.handshake, client_hello)
print(tlsplaintext)
print('[>>>] Send:')
print(hexdump(bytes(tlsplaintext)))

# Connect to server & send TLSPlaintext
client_conn = connection.ClientConnection('localhost', 50007)
client_conn.send_msg(bytes(tlsplaintext))

is_recv_serverhello = False
is_recv_finished = False

print("=== Handshake ===")

# Wait for server response
while True:
    # Blocking receive
    buf = None
    while not buf:
        buf = client_conn.recv_msg(setblocking=True)

    # Upon receiving a message, print it, and turn it into a stream
    print('[<<<] Recv:')
    print(hexdump(buf))
    stream = io.BytesIO(buf)

    # Parse TLSPlaintext
    while True:
        firstbyte = stream.read(1)
        if firstbyte == b'':
            break
        stream.seek(-1, io.SEEK_CUR)
        # Get ContentType
        content_type = ContentType(
            Uint8(int.from_bytes(firstbyte, byteorder='big')))

        # Handle Alert
        if content_type == ContentType.alert:
            tlsplaintext = TLSPlaintext.from_fs(stream)
            for alert in tlsplaintext.get_messages():
                print('[-] Recv Alert!')
                print(alert)
            sys.exit(1)

        # Handle 1st ServerHello
        elif not is_recv_serverhello:
            # ServerHello
            tlsplaintext = TLSPlaintext.from_fs(stream)
            for msg in tlsplaintext.get_messages():
                print('[*] ServerHello!')
                print(msg)
                ctx.append_msg(msg)

            # Produce shared key. Using key-exchange alg, and client secret key
            # Similar to pre-master secret in TLS 1.2
            ctx.set_key_exchange(dhkex_class, secret_key)
            Hash.length = ctx.hash_size
            print('[+] shared key:', ctx.shared_key.hex())

            # Key Schedule, produce early secret & handshake secret
            ctx.key_schedule_in_handshake()

            is_recv_serverhello = True

        # Ignore ChangeCipherSpec message
        elif content_type == ContentType.change_cipher_spec:
            # ChangeCipherSpec
            change_cipher_spec = TLSPlaintext.from_fs(stream)
            print(change_cipher_spec)

        # Handle EncryptedExtensions, Certificate, CertificateVerify, Finished
        elif content_type == ContentType.application_data:
            # EncryptedExtensions, Certificate, CertificateVerify, Finished
            print("Got!")

            tlsplaintext = TLSCiphertext.from_fs(stream) \
                                        .decrypt(ctx.server_traffic_crypto)
            # print(tlsplaintext)
            for msg in tlsplaintext.get_messages():
                ctx.append_msg(msg)
                print(msg)

                if msg.msg_type == HandshakeType.finished:
                    print('[*] Received Finished!')
                    is_recv_finished = True
                    break

    if is_recv_finished:
        break

# Verify Server-Finished
msgs_byte = b''.join(ctx.tls_messages_bytes[:-1])   # exclude Finished
finished_key = hkdf.HKDF_expand_label(
    ctx.server_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
expected_verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)
actual_verify_data = \
    ctx.tls_messages.get(
        HandshakeType.finished).msg.verify_data.get_raw_bytes()

if actual_verify_data != expected_verify_data:
    print('decrypt_error!')
    # TODO: create and send Alert msg
    sys.exit(0)

# Send Client-Finished
msgs_byte = ctx.get_messages_byte()
finished_key = hkdf.HKDF_expand_label(
    ctx.client_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)

finished = Handshake(
    msg_type=HandshakeType.finished,
    msg=Finished(
        verify_data=OpaqueHash(bytes(verify_data))
    )
)
print(finished)

tlsciphertext = TLSPlaintext.create(ContentType.handshake, finished) \
    .encrypt(ctx.client_traffic_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))
client_conn.send_msg(bytes(tlsciphertext))

# Key Schedule
ctx.key_schedule_in_app_data()


# Handsake is done.
# Now, we can send application data

loop_keyboard_input = True


def read_keyboard_input(inputQueue):
    print('Ready for keyboard input:')
    while loop_keyboard_input:
        input_str = input()
        inputQueue.put(input_str + "\n")


inputQueue = queue.Queue()
inputThread = threading.Thread(target=read_keyboard_input,
                               args=(inputQueue,), daemon=True)
inputThread.start()

print("=== Application Data ===")


try:
    while True:

        buf = None
        while not buf:
            buf = client_conn.recv_msg(setblocking=False)

            # Send keyboard input
            if inputQueue.qsize() > 0:
                input_byte = inputQueue.get().encode()
                tlsciphertext = \
                    TLSPlaintext.create(ContentType.application_data, input_byte) \
                    .encrypt(ctx.client_app_data_crypto)
                print(tlsciphertext)
                print('[>>>] Send:')
                print(hexdump(bytes(tlsciphertext)))

                client_conn.send_msg(bytes(tlsciphertext))

        print('[<<<] Recv:')
        print(hexdump(buf))

        stream = io.BytesIO(buf)

        while True:
            firstbyte = stream.read(1)
            if firstbyte == b'':
                break
            stream.seek(-1, io.SEEK_CUR)

            content_type = \
                ContentType(Uint8(int.from_bytes(firstbyte, byteorder='big')))

            # Handle Alert
            if content_type == ContentType.alert:
                tlsplaintext = TLSPlaintext.from_fs(stream)
                for alert in tlsplaintext.get_messages():
                    print('[-] Recv Alert!')
                    print(alert)
                sys.exit(1)

            # Handle encrypted application data
            elif content_type == ContentType.application_data:
                obj = TLSCiphertext.from_fs(stream) \
                    .decrypt(ctx.server_app_data_crypto)
                print(obj)

                if isinstance(obj.fragment, Handshake):
                    # New Session Ticket
                    print('[+] New Session Ticket arrived!')
                    ctx.append_msg(obj)

                else:
                    print(bytes(obj.fragment))

except KeyboardInterrupt:
    print('\nBye!')

# Closure Alert
closure_alert = Alert(
    level=AlertLevel.fatal,
    description=AlertDescription.close_notify
)

tlsciphertext = TLSPlaintext.create(ContentType.alert, closure_alert) \
    .encrypt(ctx.client_app_data_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))
client_conn.send_msg(bytes(tlsciphertext))

loop_keyboard_input = False

client_conn.close()