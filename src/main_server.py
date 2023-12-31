from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import os
import sys
import io
import threading
import queue
import ssl

import connection
from type import Uint8, Uint16, OpaqueUint8, OpaqueUint16, OpaqueUint24, OpaqueLength
from disp import hexdump

from protocol_tlscontext import TLSContext
from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext, TLSCiphertext, TLSInnerPlaintext
from protocol_handshake import Handshake
from protocol_hello import ServerHello
from protocol_ciphersuite import CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType, \
    EncryptedExtensions
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_authentication import Certificate, \
    CertificateEntrys, CertificateEntry, \
    CertificateVerify, \
    Finished, Hash, OpaqueHash
from protocol_alert import Alert, AlertLevel, AlertDescription


from crypto_ecdhe import x25519
import crypto_hkdf as hkdf

ctx = TLSContext('server')

# === Key Exchange Parameters ===

dhkex_class = x25519
secret_key = os.urandom(32)
public_key = dhkex_class(secret_key)

server_conn = connection.ServerConnection('localhost', 50007)

buf = server_conn.recv_msg(setblocking=True)
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

# 1st ClientHello
for msg in TLSPlaintext.from_fs(stream).get_messages():
    print('[*] ClientHello!')
    print(msg)
    print(hexdump(bytes(msg)))
    ctx.append_msg(msg)

# Server CipherSuite only support TLS_CHACHA20_POLY1305_SHA256
client_hello = ctx.tls_messages.get(HandshakeType.client_hello)
has_chacha20poly1305 = client_hello.msg.cipher_suites \
    .find(lambda suite: suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
if not has_chacha20poly1305:
    print('handshake_failure')
    sys.exit(0)

# === Server Hello ====

server_hello = Handshake(
    msg_type=HandshakeType.server_hello,
    msg=ServerHello(
        cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        legacy_session_id_echo=client_hello.msg.legacy_session_id,
        extensions=Extensions([
            Extension(
                extension_type=ExtensionType.supported_versions,
                extension_data=SupportedVersions(
                    versions=ProtocolVersion.TLS13
                )
            ),
            Extension(
                extension_type=ExtensionType.key_share,
                extension_data=KeyShareHello(
                    shares=KeyShareEntry(
                        group=NamedGroup.x25519,
                        key_exchange=OpaqueUint16(public_key)
                    )
                )
            )
        ])
    )
)
ctx.append_msg(server_hello)
print(server_hello)

# Key Schedule
# Produce shared key. Using key-exchange alg, and client secret key
# Similar to pre-master secret in TLS 1.2
ctx.set_key_exchange(dhkex_class, secret_key)
# Key Schedule, produce early secret & handshake secret
ctx.key_schedule_in_handshake()
Hash.length = ctx.hash_size

tlsplaintext = TLSPlaintext.create(ContentType.handshake, server_hello)
print('[>>>] Send:')
print(hexdump(bytes(tlsplaintext)))
server_conn.send_msg(bytes(tlsplaintext))

# create EncryptedExtensions
encrypted_extensions = Handshake(
    msg_type=HandshakeType.encrypted_extensions,
    msg=EncryptedExtensions(extensions=Extensions([]))
)
ctx.append_msg(encrypted_extensions)
print(encrypted_extensions)

# create Certificate
with open('cert/server.crt', 'r') as f:
    cert_data = ssl.PEM_cert_to_DER_cert(f.read())

certificate = Handshake(
    msg_type=HandshakeType.certificate,
    msg=Certificate(
        certificate_request_context=OpaqueUint8(b''),
        certificate_list=CertificateEntrys([
            CertificateEntry(
                cert_data=OpaqueUint24(cert_data),
                extensions=Extensions([])
            )
        ])
    )
)
ctx.append_msg(certificate)
print(certificate)
print(hexdump(bytes(certificate)))

# create CertificateVerify
# sign with server private key
key = RSA.importKey(open('cert/server.key').read())
client_signature_scheme_list = \
    ctx.tls_messages.get(HandshakeType.client_hello).msg.extensions \
    .find(lambda ext: ext.extension_type == ExtensionType.signature_algorithms) \
    .extension_data.supported_signature_algorithms
print(client_signature_scheme_list)

if SignatureScheme.rsa_pss_rsae_sha256 in client_signature_scheme_list:
    server_signature_scheme = SignatureScheme.rsa_pss_rsae_sha256
    from Crypto.Signature import PKCS1_PSS
    message = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify' \
        + b'\x00' + \
        hkdf.transcript_hash(ctx.get_messages_byte(), ctx.hash_name)
    print("message:")
    print(hexdump(message))
    h = SHA256.new(message)
    certificate_signature = PKCS1_PSS.new(key).sign(h)
else:
    raise NotImplementedError()

certificate_verify = Handshake(
    msg_type=HandshakeType.certificate_verify,
    msg=CertificateVerify(
        algorithm=server_signature_scheme,
        signature=OpaqueUint16(certificate_signature)
    )
)
ctx.append_msg(certificate_verify)
print(certificate_verify)

# create Finished
msgs_byte = ctx.get_messages_byte()
finished_key = hkdf.HKDF_expand_label(
    ctx.server_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)
finished = Handshake(
    msg_type=HandshakeType.finished,
    msg=Finished(
        verify_data=OpaqueHash(bytes(verify_data))
    )
)
ctx.append_msg(finished)
print(finished)

# send EncryptedExtensions + Certificate + CertificateVerify + Finished
tlsciphertext = \
    TLSPlaintext.create(ContentType.handshake,
                        encrypted_extensions, certificate,
                        certificate_verify, finished) \
    .encrypt(ctx.server_traffic_crypto)
print('[>>>] Send:')
print(hexdump(bytes(tlsciphertext)))

server_conn.send_msg(bytes(tlsciphertext))


print("=== Application Data ===")

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

is_recv_finished = False

try:
    while True:
        buf = None
        while not buf:
            buf = server_conn.recv_msg(setblocking=False)

            if inputQueue.qsize() > 0:
                input_byte = inputQueue.get().encode()
                tlsciphertext = \
                    TLSPlaintext.create(ContentType.application_data, input_byte) \
                    .encrypt(ctx.server_app_data_crypto)
                print(tlsciphertext)
                print('[>>>] Send:')
                print(hexdump(bytes(tlsciphertext)))

                server_conn.send_msg(bytes(tlsciphertext))

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

            if content_type == ContentType.alert:
                tlsplaintext = TLSPlaintext.from_fs(stream)
                for alert in tlsplaintext.get_messages():
                    print('[-] Recv Alert!')
                    print(alert)
                sys.exit(1)

            elif content_type == ContentType.change_cipher_spec:
                # ChangeCipherSpec
                change_cipher_spec = TLSPlaintext.from_fs(stream)
                print(change_cipher_spec)

            elif not is_recv_finished and content_type == ContentType.application_data:
                tlsplaintext = \
                    TLSCiphertext.from_fs(stream).decrypt(
                        ctx.client_traffic_crypto)
                for msg in tlsplaintext.get_messages():
                    print('[*] Finished!')
                    print(msg)
                    print(hexdump(bytes(msg)))

                is_recv_finished = True

                # Key Schedule
                ctx.key_schedule_in_app_data()

            elif content_type == ContentType.application_data:
                obj = TLSCiphertext.from_fs(stream) \
                    .decrypt(ctx.client_app_data_crypto)
                print(obj)

                print(bytes(obj.fragment))

except KeyboardInterrupt:
    print('\nBye!')

# Closure Alert
closure_alert = Alert(
    level=AlertLevel.fatal,
    description=AlertDescription.close_notify
)

tlsciphertext = TLSPlaintext.create(ContentType.alert, closure_alert) \
    .encrypt(ctx.server_app_data_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))
server_conn.send_msg(bytes(tlsciphertext))

server_conn.close()
