# ------------------------------------------------------------------------------
# Certificate
#   - RFC 8446 #section-4.4.2 (Certificate)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
#   - RFC 8446 #section-4.4.3 (Certificate Verify)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
#   - RFC 8446 #section-4.4.4 (Finished)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
# ------------------------------------------------------------------------------


from type import Uint8, Uint16, Uint24, Opaque, List, Enum, \
    OpaqueUint8, OpaqueUint16, OpaqueUint24
import structmeta as meta

from protocol_extensions import Extensions, Extension
from protocol_ext_signature import SignatureScheme

# --- Certificate --------------------------------------------------------------


### CertificateType ###
# enum {
#     X509(0),
#     RawPublicKey(2),
#     (255)
# } CertificateType;
#
class CertificateType(Enum):
    elem_t = Uint8

    X509 = Uint8(0)
    RawPublicKey = Uint8(2)


### CertificateEntry ###
# struct {
#     select (certificate_type) {
#         case RawPublicKey:
#           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
#           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
#
#         case X509:
#           opaque cert_data<1..2^24-1>;
#     };
#     Extension extensions<0..2^16-1>;
# } CertificateEntry;
#
@meta.struct
class CertificateEntry(meta.StructMeta):
    cert_data: OpaqueUint24
    extensions: Extensions


CertificateEntrys = List(size_t=Uint24, elem_t=CertificateEntry)


### Certificate ###
# struct {
#     opaque certificate_request_context<0..2^8-1>;
#     CertificateEntry certificate_list<0..2^24-1>;
# } Certificate;
#
@meta.struct
class Certificate(meta.StructMeta):
    certificate_request_context: OpaqueUint8
    certificate_list: CertificateEntrys


### CertificateVerify ###
# struct {
#     SignatureScheme algorithm;
#     opaque signature<0..2^16-1>;
# } CertificateVerify;
#
@meta.struct
class CertificateVerify(meta.StructMeta):
    algorithm: SignatureScheme
    signature: OpaqueUint16

# --- Finished -----------------------------------------------------------------

### TLS Finished ###


class Hash:
    length = None


OpaqueHash = Opaque(lambda self: Hash.length)


### Finished ###
# struct {
#     opaque verify_data[Hash.length];
# } Finished;
#
@meta.struct
class Finished(meta.StructMeta):
    verify_data: OpaqueHash


if __name__ == '__main__':

    import unittest

    class TestUint(unittest.TestCase):

        def test_certificate(self):
            c = Certificate(
                certificate_request_context=OpaqueUint8(b'\xaa\xaa'),
                certificate_list=CertificateEntrys([
                    CertificateEntry(
                        cert_data=OpaqueUint24(b'\xbb\xbb'),
                        extensions=Extensions([])),
                    CertificateEntry(
                        cert_data=OpaqueUint24(b'\xcc\xcc'),
                        extensions=Extensions([])),
                ])
            )
            c_bytes = bytes.fromhex('''
                02 AA AA 00 00 0E 00 00  02 BB BB 00 00 00 00 02
                CC CC 00 00
            ''')

            self.assertEqual(bytes(c), c_bytes)
            self.assertEqual(Certificate.from_bytes(bytes(c)), c)

        def test_finished_to_bytes(self):

            finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))
            finished_byte = b'\xAA' * 32
            self.assertEqual(bytes(finished), finished_byte)

        def test_finished_from_bytes(self):
            finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))

            with self.assertRaises(Exception) as cm:
                Finished.from_bytes(bytes(finished))

            Hash.length = 32
            finished2 = Finished.from_bytes(bytes(finished))
            self.assertEqual(finished, finished2)

    unittest.main()
