import struct  # Interpretation of byte sequences
import io  # Byte stream operations
import textwrap  # Text wrapping and filling
from enum import Enum as BuildinEnum

# The base class that all types inherit from


class Type:
    size = None  # Used for fixed-length
    size_t = None  # Used for variable-length
    # In the method to construct a structure from a byte sequence,
    # Pass a stream instead of a byte sequence so that the stream retains the number of characters read.

    @classmethod
    def from_bytes(cls, data):
        return cls.from_fs(io.BytesIO(data))

    # When constructing a structure, allow Opaque to refer to its parent instance.
    def set_parent(self, instance):
        self.parent = instance


class Uint(Type):
    def __init__(self, value):
        assert self.__class__ != Uint, \
            "Uint (Abstract Class) cannot construct instance!"
        assert isinstance(value, int)
        max_value = 1 << (8 * self.__class__.size)
        assert 0 <= value < max_value
        self.value = value

    def __bytes__(self):
        res = []
        tmp = self.value
        for i in range(self.__class__.size):
            res.append(bytes([tmp & 0xff]))
            tmp >>= 8
        res.reverse()
        return self.value.to_bytes(self.__class__.size, byteorder='big')

    @classmethod
    def from_fs(cls, fs, parent=None):
        data = fs.read(cls.size)
        return cls(int.from_bytes(data, byteorder='big'))

    def __len__(self):
        return self.__class__.size

    def __int__(self):
        return self.value

    def __eq__(self, other):
        return hasattr(other, 'value') and self.value == other.value

    def __repr__(self):
        classname = self.__class__.__name__
        value = self.value
        width = self.__class__.size * 2
        return "{}(0x{:0{width}x})".format(classname, value, width=width)

    def __hash__(self):
        return hash((self.__class__.size, self.value))


class Uint8(Uint):
    size = 1  # unsinged char


class Uint16(Uint):
    size = 2  # unsigned short


class Uint24(Uint):
    size = 3


class Uint32(Uint):
    size = 4  # unsigned int


class OpaqueMeta(Type):
    def get_raw_bytes(self):
        return self.byte

    def __eq__(self, other):
        return self.byte == other.byte

    def __len__(self):
        return len(self.byte)


def Opaque(size_t):
    if isinstance(size_t, int):  # When the argument is an int, it's fixed-length
        return OpaqueFix(size_t)
    # When the argument is a lambda, it's fixed-length determined at runtime
    if isinstance(size_t, type(lambda: None)):
        return OpaqueFix(size_t)
    if issubclass(size_t, Uint):  # When the argument is a UintN, it's variable-length
        return OpaqueVar(size_t)
    raise TypeError("size's type must be an int or Uint class.")


def OpaqueFix(size):
    # Fixed-length Opaque (e.g., opaque string[16])
    # However, the size can also be determined by an external variable (e.g., opaque string[Hash.length])

    class OpaqueFix(OpaqueMeta):
        size = 0

        def __init__(self, byte):
            assert isinstance(byte, (bytes, bytearray))
            size = OpaqueFix.size
            if callable(size):  # When size is a lambda, evaluate it at runtime to determine the size
                self.byte = byte
            else:
                assert len(byte) <= size
                self.byte = bytes(byte).rjust(size, b'\x00')

        def __bytes__(self):
            return self.byte

        @classmethod
        def from_fs(cls, fs, parent=None):
            size = cls.size
            if callable(size):  # When size is a lambda, evaluate it at runtime to determine the size
                size = int(size(parent))
            opaque = OpaqueFix(fs.read(size))
            opaque.set_parent(parent)
            return opaque

        def __repr__(self):
            size = OpaqueFix.size
            if callable(size):
                size = int(size(self.parent))
            return 'Opaque[%d](%s)' % (size, repr(self.byte))

    OpaqueFix.size = size
    return OpaqueFix


def OpaqueVar(size_t):

    # Variable-length Opaque (e.g., opaque string<0..15>)
    class OpaqueVar(OpaqueMeta):
        size_t = Uint

        def __init__(self, byte):
            assert isinstance(byte, (bytes, bytearray))
            self.byte = bytes(byte)
            self.size_t = OpaqueVar.size_t

        def __bytes__(self):
            UintN = self.size_t
            return bytes(UintN(len(self.byte))) + self.byte

        @classmethod
        def from_fs(cls, fs, parent=None):
            size_t = OpaqueVar.size_t
            length = int(size_t.from_fs(fs))
            byte = fs.read(length)
            return OpaqueVar(byte)

        def __repr__(self):
            return 'Opaque<%s>(%s)' % \
                (OpaqueVar.size_t.__name__, repr(self.byte))

    OpaqueVar.size_t = size_t
    return OpaqueVar


OpaqueUint8 = Opaque(Uint8)
OpaqueUint16 = Opaque(Uint16)
OpaqueUint24 = Opaque(Uint24)
OpaqueUint32 = Opaque(Uint32)
OpaqueLength = Opaque(lambda self: self.length)


class ListMeta(Type):
    pass


def List(size_t, elem_t):

    def my_issubclass(child, parent):
        if not hasattr(child, '__bases__'):
            return False
        return parent.__name__ in map(lambda x: x.__name__, child.__bases__)

    class List(ListMeta):
        size_t = None
        elem_t = None

        def __init__(self, array):
            self.array = array

        def get_array(self):
            return self.array

        def set_parent(self, instance):
            self.parent = instance

            from structmeta import StructMeta
            if my_issubclass(List.elem_t, StructMeta):
                for elem in self.get_array():
                    elem.set_parent(self.parent)

        def __bytes__(self):
            size_t = List.size_t
            content = b''.join(bytes(elem) for elem in self.get_array())
            content_len = len(content)
            return bytes(size_t(content_len)) + content

        @classmethod
        def from_fs(cls, fs, parent=None):
            from structmeta import StructMeta
            size_t = cls.size_t
            elem_t = cls.elem_t
            list_size = int(size_t.from_fs(fs))
            elem_size = elem_t.size

            array = []

            startpos = fs.tell()
            while (fs.tell() - startpos) < list_size:
                elem = elem_t.from_fs(fs, parent)
                array.append(elem)
            return List(array)

        def __eq__(self, other):
            if len(self.get_array()) != len(other.get_array()):
                return False
            for self_elem, other_elem in zip(self.get_array(), other.get_array()):
                if self_elem != other_elem:
                    return False
            return True

        def __repr__(self):
            from structmeta import StructMeta

            if my_issubclass(List.elem_t, StructMeta):
                output = ''
                for elem in self.get_array():
                    content = textwrap.indent(repr(elem), prefix="  ").strip()
                    output += '+ %s\n' % content
                return 'List<%s>:\n%s' % (self.__class__.size_t.__name__, output)
            else:

                return 'List<%s>%s' % \
                    (self.__class__.size_t.__name__, repr(self.get_array()))

        def __iter__(self):
            return iter(self.array)

        def find(self, arg):
            if callable(arg):
                return next((x for x in iter(self) if arg(x)), None)
            else:
                return next((x for x in iter(self) if x == arg), None)

    List.size_t = size_t
    List.elem_t = elem_t
    return List


class Enum(Type, BuildinEnum):

    def __bytes__(self):
        return bytes(self.value)

    @classmethod
    def from_fs(cls, fs, parent=None):
        elem_t = cls.get_type()
        return cls(elem_t.from_fs(fs))

    @classmethod
    def get_type(cls):
        return cls.elem_t.value


class EnumUnknown(Enum):
    @classmethod
    def _missing_(cls, value):
        obj = object.__new__(cls)
        obj._name_ = 'unknown'
        obj._value_ = value
        return obj


if __name__ == '__main__':

    import unittest

    class TestUint(unittest.TestCase):

        def test_uint(self):
            with self.assertRaises(Exception) as cm:
                a = Uint(123)

        def test_uint8(self):
            u = Uint8(0)
            self.assertEqual(bytes(u), b'\x00')
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)
            u = Uint8(0x12)
            self.assertEqual(bytes(u), b'\x12')
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)
            u = Uint8(255)
            self.assertEqual(bytes(u), b'\xff')
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)

        def test_uint8_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint8(256)
            with self.assertRaises(Exception) as cm:
                u = Uint8(-1)

        def test_uint16(self):
            u = Uint16(0)
            self.assertEqual(bytes(u), b'\x00\x00')
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)
            u = Uint16(0x0102)
            self.assertEqual(bytes(u), b'\x01\x02')
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)
            u = Uint16(65535)
            self.assertEqual(bytes(u), b'\xff\xff')
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)

        def test_uint16_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint16(65536)
            with self.assertRaises(Exception) as cm:
                u = Uint16(-1)

        def test_uint24(self):
            u = Uint24(0)
            self.assertEqual(bytes(u), b'\x00\x00\x00')
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)
            u = Uint24(0x010203)
            self.assertEqual(bytes(u), b'\x01\x02\x03')
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)
            u = Uint24(16777215)
            self.assertEqual(bytes(u), b'\xff\xff\xff')
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)

        def test_uint24_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint24(16777216)
            with self.assertRaises(Exception) as cm:
                u = Uint24(-1)

        def test_uint32(self):
            u = Uint32(0)
            self.assertEqual(bytes(u), b'\x00\x00\x00\x00')
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)
            u = Uint32(0x01020304)
            self.assertEqual(bytes(u), b'\x01\x02\x03\x04')
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)
            u = Uint32(4294967295)
            self.assertEqual(bytes(u), b'\xff\xff\xff\xff')
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)

        def test_uint32_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint32(4294967296)
            with self.assertRaises(Exception) as cm:
                u = Uint32(-1)

        def test_opaque_fix(self):
            Opaque4 = Opaque(4)
            o = Opaque4(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
            self.assertEqual(Opaque4.from_bytes(bytes(o)), o)

            Opaque8 = Opaque(8)
            o = Opaque8(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x00\x00\x00\x00\x01\x23\x45\x67')
            self.assertEqual(Opaque8.from_bytes(bytes(o)), o)

            self.assertEqual(Opaque4.size, 4)
            self.assertEqual(Opaque8.size, 8)

        def test_opaque_fix_invalid_args(self):
            Opaque4 = Opaque(4)
            with self.assertRaises(Exception) as cm:
                o = Opaque4(b'\x01\x23\x45\x67\x89')

        def test_opaque_fix_lambda_immediate_eval(self):
            OpaqueUnk = Opaque(lambda self: 4)
            o = OpaqueUnk(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
            self.assertEqual(OpaqueUnk.from_bytes(bytes(o)), o)

        def test_opaque_fix_lambda_lazy_eval(self):
            OpaqueUnk = Opaque(lambda self: hash_len)
            hash_len = 4
            o = OpaqueUnk(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
            self.assertEqual(OpaqueUnk.from_bytes(bytes(o)), o)

        def test_opaque_fix_lambda_parent_length(self):
            OpaqueUnk = Opaque(lambda self: self.length)

            import structmeta as meta

            @meta.struct
            class Test(meta.StructMeta):
                length: Uint8
                fragment: OpaqueUnk

            t = Test(length=Uint8(4), fragment=OpaqueUnk(b'\x01\x23\x45\x67'))
            self.assertEqual(bytes(t), b'\x04\x01\x23\x45\x67')
            self.assertEqual(Test.from_bytes(bytes(t)), t)

        def test_opaque_var(self):
            OpaqueUint8 = Opaque(Uint8)
            o = OpaqueUint8(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x04\x01\x23\x45\x67')
            self.assertEqual(OpaqueUint8.from_bytes(bytes(o)), o)

            OpaqueUint16 = Opaque(Uint16)
            o = OpaqueUint16(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x00\x04\x01\x23\x45\x67')
            self.assertEqual(OpaqueUint16.from_bytes(bytes(o)), o)

            self.assertEqual(OpaqueUint8.size_t, Uint8)
            self.assertEqual(OpaqueUint16.size_t, Uint16)

        def test_list_eq_neq(self):
            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l1 = ListUint16([Uint16(0), Uint16(0xffff)])
            l2 = ListUint16([Uint16(0), Uint16(0xffff)])
            l3 = ListUint16([Uint16(0), Uint16(0xfbff)])
            self.assertEqual(l1, l2)
            self.assertNotEqual(l1, l3)

        def test_list_fix(self):
            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l = ListUint16([])
            self.assertEqual(bytes(l), b'\x00')
            self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l = ListUint16([Uint16(1), Uint16(2), Uint16(65535)])
            self.assertEqual(bytes(l), b'\x06\x00\x01\x00\x02\xff\xff')
            self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

            ListUint8 = List(size_t=Uint16, elem_t=Uint8)
            l = ListUint8([Uint8(1), Uint8(2), Uint8(255)])
            self.assertEqual(bytes(l), b'\x00\x03\x01\x02\xff')
            self.assertEqual(ListUint8.from_bytes(bytes(l)), l)

            Opaque2 = Opaque(2)
            ListOpaque2 = List(size_t=Uint8, elem_t=Opaque2)
            l = ListOpaque2([Opaque2(b'\xdd\xdd'), Opaque2(b'\xff\xff')])
            self.assertEqual(bytes(l), b'\x04\xdd\xdd\xff\xff')
            self.assertEqual(ListOpaque2.from_bytes(bytes(l)), l)

        def test_list_var(self):
            OpaqueUint8 = Opaque(Uint8)
            ListOpaqueUint8 = List(size_t=Uint8, elem_t=OpaqueUint8)
            l = ListOpaqueUint8(
                [OpaqueUint8(b'\x12\x12'), OpaqueUint8(b'\xff\xff')])
            self.assertEqual(bytes(l), b'\x06\x02\x12\x12\x02\xff\xff')
            self.assertEqual(ListOpaqueUint8.from_bytes(bytes(l)), l)

        def test_enum(self):
            class FooType(Enum):
                hoge = 1

            self.assertEqual(FooType.hoge, FooType(1))
            with self.assertRaises(Exception) as cm:
                FooType(2)

        def test_enum_unknown(self):
            class FooType(EnumUnknown):
                hoge = 1

            self.assertEqual(FooType.hoge, FooType(1))
            t2 = FooType(2)
            self.assertEqual(t2.name, 'unknown')
            self.assertEqual(t2.value, 2)

    unittest.main()
