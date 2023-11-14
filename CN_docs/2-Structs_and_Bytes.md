# TLS 1.3 数据结构

> 本节将介绍基本类型的数据结构和字节序列的转换方法，并实现它们。
> 
> 以下各类型，实现在 `/src/type.py`, `/src/structmeta.py`。

## Uint 类型（数值）

通常，uint 是 unsinged int 的缩写，但在 RFC 8446 中，类型定义如下：

| 类型 | C语言类型 | 大小 |
|---|---|---|
| uint8	 | unsinged char	| 1 |
| uint16 | 	unsinged short	| 2 |
| uint24 | 		 | 3 | 
| uint32 | 	unsinged int	| 4 |

因此，我们创建 Uint8, Uint16, Uint24, Uint32 这些类。
由于可能出现共同的处理方式，我们还将创建一个名为 Uint 的抽象类。
Uint 的实现将包括以下功能：

- 将 Uint 类型转换为字节序列的方法 `.__bytes__()`
- 从字节序列恢复 Uint 类型的方法 `.from_bytes()`

以下是创建的 UintN 类型预期的操作示例：

```python
num = Uint16(0x1234)
num_byte = b'\x12\x34'
assert bytes(num) == num_byte
assert num == Uint16.from_bytes(num_byte)
```

## Opaque 类型（字节序列）

RFC 中使用的 opaque 是用于存储字节序列的类型。
opaque 有固定长度和可变长度两种。

```c
opaque string[16];        /* string 是 16 字节固定 */
opaque string<0..2^4-1>;  /* string 是 0〜15 字节 */
opaque string<0..2^8-1>;  /* string 是 0〜255 字节 */
opaque string<0..2^16-1>; /* string 是 0〜65535 字节 */
opaque string<0..2^32-1>; /* string 是 0〜4294967295 字节 */
```

固定长度的 opaque 因为大小固定，所以只存储字节序列。
可变长度的 opaque 因为大小可变，所以由表示字节序列长度的部分和存储字节序列的部分组成。

- `opaque[16]` : 数据（16 字节）
- `opaque<0..2^4-1>` : 表示数据长度的部分（1 字节）+ 数据（N 字节）
- `opaque<0..2^8-1>` : 表示数据长度的部分（2 字节）+ 数据（N 字节）
- `opaque<0..2^16-1>` : 表示数据长度的部分（3 字节）+ 数据（N 字节）
- `opaque<0..2^32-1>` : 表示数据长度的部分（4 字节）+ 数据（N 字节）

因此，我们创建两个类：固定长度的 OpaqueFix 和可变长度的 OpaqueVar。

- OpaqueFix 类用于存储固定长度的字节序列，因此接受一个表示大小的整数作为参数。
- OpaqueVar 类用于存储可变长度的字节序列，因此接受表示数据长度的 UintN 类型作为参数。

各类 Opaque 的实现将包括以下功能：

- 将 Opaque 类型转换为字节序列的方法 `.__bytes__()`
- 从字节序列恢复 Opaque 类型的方法 `.from_bytes()`

以下是创建的 Opaque 类型预期的操作示例：

```python
# 固定长度的情况
Opaque4 = OpaqueFix(4)
nonce = Opaque4(b'\xaa\xaa\xaa\xaa')
nonce_byte = b'\xaa\xaa\xaa\xaa'
assert bytes(nonce) == nonce_byte
assert nonce == Opaque4.from_bytes(nonce)

# 可变长度的情况
OpaqueUint8 = OpaqueVar(Uint8)
session_id = OpaqueUint8(b'\xbb\xbb\xbb\xbb')
session_id_byte = b'\x04\xbb\xbb\xbb\xbb'
assert bytes(session_id) == session_id_byte
assert session_id == OpaqueUint8.from_bytes(session_id_byte)
```

## List 类型（向量类型，数组）

向量类型有两种：元素为固定长度的和元素为可变长度的。
如果元素是固定长度的，则实现相对简单。但如果元素是可变长度的，则目前这种方式实现起来相当复杂，因此我们对迄今为止实现的 Uint 类型和 Opaque 类型进行一些修改。

### .from_bytes → .from_fs

目前为止，我们是从字节序列恢复类型，但现在我们将其改为从流中恢复类型。
流是提供对字节序列读写的功能的东西。
例如，对流执行 `.read(2)` 将读取前两个字节。再次执行 `.read(2)`，它将读取从上次读取的位置开始的两个字节。

一个简单的程序示例如下：

```python
import io
f = io.BytesIO(b'abcdefg')
f.read(2) # => b'ab'
f.read(2) # => b'cd'
f.read(3) # => b'efg'
```

接下来，我们也将 Uint 类型和 Opaque 类型的函数修改为从流中恢复类型。
预期的操作如下：

```python
import io

# Uint 类型
f = io.BytesIO(b'\x11\x22\x33\x44')
value1 = Uint8.from_fs(f)  # => Uint8(0x11)
value2 = Uint16.from_fs(f) # => Uint16(0x2233)

# Opaque 类型
f = io.BytesIO(b'\x02\xaa\xaa\x03\xbb\xbb\xbb')
value1 = OpaqueUint8(f)  #=> Opaque<Uint8>(b'\xaa\xaa')
value2 = OpaqueUint8(f)  #=> Opaque<Uint8>(b'\xbb\xbb\xbb')
```

同时，为了继续使用 `.from_bytes`，我们将创建一个 `Type` 父类，在这里实现当调用 `.from_bytes` 时将字节序列转换为流并调用 `.from_fs`。之所以这样做，是因为测试从字节序列恢复类型时这样更方便。

```python
class Type:
    @classmethod
    def from_bytes(cls, data):
        return cls.from_fs(io.BytesIO(data))

class Uint(Type):
    ...

class Opaque(Type):
    ...
```

### List 类型的实现

在有了 `.from_fs` 后，我们将实现 List 类型。

与其他类型一样，我们将创建 `.__bytes__()` 和 `.from_bytes()`。
List 类型由 “表示 List 长度的部分” 和 “List 的各个元素的部分” 组成。
因此，当将类型转换为字节序列时，就像 OpaqueVar 类型一样，在字节序列的开头添加表示 List 各元素字节序列长度的 Uint 类型。
反过来，从字节序列恢复 List 类型时，只需读取开头的长度，然后根据这个长度重复用元素类型的 `.from_fs`。

一个简单的程序示例，假设 `List` 类型的大小用 `size_t` 表示，元素类型用 `elem_t` 表示，代码如下：

```python
def from_fs(fs):
    ...
    list_size = int(size_t.from_fs(fs)) # 列表的整体长度
    array = []
    # 在当前流位置不超过整体长度的情况下，重复执行
    startpos = fs.tell()
    while (fs.tell() - startpos) < list_size:
        elem = elem_t.from_fs(fs, parent)
        array.append(elem)
    ...
```

以下是创建的 List 类型预期的操作示例：

```python
OpaqueUint8 = OpaqueVar(Uint8)
OpaqueUint8s = List(size_t=Uint8, elem_t=OpaqueUint8)
sample = OpaqueUint8s([
    OpaqueUint8(0xaa),
    OpaqueUint8(0xbbbb),
])
sample_byte = b'\x05\x01\xaa\x02\xbb\xbb'
assert bytes(sample) == sample_byte
assert sample == OpaqueUint8s.from_bytes(sample_byte)
```

## Enum 类型（枚举类型）

Enum 类型用于表示 TLS 版本或加密套件。
例如，TLS 的 ContentType 有五种状态：

```c
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    (255)
} ContentType;
```

将上述 RFC 符号表示为 Python 程序时，我们希望它如下所示：

```python
class ContentType(Enum):
    elem_t = Uint8

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)
```

与其他类型一样，我们将创建 `.__bytes__()` 和 `.from_bytes()`。

以下是创建的 Enum 类型预期的操作示例：

```python
class ContentType(Enum):
    elem_t = Uint8
    handshake = Uint8(0x16)

assert ContentType.handshake == Uint8(0x16)
assert bytes(ContentType.handshake) == b'\x16'
assert ContentType.handshake == ContentType.from_bytes(b'\x16')
```