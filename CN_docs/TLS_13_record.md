# TLS 1.3 Record Protocol

> 参考：[RFC 8446 - Sec 5 - Record Protocol](https://tools.ietf.org/html/rfc8446#section-5)，[RFC 5116 - Sec 2 - AEAD Interface](https://datatracker.ietf.org/doc/html/rfc5116#section-2)
>
> 对应代码：`/src/protocal_recordlayer.py`


本节将介绍 RFC 8446 - Sec 5 - Record Protocol 中的内容，并给出本项目中的实现。本节将只介绍重要的 5.1 - Record Layer 和 5.2 - Record Payload Protection。本项目也有实现其余内容（5.3～5.5），但不算重点，故不在本节介绍，请读者自行阅读 RFC 8446。


## Record Layer

> 参考：[RFC 8446 - Sec 5.1 - Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)

TLS 1.3 的所有通信消息都存储在 `TLSPlaintext` 或 `TLSCiphertext` 结构体中，并作为数据包发送。

例如，在握手协议期间，`TLSPlaintext` / `TLSCiphertext` 结构体中将封装 `Handshake` 结构体。此 `Handshake` 结构体中封装了如 `ClientHello` 消息等内容。即，在握手过程中，客户端首先发送 ClientHello 消息，其层级关系如下（结构上是 `TLSPlaintext` 中包含 `Handshake`，`Handshake` 中包含 `ClientHello`）：

```
TLSPlaintext
└── Handshake
    └── ClientHello
```

协议消息必须按照一定顺序发送，若发现收到的握手消息顺序不对，必须使用 “unexpected_message” alert 消息来中止握手。要求如下：

1. 握手消息不得与其他记录类型交错。也就是说，如果握手消息被分成两个或多个记录，则它们之间不能有任何其他记录。
2. 握手消息绝不能跨越密钥更改。实现方必须验证密钥更改之前的所有消息是否与记录边界对齐; 如果没有，那么他们必须用 "unexpected_message" alert 消息终止连接。因为 ClientHello，EndOfEarlyData，ServerHello，Finished 和 KeyUpdate 消息可以在密钥更改之前立即发生，所以实现方必须将这些消息与记录边界对齐。

不能发送握手类型的零长度片段，即使这些片段包含填充。具有 alert 类型的记录必须只包含一条消息。应用数据消息始终受到保护。可以发送应用数据的零长度片段，因为它们可能作为流量分析对策使用。应用数据片段可以拆分为多个记录，也可以合并为一个记录。


**记录层**是 TLS 数据包的最底层。也被称为 **TLS 记录**，所有在连接上交换的消息都通过 TLS 记录来发送和接收。TLS 记录的开头有一个头部，其中存储了内容类型 `ContentType`、协议版本 `ProtocolVersion`、记录长度 `length` 三个信息。其后是消息数据。

```
[ ContentType | ProtocolVersion | length ]
    |
    |
+---V----+--------------+
| header | message data |
+--------+--------------+
```

所有 TLS 消息都被包含在以下所述的 `TLSPlaintext` 或 `TLSCiphertext` 中发送。接下来，我们将详细介绍 `TLSPlaintext` 和 `TLSCipheretext`。


### TLSPlaintext

`TLSPlaintext` 结构体用于发送明文消息。RFC 8446 中用 C 结构体定义如下：

```c
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion legacy_record_version = 0x0303;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```

本项目中，实现在 `/src/protocal_recordlayer.py - TLSPlaintext`。如下。

```python
class ContentType(Enum):
    elem_t = Uint8

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)

ProtocolVersion = Uint16

@meta.struct
class TLSPlaintext(meta.StructMeta):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.fragment)))
    fragment: OpaqueLength
```

关于 `TLSPlaintext`：

- **type**：封装的的更高级结构体的类型（2字节）
- **legacy_record_version**：（2字节），对于由 TLS 1.3实现生成的所有记录，必须设置为 `0x0303`，除了初始的 ClientHello（即在 HelloRetryRequest 之后生成的记录），在这种情况下也可以为兼容性目的设置为 `0x0301`。此字段已被弃用，必须对所有目的忽略。在一些情况下，以前的 TLS 版本会在此字段中使用其他值。
- **length**：`TLSPlaintext.fragment` 的长度（以字节计）（2字节）。长度不得超过 `2^14` 字节。接收超过此长度的记录的端点必须使用 “record_overflow” alert 消息终止连接。
- **fragment**：封装的上层结构体的数据。例如存储 `Handshake` 结构体的数据。



## Record Payload Protection

> 参考：[RFC 8446 - Sec 5.2 - Record Payload Protection](https://datatracker.ietf.org/doc/html/rfc8446#section-5.2)，[RFC 5116 - Sec 2 - AEAD Interface](https://datatracker.ietf.org/doc/html/rfc5116#section-2)

由于在 TLS 1.3 中，ServerHello 消息之后发送的消息必须加密，因此不需要 TLS 1.2 中的 Change Cipher Spec 协议。但根据 Postel 的原则（"发送要严格，接收要宽容"），即使收到 ChangeCipherSpec 也不会出错，只需忽略即可。

加密的方式如下实现。


### TLSCiphertext & TLSInnerPlaintext

`TLSCiphertext` 结构体用于发送加密消息。
实际上，在将要发送的消息结构体存储到 `TLSInnerPlaintext` 结构体中并添加足够的零填充使其长度成为 64 的倍数之后，加密存储到 `TLSCiphertext.encrypted_record` 中。

RFC 8446 中用 C 结构体定义如下，本项目中实现在 `/src/protocal_recordlayer.py - TLSCiphertext`、`/src/protocal_recordlayer.py - TLSInnerPlaintext`。

```c
struct {
    opaque content[TLSPlaintext.length];
    ContentType type;
    uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
    ContentType opaque_type = application_data; /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;
```

本项目中，实现在 `/src/protocal_recordlayer.py - TLSPlaintext`、`/src/protocal_recordlayer.py - TLSInnerPlaintext`。如下。

```python
@meta.struct
class TLSCiphertext(meta.StructMeta):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.encrypted_record)))
    encrypted_record: OpaqueLength

class TLSInnerPlaintext:
    # no member fields, only methods
```

关于 TLSInnerPlaintext：

- **content**：需要加密的结构体数据，即之前 `TLSPlaintext.fragment` 值，包含握手或警报消息的字节编码，或要发送的应用数据的原始字节。
- **type**：需要加密的结构体类型（2字节），即之前 `TLSPlaintext.type` 值。
- **zeros**：零填充（任意长度）。更多详细信息，请参见[RFC 8446 - Sec 5.4 - Record Padding](https://datatracker.ietf.org/doc/html/rfc8446##section-5.4)。

关于 TLSCiphertext：

- **opaque_type**：上层结构体类型（2字节），始终设置为 `application_data` 的值（0x17）。
- **legacy_record_version**：TLS 版本（2字节），为了 TLS 1.2 以前版本的兼容性，始终设置为 0x0303。
- **length**：上层结构体的字节长度（2字节）。是内容和填充的长度之和，加上内部内容类型的长度加上 AEAD 算法添加的任何扩展。长度不得超过 `2 ^ 14 + 256` 字节。接收超过此长度的记录的端点必须使用 "record_overflow" alert 消息终止连接。
- **encrypted_record**：AEAD 加密形式的序列化 `TLSInnerPlaintext` 结构。


### AEAD 加密

加密 TLSInnerPlaintext 至 TLSCiphertext 时使用认证加密（AEAD）。具体细节请参阅 [RFC 5116 - Sec 2 - AEAD Interface](https://datatracker.ietf.org/doc/html/rfc5116#section-2)。

本项目中，AEAD 加解密实现如下：

- `TLSPlaintext.encrypt()` 中，使用 `TLSInnerPlaintext.append_pad()` 对数据进行填充，然后利用 `cipher_instance.encrypt_and_tag()` 进行 AEAD 加密。
- `TLSCiphertext.decrypt()` 中，对加密记录进行解密，然后使用 `TLSInnerPlaintext.split_pad()` 移除填充，恢复原始数据。

