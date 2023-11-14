# TLS 1.3 握手过程

> **参考**
>
> https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md



本节中，将概要介绍 TLS 协议包的结构。请先查看 `/CN_docs/1-Overview.md`。更为详细的 TLS 1.3 握手原理、算法细节介绍，见 `/CN_docs/4-Handshake_Principles.md`。有关 TLS 1.3 拓展，见 `/CN_docs/5-Extensions.md`。



首先，所有消息都存储在 TLSPlaintext 或 TLSCiphertext 结构体中，并作为数据包发送。在握手协议期间，TLSPlaintext / TLSCiphertext 结构体中将包含 Handshake 结构体。此 Handshake 结构体中存储了如 ClientHello 消息等内容。

即，在握手过程中，客户端首先发送 ClientHello 消息，其层级关系如下（结构上是 TLSPlaintext 中包含 Handshake，Handshake 中包含 ClientHello）：

```
TLSPlaintext
└── Handshake
    └── ClientHello
```

协议消息必须按照一定顺序发送（顺序[见后](##握手协议 & 原理分析)）。如果对端发现收到的握手消息顺序不对，必须使用 “unexpected_message” alert 消息来中止握手。



## 协议包结构 - 记录层 (Record Layer)

> 以下各类型，实现在 `/src/protocal_recordlayer.py`

**记录层**是 TLS 数据包的最底层。也被称为 **TLS 记录**，所有在连接上交换的消息都通过 TLS 记录来发送和接收。TLS 记录的开头有一个头部，其中存储了内容类型（ContentType）、协议版本（ProtocolVersion）和记录长度三个信息。其后是消息数据。

```
      [ ContentType | ProtocolVersion | length ]
          |
          |
      +---V----+--------------+
      | header | message data |
      +--------+--------------+
```

所有 TLS 消息都被包含在以下所述的 TLSPlaintext 或 TLSCiphertext 中发送。TLS 记录有两种结构体：TLSPlaintext 和 TLSCiphertext，它们的结构相同。

接下来，我们将详细介绍 TLSPlaintext 和 TLSCipheretext。

### TLSPlaintext

TLSPlaintext 结构体用于发送明文消息。

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

关于 TLSPlaintext：

- type：存储的结构体类型（2字节）
- legacy_record_version：TLS 版本（2字节），为了 TLS 1.2 以前版本的兼容性，始终设置为 0x0303。
- length：上层结构体的字节长度（2字节）
- fragment：上层结构体的数据。例如存储 Handshake 结构体的数据。

ProtocolVersion 的值分别是：0x0300 表示 SSL 3.0，0x0301 表示 TLS 1.0，0x0302 表示 TLS 1.1，0x0303 表示 TLS 1.2，0x0304 表示 TLS 1.3。在 TLS 1.3 中，TLSPlaintext.legacy_record_version 字段已弃用，不再使用。但为了兼容性，该字段仍被保留。

如果以 Python 编写 TLSPlaintext 的 RFC 表达式，希望程序如下：

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

在 TLS 1.3 中，ServerHello 消息之后发送的消息必须加密，因此不需要 TLS 1.2 中的 Change Cipher Spec 协议。但根据 Postel 的原则（"发送要严格，接收要宽容"），即使收到 ChangeCipherSpec 也不会出错，只需忽略即可。

### TLSCiphertext

TLSCiphertext 结构体用于发送加密消息。
实际上，在将要发送的消息结构体存储到 TLSInnerPlaintext 结构体中并添加足够的零填充使其长度成为 64 的倍数之后，将加密的结构体数据存储到 TLSCiphertext.encrypted_record 中。

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

关于 TLSInnerPlaintext：

- content：需要加密的结构体数据
- type：需要加密的结构体类型（2字节）
- zeros：零填充（任意长度）

关于 TLSCiphertext：

- opaque_type：上层结构体类型（2字节），始终设置为 application_data 的值（0x17）。
- legacy_record_version：TLS 版本（2字节），为了 TLS 1.2 以前版本的兼容性，始终设置为 0x0303。
- length：上层结构体的字节长度（2字节）
- encrypted_record：上层结构体的数据，存储 TLSInnerPlaintext。

加密 TLSInnerPlaintext 至 TLSCiphertext 时使用认证加密（AEAD）。

如果以 Python 编写 TLSCiphertext 的 RFC 表达式，希望程序如下。TLSInnerPlaintext 结构体只是在加密前将结构体长度调整为 16 的倍数的零填充，因此在程序中不表示为结构体。

```python
@meta.struct
class TLSCiphertext(meta.StructMeta):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.encrypted_record)))
    encrypted_record: OpaqueLength
```



## 握手协议 & 原理分析

> 以下各类型，实现在 `/src/protocol_handshake.py`, `/src/protocol_hello.py`

### 相关数据结构

与握手相关的消息使用 Handshake 结构体。
握手协议有一个头部，其中存储了握手类型（HandshakeType）和消息长度。

```
    [ HandshakeType | length ]
        |
        |
    +---V----+--------------+
    | header | message data |
    +--------+--------------+
```

将握手协议存储在 TLS 记录中时，16进制数据如下所示：

```
ContentType
|    ProtocolVersion
|    |     记录长度(length)
|    |     |   HandshakeType
|    |     |   |    消息长度(length)
|    |     |   |    |       message data...
V  <---> <---> V  <------> <--------------->
16 03 03 02 00 01 00 01 fc ...
```

使用 Wireshark 等工具抓取数据包时，可以确认数据包具有上述结构。

#### Handshake

Handshake 结构体用于握手协议，进行密钥共享或传输证书。

```c
enum {
    client_hello(1),
    server_hello(2),
    new_session_ticket(4),
    end_of_early_data(5),
    encrypted_extensions(8),
    certificate(11),
    certificate_request(13),
    certificate_verify(15),
    finished(20),
    key_update(24),
    message_hash(254),
    (255)
} HandshakeType;

struct {
    HandshakeType msg_type;    /* 握手类型 */
    uint24 length;             /* 消息中剩余的字节 */
    select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
    };
} Handshake;
```

关于 Handshake：

- msg_type：消息结构类型（2字节）
- length：消息结构的字节长度（3字节）
- 消息数据：消息结构的数据

消息数据根据 `.msg_type` 的值会有所不同。
例如，当 `.msg_type` 是 `HandshakeType.client_hello` 时，消息类型将为 ClientHello。

使用 Python 表达 Handshake 的 RFC 格式时，可以编写如下程序：

```python
@meta.struct
class Handshake(meta.StructMeta):
    msg_type: HandshakeType
    length: Uint24 = lambda self: Uint24(len(bytes(self.msg)))
    msg: meta.Select('msg_type', cases={
        HandshakeType.client_hello:         ClientHello,
        HandshakeType.server_hello:         ServerHello,
        HandshakeType.encrypted_extensions: EncryptedExtensions,
        HandshakeType.certificate:          Certificate,
        HandshakeType.certificate_verify:   CertificateVerify,
        HandshakeType.finished:             Finished,
        HandshakeType.new_session_ticket:   NewSessionTicket,
    })
```

### Key Exchange Messages

#### ClientHello

TLS 中首先由客户端发送 ClientHello。

```c
uint16 ProtocolVersion;
opaque Random[32];

uint8 CipherSuite[2];    /* Cryptographic suite selector */

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;
```

- legacy_version：TLS 版本（2字节）。为了与 TLS1.2 之前的版本兼容，总是设置为 0x0303。
- random：由安全随机数生成器生成的 32 字节随机数。
- legacy_session_id：在 TLS 1.2 中，客户端使用此字段来恢复现有会话，但在 TLS 1.3 中，会话恢复已被禁止，因此填充随机的 32 字节值。
- cipher_suite：客户端支持的密码套件列表。
- legacy_compression_methods：压缩方法。总是设为 0 （参见 CRIME 攻击）。
- extensions：TLS 扩展列表。在 TLS1.3 中，总是包含 supported_versions 扩展，因此如果没有这个扩展，则可以确定是在 TLS 1.2 或更早版本中发送的 ClientHello。

使用 Python 表达 ClientHello 的 RFC 格式时，可以编写如下程序：

```python
@meta.struct
class ClientHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suites: CipherSuites
    legacy_compression_methods: OpaqueUint8 = OpaqueUint8(b'\x00')
    extensions: Extensions
```

### Server Hello

ServerHello 是服务器响应 ClientHello 的消息。

```c
struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id_echo<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method = 0;
    Extension extensions<6..2^16-1>;
} ServerHello;
```

- legacy_version：TLS 版本（2字节）。为了与 TLS 1.2 之前的版本兼容，总是设置为 0x0303。
- random：由安全随机数生成器生成的 32 字节随机数。
- legacy_session_id_echo：与客户端的 ClientHello.legacy_session_id 值相同。这是为了与 TLS1.2 以前的版本兼容。
- cipher_suite：服务器从 ClientHello.cipher_suites 中选择的密码套件。
- legacy_compression_method：压缩方法。总是设为 0 （参见 CRIME 攻击）。
- extensions：TLS 扩展列表。在 TLS1.3 中，总是包含 supported_versions 扩展。其他与密钥共享无关的扩展将在 EncryptedExtensions 消息中发送。

使用 Python 表达 ServerHello 的 RFC 格式时，可以编写如下程序：

```python
@meta.struct
class ServerHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id_echo: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suite: CipherSuite
    legacy_compression_method: Opaque1 = Opaque1(b'\x00')
    extensions: Extensions
```

### Hello Retry Request

如果从 ClientHello 发送的信息不足以继续握手，则服务器会返回 HelloRetryRequest。但是，HelloRetryRequest 的结构与 ServerHello 相同。

### Encrypted Extensions

在服务器发送 ServerHello 后，必须发送的消息是 Encrypted Extensions。

```c
enum {
    server_name(0),                             /* RFC 6066 */
    max_fragment_length(1),                     /* RFC 6066 */
    status_request(5),                          /* RFC 6066 */
    supported_groups(10),                       /* RFC 8422, 7919 */
    signature_algorithms(13),                   /* RFC 8446 */
    use_srtp(14),                               /* RFC 5764 */
    heartbeat(15),                              /* RFC 6520 */
    application_layer_protocol_negotiation(16), /* RFC 7301 */
    signed_certificate_timestamp(18),           /* RFC 6962 */
    client_certificate_type(19),                /* RFC 7250 */
    server_certificate_type(20),                /* RFC 7250 */
    padding(21),                                /* RFC 7685 */
    pre_shared_key(41),                         /* RFC 8446 */
    early_data(42),                             /* RFC 8446 */
    supported_versions(43),                     /* RFC 8446 */
    cookie(44),                                 /* RFC 8446 */
    psk_key_exchange_modes(45),                 /* RFC 8446 */
    certificate_authorities(47),                /* RFC 8446 */
    oid_filters(48),                            /* RFC 8446 */
    post_handshake_auth(49),                    /* RFC 8446 */
    signature_algorithms_cert(50),              /* RFC 8446 */
    key_share(51),                              /* RFC 8446 */
    (65535)
} ExtensionType;

struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

struct {
    Extension extensions<0..2^16-1>;
} EncryptedExtensions;
```

如果服务器没有特殊操作，它将发送一个没有 TLS 扩展的 EncryptedExtensions 给客户端。
可以在 EncryptedExtensions 中发送的 TLS 扩展列表如下：

- server_name ([RFC 6066](https://tools.ietf.org/html/rfc6066))
- max_fragment_length ([RFC 6066](https://tools.ietf.org/html/rfc6066))
- supported_groups ([RFC 7919](https://tools.ietf.org/html/rfc7919))
- use_srtp ([RFC 5764](https://tools.ietf.org/html/rfc5764))
- heartbeat ([RFC 6520](https://tools.ietf.org/html/rfc6520))
- application_layer_protocol_negotiation ([RFC 7301](https://tools.ietf.org/html/rfc7301))
- client_certificate_type ([RFC 7250](https://tools.ietf.org/html/rfc7250))
- server_certificate_type ([RFC 7250](https://tools.ietf.org/html/rfc7250))
- early_data ([RFC 8446](https://tools.ietf.org/html/rfc8446))


### Certificate Request

如果需要客户端认证，服务器会发送 CertificateRequest 消息。

```c
struct {
    opaque certificate_request_context<0..2^8-1>;
    Extension extensions<2..2^16-1>;
} CertificateRequest;
```

### Certificate

Certificate 消息用于发送服务器证书。如果使用预共享密钥（PSK），可以省略此消息。

```c
enum {
    X509(0),
    RawPublicKey(2),
    (255)
} CertificateType;

struct {
    select (certificate_type) {
        case RawPublicKey:
          /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
          opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

        case X509:
          opaque cert_data<1..2^24-1>;
    };
    Extension extensions<0..2^16-1>;
} CertificateEntry;

struct {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
```

当使用 Python 表示 Certificate 的 RFC 语法时，可以编写如下程序：

```python
class CertificateType(Enum):
    elem_t = Uint8

    X509 = Uint8(0)
    RawPublicKey = Uint8(2)

@meta.struct
class CertificateEntry(meta.StructMeta):
    cert_data: OpaqueUint24
    extensions: Extensions

CertificateEntrys = List(size_t=Uint24, elem_t=CertificateEntry)

@meta.struct
class Certificate(meta.StructMeta):
    certificate_request_context: OpaqueUint8
    certificate_list: CertificateEntrys
```

### CertificateVerify

CertificateVerify是用于发送证书上的签名数据的消息

```
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
```

当使用 Python 表示 CertificateVerify 的 RFC 语法时，可以编写如下程序：

```python
@meta.struct
class CertificateVerify(meta.StructMeta):
    algorithm: SignatureScheme
    signature: OpaqueUint16
```

### Finished

Finished是用于确认是否共享了相同的密钥的消息。

```c
struct {
    opaque verify_data[Hash.length];
} Finished;
```

当使用Python表示Finished的RFC语法时，可以编写如下程序：

```python
class Hash:
    length = None

OpaqueHash = Opaque(lambda self: Hash.length)

@meta.struct
class Finished(meta.StructMeta):
    verify_data: OpaqueHash
```