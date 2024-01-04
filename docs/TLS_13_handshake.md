# TLS 1.3 Handshake Protocol

> 参考：[RFC 8446 - Sec 4 - Handshake Protocol](https://tools.ietf.org/html/rfc8446#section-4)
>
> 对应代码：`/src/protocal_handshake.py`，`/src/protocol_hello.py`，`/src/protocol_extensions.py`，`/src/protocol_ext_*.py`，`/src/protocol_authentication.py`，`/src/protocol_ticket.py`。




## 数据结构概述
> 对应代码：`/src/protocal_handshake.py`

与握手相关的消息使用 `Handshake` 结构体。
握手协议有一个头部，其中存储了握手类型 `HandshakeType` 和消息长度 `length`。

```
[ HandshakeType | length ]
    |
    |
+---V----+--------------+
| header | message data |
+--------+--------------+
```

结合上一节（[Record Layer](TLS_13_record.md)），握手消息被提供给 TLS 记录层，在记录层它们被封装到一个或多个 `TLSPlaintext` 或 `TLSCiphertext` 中，它们按照当前活动连接状态进行处理和传输。将握手协议封装在 TLS 记录中时，16进制数据如下所示：

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

### Handshake

`Handshake` 结构体用于握手协议，协商连接的安全参数。RFC 8446 中用 C 结构体定义如下：

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
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* remaining bytes in message */
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

本项目中，实现在 `/src/protocal_handshake.py - Handshake`。如下。

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

关于 `Handshake`：

- **msg_type**：消息结构类型（2字节）
- **length**：消息结构的字节长度（3字节）
- **消息数据**：消息结构的数据




## Key Exchange Messages
> 参考：[RFC 8446 - Sec 4.1 - Key Exchange Messages](https://tools.ietf.org/html/rfc8446#section-4.1)
>
> 对应代码：`/src/protocal_hello.py`
>
> 本节将介绍 RFC 8446 - Sec 4.1 - Key Exchange Messages 中的内容，并给出本项目中的实现。本节将只介绍重要的 4.1.1 - Cryptographic Negotiation 和 4.1.2 - Client Hello 及 4.1.3 - Server Hello。本项目也有实现其余内容（4.1.4），但不算重点，故不在本节介绍，请读者自行阅读 RFC 8446。


### Cryptographic Negotiation

在 TLS 协议中，Client 在发送 ClientHello 消息期间，可以提供以下四种选项以便进行密钥协商：

- **支持的加密套件列表**：客户端支持的 AEAD 算法或 HKDF 哈希对。
- **"supported_groups" 和 "key_share" 扩展**："supported_groups" 扩展表明客户端支持的 (EC)DHE 群组，而 "key_share" 扩展则表示客户端是否包含了一些或全部的 (EC)DHE 共享。
- **"signature_algorithms" 和 "signature_algorithms_cert" 扩展**："signature_algorithms" 扩展展示了客户端支持的签名算法，而 "signature_algorithms_cert" 扩展则显示了特定于证书的签名算法。
- **"pre_shared_key" 和 "psk_key_exchange_modes" 扩展**：这些扩展包含了客户端可以识别的对称密钥标识和可能与 PSK 一起使用的密钥交换模式。

有几下几种情况：

若 Server 未选择 PSK，那么上述前三个选项是相互独立的。服务器将独立选择加密套件、(EC)DHE 群组、用于建立连接的密钥共享以及用于验证服务器的签名算法/证书对。如果服务器接收到的 "supported_groups" 中没有其支持的算法，那么它必须返回 "handshake_failure" 或 "insufficient_security" 的警告消息。

若服务器选择 PSK，它必须从客户端的 "psk_key_exchange_modes" 扩展中选择一个密钥建立模式。在这种情况下，PSK 和 (EC)DHE 是分开处理的（见[TLS 1.3 Introduction](./TLS_13_intro.md)一节中 “Key Schedule 过程的改动” 一章）。即使 "supported_groups" 中不存在客户端和服务器共同支持的算法，握手过程也不会终止。

如果服务器选择了 (EC)DHE 群组，而客户端在 ClientHello 中未提供合适的 "key_share" 扩展，那么服务器必须以 HelloRetryRequest 消息作为回应。

如果服务器成功选择了参数，则不需要 HelloRetryRequest 消息。此时，服务器将发送 ServerHello 消息，其中包含以下参数：

- **正在使用 PSK 时**：服务器会发送包含选定密钥的 "pre_shared_key" 扩展。
- **未使用 PSK 而选择 (EC)DHE 时**：服务器将提供一个 "key_share" 扩展。通常情况下，若未使用 PSK，则会采用 (EC)DHE 和基于证书的认证。
- **通过证书进行认证时**：服务器会发送 Certificate 和 CertificateVerify 消息。根据 TLS 1.3 的规定，虽然通常会使用 PSK 或证书，但不会同时使用它们。未来的文档可能会定义如何同时使用这两种方法。

如果服务器无法协商出双方都支持的参数集合，即客户端和服务器支持的参数集合中没有交集，那么服务器必须发送 "handshake_failure" 或 "insufficient_security" 消息来中止握手过程。


### Client Hello

RFC 8446 中用 C 结构体定义如下：

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

本项目中，实现在 `/src/protocal_hello.py - ClientHello`。如下。

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

关于 `ClientHello`：

- **legacy_version**：TLS 版本（2字节）。为了与 TLS1.2 之前的版本兼容，总是设置为 `0x0303`。
- **random**：由安全随机数生成器生成的 32 字节随机数。
- **legacy_session_id**：在 TLS 1.2 中，客户端使用此字段来恢复现有会话，但在 TLS 1.3 中，会话恢复已被禁止，因此填充随机的 32 字节值。
- **cipher_suite**：客户端支持的密码套件列表。
- **legacy_compression_methods**：压缩方法。总是设为 0 （参见 CRIME 攻击）。
- **extensions**：TLS 扩展列表。在 TLS1.3 中，总是包含 `supported_versions` 扩展，因此如果没有这个扩展，则可以确定是在 TLS 1.2 或更早版本中发送的 ClientHello。


另外，RFC 8446 - Sec 4.1.2 中提到几个关键点：

当一个 Client 第一次连接一个 Server 时，它需要在发送第一条 TLS 消息的时候，发送 ClientHello 消息。当 Server 发送 HelloRetryRequest 消息的时候，Client 收到了以后也需要回应一条 ClientHello 消息。在这种情况下，Client 必须发送相同的无修改的 ClientHello 消息，除非以下几种情况：

- 如果 HelloRetryRequest 消息中包含了 "key_share" 扩展，则将共享列表用包含了单个来自表明的组中的 KeyShareEntry 代替。
- 如果存在 “early_data” 扩展则将其移除。 “early_data” 不允许出现在 HelloRetryRequest 之后。
- 如果 HelloRetryRequest 中包含了 cookie 扩展，则需要包含一个。
- 如果重新计算了 "obfuscated_ticket_age" 和绑定值，同时(可选地)删除了任何不兼容 Server 展示的密码族的 PSK，则更新 "pre_shared_key" 扩展。
- 选择性地增加，删除或更改 ”padding” 扩展[RFC 7685](https://datatracker.ietf.org/doc/html/rfc7685)中的长度。
- 可能被允许的一些其他的修改。例如未来指定的一些扩展定义和 HelloRetryRequest 。

由于 TLS 1.3 严禁重协商，如果 Server 已经完成了 TLS 1.3 的协商了，在未来某一时刻又收到了 ClientHello ，Server 不应该理会这条消息，必须立即断开连接，并发送 "unexpected_message" alert 消息。

如果一个 Server 建立了一个 TLS 以前版本的 TLS 连接，并在重协商的时候收到了 TLS 1.3 的 ClientHello ，这个时候，Server 必须继续保持之前的版本，严禁协商 TLS 1.3 。


### Server Hello

RFC 8446 中用 C 结构体定义如下：

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

本项目中，实现在 `/src/protocal_hello.py - ServerHello`。如下。

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

关于 `ServerHello`：

- **legacy_version**：TLS 版本（2字节）。为了与 TLS 1.2 之前的版本兼容，总是设置为 `0x0303`。
- **random**：由安全随机数生成器生成的 32 字节随机数。
- **legacy_session_id_echo**：与客户端的 ClientHello.legacy_session_id 值相同。这是为了与 TLS1.2 以前的版本兼容。
- **cipher_suite**：服务器从 ClientHello.cipher_suites 中选择的密码套件。
- **legacy_compression_method**：压缩方法。总是设为 0 （由于 CRIME 攻击）。
- **extensions**：TLS 扩展列表。在 TLS1.3 中，总是包含 supported_versions 扩展。其他与密钥共享无关的扩展将在 EncryptedExtensions 消息中发送。


### Encrypted Retry Request

如果在 Client 发来的 ClientHello 消息中能够找到一组可以相互支持的参数，但是 Client 又不能为接下来的握手提供足够的信息，这个时候 Server 就需要发送 HelloRetryRequest 消息来响应 ClientHello 消息。

`HelloRetryRequest` 的结构与 `ServerHello` 相同。




## Extensions

> 参考：[RFC 8446 - Sec 4.2 - Extensions](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)
>
> 对应代码：`/src/protocol_extensions.py`，`/src/protocol_ext_*.py`，有多份。

本项目中实现了部分拓展：

1.  **supported_versions**：`/src/proto_ext_supportedversions.py`。RFC 8446 - Sec 4.2.1
2.  **signature_algorithms**：`/src/proto_ext_signature.py`。RFC 8446 - Sec 4.2.3
3.  **supported_groups**：`/src/proto_ext_supportedgroups.py`。RFC 8446 - Sec 4.2.7
4.  **key_share**：`/src/proto_ext_key_share.py`。RFC 8446 - Sec 4.2.8

并按照 [RFC 8446 - Sec 4.2 - Extensions](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2)，实现了编码查找表，位于 `/src/protocol_extensions.py - ExtensionType` 中。

由于篇幅，详见 [TLS 1.3 Extensions](./TLS_13_extensions.md)。


## Server Parameters

> 参考：[RFC 8446 - Sec 4.3 - Server Parameters](https://datatracker.ietf.org/doc/html/rfc8446#section-4.3)
>
> 对应代码：`/src/protocol_extensions.py`
> 
> 本节将介绍 RFC 8446 - Sec 4.3 - Server Parameters 中的内容，并给出本项目中的实现。本节将只介绍重要的 4.3.1 - Encrypted Extensions。**注意**，本项目未实现 4.3.2 - Certificate Request，故不在本节介绍，请读者自行阅读 RFC 8446。

Server 接下来的 2 条消息，EncryptedExtensions 和 CertificateRequest 消息确定了握手的其余部分。这些消息是加密的，通过从 `server_handshake_traffic_secret` 中派生的密钥加密的。

### Encrypted Extensions


在所有的握手中，Server 必须在 ServerHello 消息之后立即发送 EncryptedExtensions 消息。这是在从 server\_handshake\_traffic\_secret 派生的密钥下加密的第一条消息。

EncryptedExtensions 消息包含应该被保护的扩展。即，任何不需要建立加密上下文但不与各个证书相互关联的扩展。Client 必须检查 EncryptedExtensions 消息中是否存在任何禁止的扩展，如果有发现禁止的扩展，必须立即用 "illegal\_parameter" alert 消息中止握手。

RFC 8446 中用 C 结构体定义如下：

```c
Structure of this message:

    struct {
        Extension extensions<0..2^16-1>;
    } EncryptedExtensions;
```

本项目中，实现在 `/src/protocol_extensions.py - EncryptedExtensions`、`/src/protocol_extensions.py - Extension`。如下。

```python
@meta.struct
class Extension(meta.StructMeta):
    extension_type: ExtensionType
    length: Uint16 = lambda self: Uint16(len(bytes(self.extension_data)))
    extension_data: meta.Select('extension_type', cases={
        ExtensionType.supported_versions: SupportedVersions,
        ExtensionType.supported_groups: NamedGroupList,
        ExtensionType.key_share: KeyShareHello,
        ExtensionType.signature_algorithms: SignatureSchemeList,
        meta.Otherwise: OpaqueLength,
    })

@meta.struct
class EncryptedExtensions(meta.StructMeta):
    extensions: Extensions
```

由于本项目只实现了 4 种拓展（见 [Extensions](#extensions) 一节），故 `Extension` 结构体中的 `extension_data` 仅实现了这 4 种拓展，其他拓展则使用 `OpaqueLength` 占位。



## Authentication Messages

> 参考：[RFC 8446 - Sec 4.4 - Authentication Messages](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4)
>
> 对应代码：`/src/protocol_authentication.py`
>
> 本节将介绍 RFC 8446 - Sec 4.4 - Authentication Messages 中的内容，并给出本项目中的实现。本节将只重点介绍重要的 4.4.2 - Certificate 和 4.4.3 - CertificateVerify 和 4.4.4 - Finished。本项目也有实现其余内容（4.4.1 - The Transcript Hash），用于 `CertificationVerify` 结构体，但不算重点，故不在本节介绍，请读者自行阅读 RFC 8446。

Certificate 和 CertificateVerify 消息如下面描述的那样，只在某些情况才会发送。Finished 消息总是发送。这些消息使用从 `sender_handshake_traffic_secret` 派生出来的密钥进行加密。

Authentication 消息的计算统一采用以下的输入方式：

- 要使用证书和签名密钥
- 握手上下文由哈希副本中的一段消息集组成
- `Base key` 用于计算 MAC 密钥

基于这些输入，消息包含：

- **Certificate**：用于认证的证书和链中任何支持的证书。

- **CertificateVerify**：根据 `Transcript-Hash(Handshake Context, Certificate)` 得出的签名。

- **Finished**：根据 `Transcript-Hash(Handshake Context, Certificate, CertificateVerify)` 的值得出的 MAC 。使用从 Base key 派生出来的 MAC key 计算的 MAC 值。

对于每个场景，下表定义了握手上下文和 MAC Base Key：

```
+-----------+-------------------------+-----------------------------+
| Mode      | Handshake Context       | Base Key                    |
+-----------+-------------------------+-----------------------------+
| Server    | ClientHello ... later   | server_handshake_traffic_   |
|           | of EncryptedExtensions/ | secret                      |
|           | CertificateRequest      |                             |
|           |                         |                             |
| Client    | ClientHello ... later   | client_handshake_traffic_   |
|           | of server               | secret                      |
|           | Finished/EndOfEarlyData |                             |
|           |                         |                             |
| Post-     | ClientHello ... client  | client_application_traffic_ |
| Handshake | Finished +              | secret_N                    |
|           | CertificateRequest      |                             |
+-----------+-------------------------+-----------------------------+
```


### Certificate

Certificate 消息用于发送服务器证书。如果使用 PSK，可以省略此消息。当且仅当 Server 通过发送 CertificateRequest 消息请求 Client 认证时，Client 必须发送 Certificate 消息（如前所述，本项目没有实现这种情况，没有实现 `CertificationRequest`）。

RFC 8446 中用 C 结构体定义如下：

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

本项目中，实现在 `/src/protocol_authentication.py - Certificate`。如下。

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


`CertificateVerify` 是用于发送证书上的签名数据的消息。RFC 8446 中用 C 结构体定义如下：

```c
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
```

本项目中，实现在 `/src/protocol_authentication.py - CertificateVerify`。如下。

```python
@meta.struct
class CertificateVerify(meta.StructMeta):
    algorithm: SignatureScheme
    signature: OpaqueUint16
```


### Finished

RFC 8446 中用 C 结构体定义如下：

```c
struct {
    opaque verify_data[Hash.length];
} Finished;
```

本项目中，实现在 `/src/protocol_authentication.py - Finished`。如下。

```python
class Hash:
    length = None

OpaqueHash = Opaque(lambda self: Hash.length)

@meta.struct
class Finished(meta.StructMeta):
    verify_data: OpaqueHash
```



## End of Early Data 和 Post-Handshake Messages

> 参考：[RFC 8446 - Sec 4.5 - End of Early Data](https://datatracker.ietf.org/doc/html/rfc8446#section-4.5)，[RFC 8446 - Sec 4.6 - Post-Handshake Messages](https://datatracker.ietf.org/doc/html/rfc8446#section-4.6)
>
> 对应代码：`/src/protocol_ticket.py`
>
> 本项目也有实现这部分内容，但不算重点，故不在本节介绍，请读者自行阅读 RFC 8446。