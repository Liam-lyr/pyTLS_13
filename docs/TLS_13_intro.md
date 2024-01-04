# TLS 1.3 概述

> 参考：[RFC 5246 doc](https://datatracker.ietf.org/doc/html/rfc5246)，[RFC 8446 doc](https://datatracker.ietf.org/doc/html/rfc8446)

为了更好地在后续介绍 TLS 1.3，上一节详细介绍了 TLS 1.2 中内容，本节将从 TLS 1.2 与 TLS 1.3 的区别出发，对 TLS 1.3 进行概述。



## 差异概述

RFC 8446 中对 TLS 1.3 与 TLS 1.2 的差异进行了详细的描述，[见此](https://datatracker.ietf.org/doc/html/rfc8446#section-1.2)，本节中将对其进行概述。差异主要在于

- 引入了新的密钥协商机制 PSK。
- 平均数据传输在 1-RTT，并支持有副作用的 0-RTT 数据传输，在建立连接时节省了往返时间。
- 废弃了 3DES、RC4、AES-CBC 等加密组件，废弃了 SHA1、MD5 等哈希算法。
- ServerHello 之后的所有握手消息采取了加密操作，可见明文大大减少。
- 不再允许对加密报文进行压缩、不再允许双方发起重协商。
- DSA 证书不再允许在 TLS 1.3 中使用。

故，相比于 TLS 1.2，TLS 1.3 的优势可概括成两方面：更快的访问速度、更强的安全性。


### 更快的访问速度

TLS 1.3 握手流程：

```
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

```

TLS 1.2 握手流程：

```
Client                                               Server

ClientHello                 -------->
                                                ServerHello
                                               Certificate*
                                         ServerKeyExchange*
                                        CertificateRequest*
                            <--------       ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished                    -------->
                                         [ChangeCipherSpec]
                            <--------              Finished
Application Data            <------->      Application Data
```

可见，使用 TLS 1.2 需要 2-RTT 才能完成握手，TLS 1.3中，Hello 和公钥交换这两个消息合并成了一个消息，故只需要 1-RTT。

具体来说，客户端在发送的 “Client Hello” 消息中，不仅包含了它支持的椭圆曲线列表，还附带了相应椭圆曲线的公钥信息。当服务端接收到这些信息后，它选择一个合适的椭圆曲线和相关参数，同时在回应消息中附上服务端的公钥。通过这一个 RTT，双方就拥有了生成会话密钥所需的所有必要信息，使客户端能够计算出会话密钥并开始应用数据的加密传输。

实际使用中，访问一个移动端网站，使用 TLS 1.3 协议可能会减少将近 100ms 的时间。


### 更强的安全性

TLS 1.2 高度可配置，但支持的一些加密算法后续被证明不安全。TLS 1.3 剔除了这部分算法，算法及漏洞如下：

- RSA 密钥传输：缺乏前向安全性。
- CBC 模式密码：易受 BEAST 和 Lucky 13 攻击。
- RC4 流密码：在 HTTPS 中被认为不安全。
- SHA-1 哈希函数：已被建议用更安全的 SHA-2 替代。
- 任意 Diffie-Hellman 组：存在 CVE-2016-0701 漏洞。
- 输出密码：易受 FREAK 和 LogJam 攻击。
  

在密钥交换算法方面，TLS 1.3 废除了不支持前向安全性的 RSA 和 DH 算法，只支持 ECDHE 算法。至于对称加密和签名算法，TLS 1.3 只支持目前认为最安全的几种密码套件。例如，在 OpenSSL 中，TLS 1.3 仅支持以下 5 种密码套件：

- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_AES_128_GCM_SHA256
- TLS_AES_128_CCM_8_SHA256
- TLS_AES_128_CCM_SHA256

选择支持较少密码套件的原因是，TLS 1.2 由于支持许多过时且不安全的密码套件，容易受到中间人的降级攻击。在这种攻击中，攻击者可以伪造客户端的 “Client Hello” 消息，替换为不安全的密码套件，迫使服务器使用这些不安全的套件进行 HTTPS 连接，从而使加密通信易于破解。




## 具体变化概述

TLS 1.3 的改动 值得关注的重大改进有：

- 1-RTT 握手支持
- 0-RTT 握手支持
- 改为使用 HKDF 做密钥拓展
- 彻底禁止 RC4
- 彻底禁止压缩
- 彻底禁止 aead 以外的其他算法
- 去除 aead 的显式 IV
- 去除 了AEAD 的 AD 中的长度字段
- 去除 ChangeCipherSpec
- 去除重协商，即去除密码套件变更协议（故 record layer 之上只有 3 个协议）
- 去除静态 RSA 和 DH 密钥协商


### Record Layer 的密码学保护改动

由于 TLS 1.3 仅保留了 AEAD 算法，MAC key 已不再必要。AEAD 的具体参数有所调整，且 KDF 现已标准化为 HKDF，主要有两种：`tls_kdf_sha256` 和 `tls_kdf_sha384`。

可参考前一节。


### Handshake Protocol 的改动

TLS 1.3 把 TLS 1.2 的 session ticket 机制的优势内置化，改称为 PSK（Pre-Shared Key）。

综合考虑了 session resuming ，session ticket后， TLS 1.3 提出了3种handshake模式：

- **EC(DHE)**
- **PSK-only**：用统一的模型来处理 ession resuming 和 rfc4279 中的 PSK。
- **PSK with (EC)DHE**：前两者合体。


#### 1-RTT 握手

TLS 1.3 通过在首个 RTT 中直接发送 KeyExchange 的公钥，降低了握手所需的 RTT 数。若服务器发现客户端提供的算法不正确，则通过 HelloRetryRequest 消息指示客户端进行更正。这大大简化了握手过程。

由于 TLS 1.3 去除了各类自定义 DH 群、ECDH 自定义曲线、RSA 协商，密钥协商的算法只有少数几个，而且实际应用大多数使用 `ECDH P-256`，故可使客户端缓存服务器上一次用的是啥协商算法，把 KeyExchange 直接并入第一个 RTT，直接就用缓存的这个算法发送 KeyExchange 的公钥，若服务器发现客户端发上来的算法无法支持，那么再告知正确的，让客户端重试。

当需要通过 HelloRetryRequest 来进行更正时，握手流程如下：

```
Client                                               Server

ClientHello
+ key_share             -------->
                                          HelloRetryRequest
                        <--------               + key_share
ClientHello
+ key_share             -------->
                                                ServerHello
                                                + key_share
                                      {EncryptedExtensions}
                                      {CertificateRequest*}
                                             {Certificate*}
                                       {CertificateVerify*}
                                                 {Finished}
                        <--------       [Application Data*]
{Certificate*}
{CertificateVerify*}
{Finished}              -------->
[Application Data]      <------->        [Application Data]

```


#### 有副作用的 0-RTT 握手

若客户端和服务端共享一个 PSK（从外部获得或通过一个以前的握手获得）时，TLS 1.3 允许客户端在第一个发送出去的消息中携带数据（"early data"）。客户端使用这个 PSK 来认证服务端并加密 `early data`。

如下，0-RTT 数据在第一个发送的消息中被加入到 1-RTT 握手过程中。握手的其余消息与带 PSK 会话恢复的 1-RTT 握手消息相同。

```
Client                                               Server

ClientHello
+ early_data
+ key_share*
+ psk_key_exchange_modes
+ pre_shared_key
(Application Data*)     -------->
                                                ServerHello
                                           + pre_shared_key
                                               + key_share*
                                      {EncryptedExtensions}
                                              + early_data*
                                                 {Finished}
                        <--------       [Application Data*]
(EndOfEarlyData)
{Finished}              -------->
[Application Data]      <------->        [Application Data]
```

这个0-rtt优化是有副作用的：

1. RTT发送的应用数据没有前向安全性。它使用的是被提供的 PSK 中导出的密钥进行加密的。
2. 跨连接可以重放 0-RTT 里的应用数据（任何服务器端无共享状态的协议，都无法做到跨连接防重放）.


#### Resumption 和 PSK

虽然 TLS PSK 能够在带外建立，预共享密钥也能在一个之前的连接中建立然后重用（会话恢复）。一旦一次握手完成，server 就能给 client 发送一个与一个独特密钥对应的 PSK 密钥，这个密钥来自初次握手。然后 client 能够使用这个 PSK 密钥在将来的握手中协商相关 PSK 的使用。如果 server 接受它，新连接的安全上下文在密码学上就与初始连接关联在一起，从初次握手中得到的密钥就会用于装载密码状态来替代完整的握手。在 TLS 1.2 以及更低的版本中，这个功能由 "session IDs" 和 "session tickets" [RFC5077]来提供

在 TLS 1.3 中，session resumption/session ticket 生成的密钥和 rfc4279 中的 PSK 在一个统一的 handshake PSK 模式下处理。

PSK 可以与 (EC)DHE 密钥交换算法一同使用以便使共享密钥具备前向安全，或者 PSK 可以被单独使用，这样是以丢失了应用数据的前向安全为代价。

此时，握手流程如下。当 server 通过一个 PSK 进行认证时，它不会发送一个 Certificate 或一个 CertificateVerify 消息。当一个 client 通过 PSK 想恢复会话的时候，它也应当提供一个 "key_share" 给 server，以允许 server 拒绝恢复会话的时候降级到重新回答一个完整的握手流程中。Server 响应 "pre_shared_key" 扩展，使用 PSK 密钥协商建立连接，同时响应 "key_share" 扩展来进行 (EC)DHE 密钥建立，由此提供前向安全。

```
          Client                                               Server

   Initial Handshake:
          ClientHello
          + key_share               -------->
                                                          ServerHello
                                                          + key_share
                                                {EncryptedExtensions}
                                                {CertificateRequest*}
                                                       {Certificate*}
                                                 {CertificateVerify*}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Certificate*}
          {CertificateVerify*}
          {Finished}                -------->
                                    <--------      [NewSessionTicket]
          [Application Data]        <------->      [Application Data]


   Subsequent Handshake:
          ClientHello
          + key_share*
          + pre_shared_key          -------->
                                                          ServerHello
                                                     + pre_shared_key
                                                         + key_share*
                                                {EncryptedExtensions}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Finished}                -------->
          [Application Data]        <------->      [Application Data]

```


#### Key Schedule 过程的改动

TLS 1.3 提出了 ES 和 SS 两个概念，用以统一处理密钥协商的不同情况。在不同的握手模式下，ES 和 SS 的来源有所不同，不同模式下的取值如下表所示：

- **Ephemeral Secret (ES)**：专门为单次会话生成的密钥，每次会话都会生成新的密钥。凡是从 ES 得出的值，都是前向安全的（当然，在 PSK only 模式下，不是前向安全的）。
- **Static Secret (SS)**：多个会话中保持不变的密钥。在 TLS 1.3 中，这可能是一个预共享密钥（Pre-Shared Key, PSK），或者在使用0-RTT场景下的服务器的半静态ECDH密钥。

在各种 handshake 模式下：


| Key Exchange       | Static Secret (SS)                   | Ephemeral Secret (ES)                |
| ------------------ | ------------------------------------ | ------------------------------------ |
| (EC)DHE (完整握手) | Client ephemeral w/ server ephemeral | Client ephemeral w/ server ephemeral |
| (EC)DHE (w/ 0-RTT) | Client ephemeral w/ server static    | Client ephemeral w/ server ephemeral |
| PSK                | Pre-Shared Key                       | Pre-shared key                       |
| PSK + (EC)DHE      | Pre-Shared Key                       | Client ephemeral w/ server ephemeral |

如上表：

- **完整的 1-RTT 握手**：SS 和 ES 都是用的 ephemeral key ，这样是一定有前向安全性的。
- **使用 0-RTT 的握手**：使用客户端的 ephemeral key 和 服务器端的半静态 ECDH 公钥生成 SS，
- **纯 PSK**：这种场景完全没有前向安全性，应该避免。
- **PSK +　ECDHE**：SS 取 Pre-Shared Key，没有前向安全性，ES 用的 ephemeral key，有前向安全性。

可以看到，相比 TLS 1.2 的 session ticket，TLS 1.3 中 的 PSK + ECDHE，是结合了 ES 的，这样就有了前向安全性，相对更安全。

在一个TLS 连接中，究竟是用哪种握手模式，是由加密套件协商决定的。