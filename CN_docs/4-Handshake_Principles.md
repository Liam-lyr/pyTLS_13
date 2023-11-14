# TLS 1.3 握手协议原理

> **来源**
>
> 本节直接转载一篇 blog，本项目中有很多实现细节都参考了本文，故直接贴出。
> 
> https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md

握手协议用于协商连接的安全参数。握手消息被提供给 TLS 记录层，在记录层它们被封装到一个或多个 TLSPlaintext 或 TLSCiphertext 中，它们按照当前活动连接状态进行处理和传输。

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

协议消息必须按照一定顺序发送(顺序见下文)。如果对端发现收到的握手消息顺序不对，必须使用 “unexpected\_message” alert 消息来中止握手。


另外 IANA 分配了新的握手消息类型，见[第 11 章](https://tools.ietf.org/html/rfc8446#section-11)

## 一. Key Exchange Messages

密钥交换消息用于确保 Client 和 Server 的安全性和建立用于保护握手和数据的通信密钥的安全性。

### 1. Cryptographic Negotiation

在 TLS 协议中，密钥协商的过程中，Client 在 ClientHello 中可以提供以下 4 种 options。


-  Client 支持的加密套件列表。密码套件里面中能体现出 Client 支持的 AEAD 算法或者 HKDF 哈希对。
- “supported\_groups” 的扩展 和 "key\_share" 扩展。“supported\_groups” 这个扩展表明了 Client 支持的 (EC)DHE groups，"key\_share" 扩展表明了 Client 是否包含了一些或者全部的（EC）DHE共享。
- "signature\_algorithms" 签名算法和 "signature\_algorithms\_cert" 签名证书算法的扩展。"signature\_algorithms" 这个扩展展示了 Client 可以支持了签名算法有哪些。"signature\_algorithms\_cert" 这个扩展展示了具体证书的签名算法。
- "pre\_shared\_key" 预共享密钥和 "psk\_key\_exchange\_modes" 扩展。预共享密钥扩展包含了 Client 可以识别的对称密钥标识。"psk\_key\_exchange\_modes" 扩展表明了可能可以和 psk 一起使用的密钥交换模式。


如果 Server 不选择 PSK，那么上面 4 个 option 中的前 3 个是正交的， Server 独立的选择一个加密套件，独立的选择一个 (EC)DHE 组，独立的选择一个用于建立连接的密钥共享，独立的选择一个签名算法/证书对用于给 Client 验证 Server 。如果 Server 收到的 "supported\_groups" 中没有 Server 能支持的算法，那么就必须返回 "handshake\_failure" 或者 "insufficient\_security" 的 alert 消息。

如果 Server 选择了 PSK，它必须从 Client 的 "psk\_key\_exchange\_modes" 扩展消息中选择一个密钥建立模式。这个时候 PSK 和 (EC)DHE 是分开的。在 PSK 和 (EC)DHE 分开的基础上，即使，"supported\_groups" 中不存在 Server 和 Client 相同的算法，也不会终止握手。

如果 Server 选择了 (EC)DHE 组，并且 Client 在 ClientHello 中没有提供合适的 "key\_share" 扩展， Server 必须用 HelloRetryRequest 消息作为回应。


如果 Server 成功的选择了参数，也就不需要 HelloRetryRequest 消息了。 Server 将发送 ServerHello 消息，它包含以下几个参数：

- 如果正在使用 PSK， Server 将发送 "pre\_shared\_key" 扩展，里面包含了选择的密钥。
- 如果没有使用 PSK，选择的 (EC)DHE， Server 将会提供一个 "key\_share" 扩展。通常，如果 PSK 没有使用，就会使用 (EC)DHE 和基于证书的认证。
- 当通过证书进行认证的时候， Server 会发送 Certificate 和 CertificateVerify 消息。在 TLS 1.3 的官方规定中，PSK 和 证书通常被用到，但是不是一起使用，未来的文档可能会定义如何同时使用它们。

如果 Server 不能协商出可支持的参数集合，即在 Client 和 Server 各自支持的参数集合中没有重叠，那么 Server 必须发送 "handshake\_failure" 或者 "insufficient\_security" 消息来中止握手。

### 2. Client Hello

当一个 Client 第一次连接一个 Server 时，它需要在发送第一条 TLS 消息的时候，发送 ClientHello 消息。当 Server 发送 HelloRetryRequest 消息的时候，Client 收到了以后也需要回应一条 ClientHello 消息。在这种情况下，Client 必须发送相同的无修改的 ClientHello 消息，除非以下几种情况：

- 如果 HelloRetryRequest 消息中包含了 "key\_share" 扩展，则将共享列表用包含了单个来自表明的组中的 KeyShareEntry 代替。
- 如果存在 “early\_data” 扩展则将其移除。 “early\_data” 不允许出现在 HelloRetryRequest 之后。
- 如果 HelloRetryRequest 中包含了 cookie 扩展，则需要包含一个。
- 如果重新计算了 "obfuscated\_ticket\_age" 和绑定值，同时(可选地)删除了任何不兼容 Server 展示的密码族的 PSK，则更新 "pre\_shared\_key" 扩展。
- 选择性地增加，删除或更改 ”padding” 扩展[RFC 7685](https://tools.ietf.org/html/rfc7685)的长度。
- 可能被允许的一些其他的修改。例如未来指定的一些扩展定义和 HelloRetryRequest 。

由于 TLS 1.3 **严禁重协商**，如果 Server 已经完成了 TLS 1.3 的协商了，在未来某一时刻又收到了 ClientHello ，Server 不应该理会这条消息，必须立即断开连接，并发送 "unexpected\_message" alert 消息。

如果一个 Server 建立了一个 TLS 以前版本的 TLS 连接，并在重协商的时候收到了 TLS 1.3 的 ClientHello ，这个时候，Server 必须继续保持之前的版本，严禁协商 TLS 1.3 。

ClientHello 消息的结构是

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

关于结构体的一些说明：

- legacy\_version:    
	在 TLS 以前的版本里，这个字段被用来版本协商和表示 Client 所能支持的 TLS 最高版本号。经验表明，**很多 Server 并没有正确的实现版本协商**，导致了 "version intolerance" —— Sever 拒绝了一些本来可以支持的 ClientHello 消息，只因为这些消息的版本号高于 Server 能支持的版本号。在 TLS 1.3 中，Client 在 "supported\_versions" 扩展中表明了它的版本。并且 legacy\_version 字段必须设置成 0x0303，这是 TLS 1.2 的版本号。在 TLS 1.3 中的 ClientHello 消息中的 legacy\_version 都设置成 0x0303，supported\_versions 扩展设置成 0x0304。更加详细的信息见附录 D。

- random:    
	由一个安全随机数生成器产生的32字节随机数。额外信息见附录 C。
	
- legacy\_session\_id:    
	TLS 1.3 版本之前的版本支持会话恢复的特性。在 TLS 1.3 的这个版本中，这一特性已经和预共享密钥 PSK 合并了。如果 Client 有 TLS 1.3 版本之前的 Server 设置的缓存 Session ID，那么这个字段要填上这个 ID 值。在兼容模式下，这个值必须是非空的，所以一个 Client 要是不能提供 TLS 1.3 版本之前的 Session 的话，就必须生成一个新的 32 字节的值。这个值不要求是随机值，但必须是一个不可预测的值，防止实现上固定成了一个固定的值了。否则，这个字段必须被设置成一个长度为 0 的向量。（例如，一个0字节长度域）

- cipher\_suites:  
	这个列表是 Client 所支持对称加密选项的列表，特别是记录保护算法(包括密钥长度) 和 HKDF 一起使用的 hash 算法。以 Client 的偏好降序排列。如果列表包含的密码套件是 Server 不能识别的或者是不能支持的，或者是希望使用的，Server 必须忽略这些密码套件，照常处理剩下来的密码套件。如果 Client 尝试建立 PSK 密钥，则它应该至少包含一个与 PSK 相关的哈希加密套件。
	
- legacy\_compression\_methods:     
	TLS 1.3 之前的 TLS 版本支持压缩，在这个字段中发送支持的压缩方法列表。对于每个 ClientHello，该向量必须包含一个设置为 0 的一个字节，它对应着 TLS 之前版本中的 null 压缩方法。如果 TLS 1.3 中的 ClientHello 中这个字段包含有值，Server 必须立即发送 “illegal\_parameter” alert 消息中止握手。注意，TLS 1.3 Server 可能接收到 TLS 1.2 或者之前更老版本的 ClientHellos，其中包含了其他压缩方法。如果正在协商这些之前的版本，那么必须遵循 TLS 之前版本的规定。
	
- extensions:      
	Client 通过在扩展字段中发送数据，向 Server 请求扩展功能。“Extension” 遵循格式定义。在 TLS 1.3 中，使用确定的扩展项是强制的。因为功能被移动到了扩展中以保持和之前 TLS 版本的 ClientHello 消息的兼容性。Server 必须忽略不能识别的 extensions。
	
所有版本的 TLS 都允许可选的带上 compression\_methods 这个扩展字段。TLS 1.3 ClientHello 消息通常包含扩展消息(至少包含 “supported\_versions”，否则这条消息会被解读成 TLS 1.2 的 ClientHello 消息)然而，TLS 1.3 Server 也有可能收到之前 TLS 版本发来的不带扩展字段的 ClientHello 消息。扩展是否存在，可以通过检测 ClientHello 结尾的 compression\_methods 字段内是否有字节来确定。请注意，这种检测可选数据的方法与具有可变长度字段的普通 TLS 方法不同，但是在扩展被定义之前，这种方法可以用来做兼容。TLS 1.3 Server 需要首先执行此项检查，并且仅当存在 “supported\_versions” 扩展时才尝试协商 TLS 1.3。如果协商的是 TLS 1.3 之前的版本，Server 必须做 2 项检查：legacy\_compression\_methods 字段后面是否还有数据；有效的 extensions block 后没有数据跟随。如果上面这 2 项检查都不通过，需要立即发送 "decode\_error" alert 消息中止握手。
	
	
如果 Client 通过扩展请求额外功能，但是这个功能 Server 并不提供，则 Client 可以中止握手。

发送 ClientHello 消息后，Client 等待 ServerHello 或者 HelloRetryRequest 消息。如果 early data 在使用中，Client 在等待下一条握手消息期间，可以先发送 early Application Data。

### 3. Server Hello

如果 Server 和 Client 可以在 ClientHello 消息中协商出一套双方都可以接受的握手参数的话，那么 Server 会发送 Server Hello 消息回应 ClientHello 消息。

消息的结构体是：

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

- legacy\_version:  
	在 TLS 1.3 之前的版本，这个字段被用来版本协商和标识建立连接时候双方选择的版本号。不幸的是，一些中间件在给这个字段赋予新值的时候可能会失败。在 TLS 1.3 中，Server 用 "supported\_versions" 扩展字段来标识它支持的版本，legacy\_version 字段必须设置为 0x0303(这个值代表的 TLS 1.2)。（有关向后兼容性的详细信息，请参阅附录D.）
	
- random:  
	由安全随机数生成器生成的随机 32 字节。如果协商的是 TLS 1.1 或者 TLS 1.2 ，那么最后 8 字节必须被重写，其余的 24 字节必须是随机的。这个结构由 Server 生成并且必须独立于 ClientHello.random。

- legacy\_session\_id\_echo:  
	Client 的 legacy\_session\_id 字段的内容。请注意，即使 Server 决定不再恢复 TLS 1.3 之前的会话，Client 的 legacy\_session\_id 字段缓存的是 TLS 1.3  之前的值，这个时候 legacy\_session\_id\_echo 字段也会被 echoed。Client 收到的 legacy\_session\_id\_echo 值和它在 ClientHello 中发送的值不匹配的时候，必须立即用 "illegal\_parameter" alert 消息中止握手。
	
- cipher\_suite:  
	Server 从 ClientHello 中的 cipher\_suites 列表中选择的一个加密套件。Client 如果接收到并没有提供的密码套件，此时应该立即用 "illegal\_parameter" alert 消息中止握手。
	
	
- legacy\_compression\_method:  
	必须有 0 值的单一字节。
	
- extensions:  
	扩展列表。ServerHello 中必须仅仅只能包括建立加密上下文和协商协议版本所需的扩展。**所有 TLS 1.3 的 ServerHello 消息必须包含 "supported\_versions" 扩展**。当前的 ServerHello 消息还另外包含 "pre\_shared\_key" 扩展或者 "key\_share" 扩展，或者两个扩展都有(当使用 PSK 和 (EC)DHE 建立连接的时候)。其他的扩展会在 EncryptedExtensions 消息中分别发送。
	
出于向后兼容中间件的原因，HelloRetryRequest 消息和 ServerHello 消息采用相同的结构体，但需要随机设置 HelloRetryRequest 的 SHA-256 特定值：

```c
     CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
     C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
```
	
当收到 server\_hello 消息以后，实现必须首先检查这个随机值是不是和上面这个值匹配。如果和上面这个值是一致的，再继续处理。


TLS 1.3 具有降级保护机制，这种机制是通过嵌入在 Server 的随机值实现的。TLS 1.3 Server 协商 TLS 1.2 或者更老的版本，为了响应 ClientHello ，ServerHello 消息中必须在最后 8 个字节中填入特定的随机值。

如果协商的 TLS 1.2 ，TLS 1.3 Server 必须把 ServerHello 中的 Random 字段的最后 8 字节设置为：

```c
44 4F 57 4E 47 52 44 01
D  O  W  N  G  R  D
```

如果协商的 TLS 1.1 或者更老的版本，TLS 1.3 Server 和 TLS 1.2 Server 必须把 ServerHello 中的 Random 字段的最后 8 字节的值改为：

```c
44 4F 57 4E 47 52 44 00
D  O  W  N  G  R  D
```
	
TLS 1.3 Client 接收到 TLS 1.2 或者 TLS 更老的版本的 ServerHello 消息以后，必须要检查 ServerHello 中的 Random 字段的最后 8 字节不等于上面 2 个值才对。TLS 1.2 的 Client 也需要检查最后 8 个字节，如果协商的是 TLS 1.1 或者是更老的版本，那么 Random 值也不应该等于上面第二个值。如果都没有匹配上，那么 Client 必须用 "illegal\_parameter" alert 消息中止握手。这种机制提供了有限的保护措施，抵御降级攻击。通过 Finished exchange ，能超越保护机制的保护范围：因为在 TLS 1.2 或更低的版本上，ServerKeyExchange 消息包含 2 个随机值的签名。只要使用了临时的加密方式，攻击者就不可能在不被发现的情况下，修改随机值。所以对于静态的 RSA，是无法提供降级攻击的保护。

>请注意，上面这些改动在 [RFC5246](https://tools.ietf.org/html/rfc5246) 中说明的，实际上许多 TLS 1.2 的 Client 和 Server 都没有按照上面的规定来实践。

如果 Client 在重新协商 TLS 1.2 或者更老的版本的时候，协商过程中收到了 TLS 1.3 的 ServerHello，这个时候 Client 必须立即发送 “protocol\_version” alert 中止握手。请注意，**一旦 TLS 1.3 协商完成，就无法再重新协商了，因为 TLS 1.3 严禁重新协商**。


### 4. Hello Retry Request

如果在 Client 发来的 ClientHello 消息中能够找到一组可以相互支持的参数，但是 Client 又不能为接下来的握手提供足够的信息，这个时候 Server 就需要发送 HelloRetryRequest 消息来响应 ClientHello 消息。在上一节中，谈到 HelloRetryRequest 和 ServerHello 消息是有相同的数据结构，legacy\_version, legacy\_session\_id\_echo, cipher\_suite, legacy\_compression\_method 这些字段的含义也是一样的。为了讨论的方便，下文中，我们讨论 HelloRetryRequest 消息都当做不同的消息来对待。

Server 的扩展集中必须包含 "supported\_versions"。另外，它还需要包含最小的扩展集，能让 Client 生成正确的 ClientHello 对。相比 ServerHello 而言，HelloRetryRequest 只能包含任何在第一次 ClientHello 中出现过的扩展，除了可选的 "cookie" 以外。


Client 接收到 HelloRetryRequest 消息以后，必须要先校验 legacy\_version, legacy\_session\_id\_echo, cipher\_suite, legacy\_compression\_method 这四个参数。先从 “supported\_versions” 开始决定和 Server 建立连接的版本，然后再处理扩展。如果 HelloRetryRequest 不会导致 ClientHello 的任何更改，Client 必须用 “illegal\_parameter” alert 消息中止握手。如果 Client 在一个连接中收到了第 2 个 HelloRetryRequest 消息( ClientHello 本身就是响应 HelloRetryRequest 的)，那么必须用 “unexpected\_message” alert 消息中止握手。

否则，Client 必须处理 HelloRetryRequest 中所有的扩展，并且发送第二个更新的 ClientHello。在本规范中定义的 HelloRetryRequest 扩展名是：

- supported\_versions
- cookie
- key\_share

Client 在接收到自己并没有提供的密码套件的时候必须立即中止握手。Server 必须确保在接收到合法并且更新过的 ClientHello 时，它们在协商相同的密码套件(如果 Server 把选择密码套件作为协商的第一步，那么这一步会自动发送)。Client 收到 ServerHello 后必须检查 ServerHello 中提供的密码套件是否与 HelloRetryRequest 中的密码套件相同，否则将以 “illegal\_parameter” alert 消息中止握手。


此外，Client 在其更新的 ClientHello 中，Client 不能提供任何与所选密码套件以外的预共享密钥(与哈希相关联的)。这允许 Client 避免在第二个 ClientHello 中计算多个散列的部分哈希转录。

在 HelloRetryRequest 的 "support\_versions" 扩展中的 selected\_version 字段的值必须被保留在 ServerHello 中，如果这个值变了，Client 必须用 “illegal\_parameter” alert 消息中止握手。


## 二. Extensions

见 `/CN_docs/5-Extensions.md`。



## 三. Server Parameters


Server 接下来的 2 条消息，EncryptedExtensions 和 CertificateRequest 消息，包含来自 Server 的消息，这个 Server 确定了握手的其余部分。这些消息是加密的，通过从 server\_handshake\_traffic\_secret 中派生的密钥加密的。


### 1. Encrypted Extensions


在所有的握手中，Server 必须在 ServerHello 消息之后立即发送 EncryptedExtensions 消息。这是在从 server\_handshake\_traffic\_secret 派生的密钥下加密的第一条消息。

EncryptedExtensions 消息包含应该被保护的扩展。即，任何不需要建立加密上下文但不与各个证书相互关联的扩展。Client 必须检查 EncryptedExtensions 消息中是否存在任何禁止的扩展，如果有发现禁止的扩展，必须立即用 "illegal\_parameter" alert 消息中止握手。


```c
   Structure of this message:

      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
```

- extensions:   
	扩展列表。


### 2. Certificate Request

使用证书进行身份验证的 Server 可以选择性的向 Client 请求证书，这条请求消息(如果发送了)要跟在 EncryptedExtensions 消息后面。

消息的结构体：

```c
      struct {
          opaque certificate_request_context<0..2^8-1>;
          Extension extensions<2..2^16-1>;
      } CertificateRequest;
```


- certificate_request_context:  
	一个不透明的字符串，这个字符串用来标识证书请求，并在 Client 的 Certificate 消息中回显。certificate\_request\_context 必须在本次连接中必须是唯一的(从而防止 Client 的 CertificateVerify 重放攻击)。这个字段一般情况下都是 0 长度，除非用于 [[4.6.2]](https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md#2-post-handshake-authentication) 中描述的握手后身份验证交换。当请求握手后身份验证以后，Server 应该发送不可预测的上下文给 Client (例如，用随机数生成)，这样是为了防止攻击者破解。攻击者可以预先计算有效的 CertificateVerify 消息，从而获取临时的 Client 私钥的权限。


- extensions:  
	一组描述正在请求的证书需要的参数扩展集。"signature\_algorithms" 扩展必须是特定的，如果其他的扩展被这个消息所定义，那么其他扩展也可能可选的被包含进来。Client 必须忽略不能识别的扩展。


在 TLS 1.3 之前的版本中，CertificateRequest 消息携带了签名算法列表和 Server 可接受的证书授权列表。在 TLS 1.3 中，签名算法列表可以通过 "signature\_algorithms" 和可选的 "signature_algorithms_cert" 扩展来表示。而后者证书授权列表可以通过发送 "certificate\_authorities" 扩展来表示。


通过 PSK 进行验证的 Server 不能在主握手中发送 CertificateRequest 消息，不过它们可能可以在握手后身份验证中发送 CertificateRequest 消息，前提是 Client 已经发送了 "post\_handshake\_auth" 扩展名。




## 四. Authentication Messages

正如我们在 [section-2](https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3.md#%E4%BA%94tls-13-%E5%8D%8F%E8%AE%AE%E6%A6%82%E8%A7%88) 中讨论的，TLS 使用一组通用的消息用于身份验证，密钥确认和握手的正确性：Certificate, CertificateVerify 和 Finished。(PSK binders 也以类似的方式进行密钥确认)。这三条消息总是作为握手消息的最后三条消息。Certificate 和 CertificateVerify 消息如下面描述的那样，只在某些情况才会发送。Finished 的消息总是作为认证块的一部分发送。这些消息使用从 sender\_handshake\_traffic\_secret 派生出来的密钥进行加密。

Authentication 消息的计算统一采用以下的输入方式：

- 要使用证书和签名密钥
- 握手上下文由哈希副本中的一段消息集组成
- Base key 用于计算 MAC 密钥

基于这些输入，消息包含：

- Certificate：  
  用于认证的证书和链中任何支持的证书。请注意，基于证书的 Client 身份验证在 PSK 握手流中不可用(包括 0-RTT)

- CertificateVerify:   
  根据 Transcript-Hash(Handshake Context, Certificate) 的值得出的签名

- Finished:   
  根据 Transcript-Hash(Handshake Context, Certificate, CertificateVerify) 的值得出的 MAC 。使用从 Base key 派生出来的 MAC key 计算的 MAC 值。

对于每个场景，下表定义了握手上下文和 MAC Base Key    

```c
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


### 1. The Transcript Hash

TLS 中的许多加密计算都使用了哈希副本。这个值是通过级联每个包含的握手消息的方式进来哈希计算的，它包含握手消息头部携带的握手消息类型和长度字段，但是不包括记录层的头部。例如：

```c
Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
```

作为此一般规则的例外，当 Server 用一条 HelloRetryRequest 消息来响应一条 ClientHello 消息时，ClientHello1 的值替换为包含 Hash(ClientHello1）的握手类型为 "message\_hash" 的特殊合成握手消息。例如：

```c
  Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
      Hash(message_hash ||        /* Handshake type */
           00 00 Hash.length  ||  /* Handshake message length (bytes) */
           Hash(ClientHello1) ||  /* Hash of ClientHello1 */
           HelloRetryRequest  || ... || Mn)
```

设计这种结构的原因是允许 Server 通过在 cookie 中仅存储 ClientHello1 的哈希值来执行无状态 HelloRetryRequest，而不是要求它导出整个中间哈希状态。

具体而言，哈希副本始终取自于下列握手消息序列，从第一个 ClientHello 开始，仅包括已发送的消息：ClientHello, HelloRetryRequest, ClientHello, ServerHello, EncryptedExtensions, server CertificateRequest, server Certificate, server CertificateVerify, server Finished, EndOfEarlyData, client Certificate, client CertificateVerify, client Finished。

通常上，实现方可以下面的方法来实现哈希副本：根据协商的哈希来维持一个动态的哈希副本。请注意，随后的握手后认证不会相互包含，只是通过主握手结束的消息。


### 2. Certificate

此消息将端点的证书链发给对端。

每当约定的密钥交换方法是用证书进行认证(这包括本文档中除了 PSK 以外定义的所有密钥交换方法)的时候，Server 就必须发送 Certificate 消息。

当且仅当 Server 通过发送 CertificateRequest 消息请求 Client 认证时，Client 必须发送 Certificate 消息。


如果 Server 请求 Client 认证但没有合适的证书可用，则 Client 必须发送不包含证书的证书消息(例如，具有长度为 0 的 "certificate\_list" 字段)。Finished 消息必须发送，无论 Certificate 消息是否为空。

Certificate 消息的结构体是：


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

- certificate\_request\_context:  
	如果此消息是响应 CertificateRequest 消息的，则该消息中的 certificate\_request\_context 的值不为 0。否则(在 Server 认证的情况下)，该字段应为零长度。


- certificate\_list:  
	这是一个 CertificateEntry 结构的序列(链)，每个结构包含单个证书和一组扩展。

- extensions:  
	CertificateEntry 的一组扩展值。"Extension" 的格式在 [[Section 4.2]](https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md#%E4%BA%8C-extensions) 中定义了。有效的扩展包括 OCSP 状态扩展 [[RFC6066]](https://tools.ietf.org/html/rfc6066) 和 SignedCertificateTimestamp [[RFC6962]](https://tools.ietf.org/html/rfc6962) 扩展。未来可以为此消息定义一些新的扩展。Server 的 Certificate 消息中的扩展必须对应于 ClientHello 消息中的扩展。Client 的 Certificate 消息中的扩展必须对应于 Server 的 CertificateRequest 消息中的扩展。如果一个扩展适应用于整个链，它应该被包括在第一个 CertificateEntry 中。
	

如果没有在 EncryptedExtensions 中协商相应的证书类型扩展名 ("server\_certificate\_type" 或 "client\_certificate\_type")，或者协商了 X.509 证书类型，则每个 CertificateEntry 都要包含 DER 编码的 X.509 证书。发件者的证书必须位于列表中的第一个 CertificateEntry 中。之后的每个证书都应该直接证明其前面的证书。由于证书验证要求信任锚独立分发，因此可以从链中省略指定信任锚的证书(前提是已知支持的对等方拥有可省略的证书)。
	
注意：TLS 1.3 之前的版本，"certificate\_list" 排序需要每个证书要证明紧接在其前面的证书，然而，一些实现允许一些灵活性。Server 有时为了过渡的目的而发送当前和已弃用的中间体，而其他的配置不正确，但这些情况仍然可以正确地验证。为了最大程度的兼容性，所有实现应该准备处理可能是无关紧要的证书和 TLS 版本的任意排序，但最终实体证书(排序的顺序)必须是第一个。

如果协商了 RawPublicKey 证书类型，则 certificate\_list 必须包含不超过一个CertificateEntry，CertificateEntry 中包含定义在 [[RFC7250], Section 3](https://tools.ietf.org/html/rfc7250#section-3) 中的 ASN1\_subjectPublicKeyInfo 值。
	

OpenPGP 证书类型禁止在 TLS 1.3 中使用。

Server 的 certificate\_list 必须始终是非空的。如果 Client 没有适当的证书要发送以响应 Server 的身份验证请求，则会发送空的 certificate\_list。

#### (1) OCSP Status and SCT Extensions

[[RFC6066]](https://tools.ietf.org/html/rfc6066) 和 [[RFC6961]](https://tools.ietf.org/html/rfc6961) 提供了协商 Server 向 Client 发送 OCSP 响应的扩展。 在 TLS 1.2 及以下版本中，Server 回复空的扩展名以表示对此扩展的协商，并且在 CertificateStatus 消息中携带 OCSP 信息。在 TLS 1.3 中，Server 的 OCSP 信息在包含相关证书的 CertificateEntry 中的扩展中。特别的，来自 Server 的 "status\_request" 扩展的主体必须是分别在 [[RFC6066]](https://tools.ietf.org/html/rfc6066) 和 [[RFC6960]](https://tools.ietf.org/html/rfc6960) 中定义的 CertificateStatus 结构。


注意：status\_request\_v2 扩展 [[RFC6961]](https://tools.ietf.org/html/rfc6961) 已经废弃了，TLS 1.3 不能根据它是否存在或者根据它的信息来出来 ClientHello 消息。特别是，禁止在 EncryptedExtensions, CertificateRequest 和 Certificate 消息中发送 status\_request\_v2 扩展。TLS 1.3 的 Server 必须要能够处理包含它的 ClientHello 消息，因为这条消息可能是由希望在早期协议版本中使用它的 Client 发送的。


Server 可以通过在其 CertificateRequest 消息中发送空的 "status\_request" 扩展来请求 Client 使用其证书来做 OCSP 的响应。如果 Client 选择性的发送 OCSP 响应，则其 "status\_request" 扩展的主体必须是在 [[RFC6966]](https://tools.ietf.org/html/rfc6966) 中定义的 CertificateStatus 结构。


类似地，[[RFC6962]](https://tools.ietf.org/html/rfc6962) 为 Server 提供了一种机制，用在 TLS 1.2 及更低版本中的，可在 ServerHello 中发送签名证书时间戳 (SCT) 的扩展。 在 TLS 1.3 中，Server 的 SCT 信息在 CertificateEntry 的扩展中。


#### (2) Server Certificate Selection

以下规则适用于 Server 发送的证书:

- 证书类型必须是 X.509v3 [[RFC5280]](https://tools.ietf.org/html/rfc5280)，除非另有明确协商（例如，[[RFC5081]](https://tools.ietf.org/html/rfc5081)）

- Server 的终端实体证书的公钥（和相关限制）必须与 Client的 "signature\_algorithms" 扩展(目前为RSA，ECDSA 或 EdDSA)中的所选认证算法兼容。

- 证书必须允许密钥用于签名（即，如果存在密钥用法扩展，则必须设置 digitalSignature 位），并在 Client 的"signature\_algorithms"/"signature\_algorithms\_cert" 扩展中指示签名方案。


- "server\_name" [[RFC6066]](https://tools.ietf.org/html/rfc6066) 和 "certificate\_authorities" 扩展用于指导证书选择。由于 Server 可能需要存在 "server\_name" 扩展名，因此 Client 应该在适用时发送此扩展名。

如果 Server 能够提供证书链，Server 所有的证书都必须由 Client 提供的签名算法签名。自签名的证书或预期为信任锚的证书不会作为链的一部分进行验证，因此可以使用任何算法进行签名。


如果 Server 不能产生只通过所指示的支持的算法签名的证书链，则它应当通过向 Client 发送其选择的证书链来继续握手，该证书链可能会包括 Client 不知道能否支持的算法。这个回退链可以只在 Client 允许的情况下才可以使用已弃用的 SHA-1 哈希算法，其他情况都必须禁止使用 SHA-1 哈希算法。


如果 Client 无法使用提供的证书构造可接受的证书链，那么必须中止握手。中止握手并发送证书相关的 alert 消息(默认的，发送 "unsupported\_certificate" alert 消息)


如果 Server 有多张证书，它会根据上述标准(除了其他标准以外，如传输层端点，本地配置和首选项)选择其中的一个证书。



#### (3) Client Certificate Selection

以下的规则适用于 Client 发送的证书:

- 证书类型必须是 X.509v3 [[RFC5280]](https://tools.ietf.org/html/rfc5280)，除非另有明确协商（例如，[[RFC5081]](https://tools.ietf.org/html/rfc5081)）

- 如果 CertificateRequest 消息中 "certificate\_authorities" 扩展不为空，则证书链中的至少一个证书应该由所列出的 CA 之一发布的。

- 证书必须使用可接受的签名算法签名，如第 4.3.2 节所述。注意，这放宽了在 TLS 的先前版本中发现的证书签名算法的约束。

- 如果 CertificateRequest 消息包含非空的 "oid\_filters" 扩展，则终端实体证书必须匹配 Client 识别的扩展 OID，如第 4.2.5 节中所述。



#### (4) Receiving a Certificate Message


通常，详细的证书验证程序超出了 TLS 的范围(参见[[RFC5280]](https://tools.ietf.org/html/rfc5280))。 本节提供特定于 TLS 的要求。

如果 Server 提供空的证书消息，则 Client 必须使用 "decode\_error" alert 消息中止握手。

如果 Client 没有发送任何证书(即，它发送一个空的证书消息)，Server 可以自行决定是否在没有 Client 认证的情况下继续握手，或者使用 "certificate\_required" alert 消息中止握手。此外，如果证书链的某些方面是不可接受的(例如，它未由已知的可信 CA 签名)，则 Server 可以自行决定是继续握手(考虑 Client 还没有经过身份验证)还是中止握手。

任何端点接收任何需要使用任何签名算法使用 MD5 哈希验证的证书都必须使用 "bad\_certificate" alert 消息中止握手。不推荐使用 SHA-1，并且建议任何接收任何使用 SHA-1 哈希使用任何签名算法验证的证书的端点都会使用 "bad\_certificate" alert 消息中止握手。为清楚起见，这意味着端点可以接受这些算法用于自签名或信任锚的证书。


建议所有端点尽快转换为 SHA-256 或更好的算法，以保持与当前正在逐步淘汰 SHA-1 支持的实现的互操作性。


请注意，包含一个签名算法的密钥的证书可以使用不同的签名算法进行签名(例如，使用 ECDSA 密钥签名的 RSA 密钥)。


### 3. Certificate Verify

此消息用于提供端点拥有与其证书对应的私钥的明确证据。CertificateVerify 消息还为到此为止的握手提供完整性。Server 必须在通过证书进行身份验证时发送此消息。每当通过证书进行身份验证时(即，当证书消息非空时)，Client 必须发送此消息。发送时，此消息必须在 Certificate 消息之后立即出现，并且紧接在 Finished 消息之前。


这条消息的结构体是:

```c
      struct {
          SignatureScheme algorithm;
          opaque signature<0..2^16-1>;
      } CertificateVerify;
```

algorithm 字段指定使用的签名算法(有关此类型的定义，请参见第 4.2.3 节)。signature 字段是使用该算法的数字签名。签名中涵盖的内容是第 4.4.1 节中描述的哈希输出，即：

```c
      Transcript-Hash(Handshake Context, Certificate)
```

计算数字签名是级联计算的：

- 由八位字节32(0x20)组成的字符串重复 64 次
- 上下文字符串
- 用作分隔符的单个0字节
- 要签名的内容


设计这个结构目的是为了防止对先前版本的 TLS 的攻击，其中 ServerKeyExchange 格式意味着攻击者可以获得具有所选 32 字节前缀(ClientHello.random)的消息的签名。 最初的 64 字节填充将清除 Server 控制的 ServerHello.random 中的前缀。

Server 签名的上下文字符串是 "TLS 1.3，Server CertificateVerify"。Client 签名的上下文字符串是 "TLS 1.3，Client CertificateVerify"。它用于在不同的上下文中提供签名之间的分离，帮助抵御潜在的跨协议攻击。

例如，如果 hash副本 是 32 字节 01(这个长度对 SHA-256 有意义)，Server 的 CertificateVerify 的数字签名所涵盖的内容将是：

```c
      2020202020202020202020202020202020202020202020202020202020202020
      2020202020202020202020202020202020202020202020202020202020202020
      544c5320312e332c207365727665722043657274696669636174655665726966
      79
      00
      0101010101010101010101010101010101010101010101010101010101010101
```

在发送方，用于计算 CertificateVerify 消息的签名字段的过程作为输入:

- 数字签名算涵盖的内容

- 与上一条消息中发送的证书对应的私有签名密钥


如果由 Server 发送 CertificateVerify 消息，则签名算法必须是 Client "signature\_algorithms" 扩展中提供的，除非在没有不支持的算法的情况下不能生成有效的证书链(除非当前支持的算法都不能生成有效的证书链)。

如果由 Client 发送，则签名中使用的签名算法必须是 CertificateRequest 消息中 "signature\_algorithms" 扩展的 supported\_signature\_algorithms 字段中存在的签名算法之一。

另外，签名算法必须与发送者的终端实体证书中的密钥兼容。无论 RSASSA-PKCS1-v1\_5 算法是否出现在 "signature\_algorithms" 中，RSA 签名都必须使用 RSASSA-PSS 算法。SHA-1 算法禁止用于 CertificateVerify 消息的任何签名。

本规范中的所有 SHA-1 签名算法仅定义用于旧证书，并且对 CertificateVerify 签名无效。

CertificateVerify 消息的接收者必须验证签名字段。验证过程作为输入：

- 数字签名所涵盖的内容

- 在关联的证书消息中找到的最终实体证书中包含的公钥

- 在 CertificateVerify 消息的签名字段中收到的数字签名

如果验证失败，接收方必须通过 "decrypt\_error" 警报终止握手。


### 4. Finished


Finished 消息是认证块中的最后一条消息。它对提供握手和计算密钥的身份验证起了至关重要的作用。

Finished 消息的收件人必须验证内容是否正确，如果不正确，必须使用 "decrypt\_error" alert 消息终止连接。

一旦一方已发送其 Finished 消息并已收到并验证来自其对端的 Finished 消息，它就可以开始通过该连接发送和接收应用数据。有两种设置允许在接收对端的 Finished 之前发送数据:

1. 如 [Section 4.2.10](https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md#10-early-data-indication) 中所述，Client 可以发送 0-RTT 数据。
2. Server 可以在第一个 flight 之后就发送数据，但是因为握手还没有完成，所以不能保证对端的身份正确性，以及对端是否还在线。(ClientHello 可能重播)

用于计算 Finished 消息的密钥是使用 HKDF，它是从第 4.4 节中定义的 Base Key 计算而来的(参见第7.1节)。特别的:

```c
   finished_key =
       HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
```


这条消息的数据结构是:

```c
      struct {
          opaque verify_data[Hash.length];
      } Finished;
```

verify\_data 按照如下方法计算:

```c
      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))

      * Only included if present.
```


HMAC [[RFC2104]](https://tools.ietf.org/html/rfc2104) 使用哈希算法进行握手。如上所述，HMAC 输入通常是通过动态的哈希实现的，即，此时仅是握手的哈希。

在以前版本的 TLS 中，verify\_data 的长度总是 12 个八位字节。在 TLS 1.3 中，它是用来表示握手的哈希的 HMAC 输出的大小。

**注意：警报和任何其他非握手记录类型不是握手消息，并且不包含在哈希计算中**。

Finished 消息之后的任何记录都必须在适当的 client\_application\_traffic\_secret\_N 下加密，如第 7.2 节所述。特别是，这包括 Server 为了响应 Client 的 Certificate 消息和 CertificateVerify 消息而发送的任何 alert。




### 5. End of Early Data


```c
      struct {} EndOfEarlyData;
```

如果 Server 在 EncryptedExtensions 中发送了 "early\_data" 扩展，则 Client 必须在收到 Server 的 Finished 消息后发送 EndOfEarlyData 消息。 如果 Server 没有在 EncryptedExtensions中发送 "early\_data" 扩展，那么 Client 绝不能发送 EndOfEarlyData 消息。此消息表示已传输完了所有 0-RTT application\_data消息(如果有)，并且接下来的记录受到握手流量密钥的保护。Server 不能发送此消息，Client 如果收到了这条消息，那么必须使用 "unexpected\_message" alert 消息终止连接。这条消息使用从 client\_early\_traffic\_secret 中派生出来的密钥进行加密保护。


### 6. Post-Handshake Messages


TLS 还允许在主握手后发送其他的消息。这些消息使用握手内容类型，并使用适当的应用程序流量密钥进行加密。


#### (1) New Session Ticket Message

在 Server 接收到 Client 的 Finished 消息以后的任何时刻，它都可以发送 NewSessionTicket 消息。此消息在 ticket 值和从恢复主密钥派生出来的 PSK 之间创建了唯一的关联。


Client 在 ClientHello 消息中包含 "pre\_shared\_key" 扩展，并在扩展中包含 ticket ，那么 Client 就可能在未来的握手中使用 PSK。Server 可能在一个连接中发送多个 ticket，发送时机可能是一个接一个的立即发送，也可能是在某个特定事件以后发送。例如，Server 可能会在握手后身份验证之后发送新的 ticket，以封装其他 Client 身份验证状态。多个 ticket 对于 Client 来说，可用于各种目的，例如：

- 打开多个并行的 HTTP 连接

- 通过(例如) Happy Eyeballs [[RFC8305]](https://tools.ietf.org/html/rfc8305) 或相关的技术在接口和地址簇上进行连接竞争


任何 ticket 必须只能使用与用于建立原始连接的 KDF 哈希算法相同的密码套件来恢复会话。

Client 必须只有在新的 SNI 值对原始会话中提供的 Server 证书有效时才能恢复，并且只有在 SNI 值与原始会话中使用的 SNI 值匹配时才应恢复。后者是性能优化：通常，没有理由期望单个证书所涵盖的不同 Server 之间能够相互接受彼此的 ticket；因此，在这种情况下尝试恢复会话将会浪费一次性的 ticket。如果提供了这种指示(外部或通过任何其他方式)，则 Client 可能可以使用不同的 SNI 值进行恢复会话。


在恢复会话时，如果向调用的应用程序报告 SNI 值，则实现方必须使用在恢复 ClientHello 中发送的值而不是在先前会话中发送的值。请注意，如果 Server 的实现拒绝了不同 SNI 值的所有 PSK 标识，则这两个值总是相同。

注意：虽然恢复主密钥取决于 Client 的第二次 flight，但是不请求 Client 身份验证的 Server 可以独立计算转录哈希的剩余部分，然后在发送 Finished 消息后立即发送 NewSessionTicket 而不是等待 Client 的 Finished 消息。这可能适用于 Client 需要并行打开多个 TLS 连接并且可以从减少恢复握手的开销中受益的情况。

```c
      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
```


- ticket\_lifetime：  
	这个字段表示 ticket 的生存时间，这个时间是以 ticket 发布时间为网络字节顺序的 32 位无符号整数表示以秒为单位的时间。Server 禁止使用任何大于 604800秒(7 天)的值。值为零表示应立即丢弃 ticket。无论 ticket\_lifetime 如何，Client 都不得缓存超过 7 天的 ticket，并且可以根据本地策略提前删除 ticket。Server 可以将 ticket 视为有效的时间段短于 ticket\_lifetime 中所述的时间段。

- ticket\_age\_add:   
	安全的生成的随机 32 位值，用于模糊 Client 在 "pre\_shared\_key" 扩展中包含的 ticket 的时间。Client 的 ticket age 以模 2 ^ 32 的形式添加此值，以计算出 Client 要传输的值。Server 必须为它发出的每个 ticket 生成一个新值。

- ticket\_nonce:  
	每一个 ticket 的值，在本次连接中发出的所有的 ticket 中是唯一的。

- ticket:  
	这个值是被用作 PSK 标识的值。ticket 本身是一个不透明的标签。它可以是数据库查找键，也可以是自加密和自我验证的值。

- extensions：  
	ticket 的一组扩展值。扩展格式在 4.2 节中定义的。Client 必须忽略无法识别的扩展。
	
当前为 NewSessionTicket 定义的唯一扩展名是 "early\_data"，表示该 ticket 可用于发送 0-RTT 数据(第4.2.10节)。 它包含以下值：

- max\_early\_data\_size:    
	这个字段表示使用 ticket 时允许 Client 发送的最大 0-RTT 数据量(以字节为单位)。数据量仅计算应用数据有效载荷(即，明文但不填充或内部内容类型字节)。Server 如果接收的数据大小超过了 max\_early\_data\_size 字节的 0-RTT 数据，应该立即使用 "unexpected\_message" alert 消息终止连接。请注意，由于缺少加密材料而拒绝 early data 的 Server 将无法区分内容中的填充部分，因此 Client 不应该依赖于能够在 early data 记录中发送大量填充内容。


PSK 关联的 ticket 计算方法如下：

```c
       HKDF-Expand-Label(resumption_master_secret,
                        "resumption", ticket_nonce, Hash.length)
```

因为 ticket\_nonce 值对于每个 NewSessionTicket 消息都是不同的，所以每个 ticket 会派生出不同的 PSK。

请注意，原则上可以继续发布新 ticket，该 ticket 无限期地延长生命周期，这个生命周期是最初从初始非 PSK 握手中(最可能与对等证书相关联)派生得到的密钥材料的生命周期。
 

建议实现方对密钥材料这些加上总寿命时间的限制。这些限制应考虑到对等方证书的生命周期，干预撤销的可能性以及自从对等方在线 CertificateVerify 签名到当前时间的这段时间。


#### (2) Post-Handshake Authentication

当 Client 发送了 "post\_handshake\_auth" 扩展(参见第4.2.6节)时，Server 可以在握手完成后随时通过发送 CertificateRequest 消息来请求客户端身份验证。Client 必须使用适当的验证消息进行响应(参见第4.4节)。如果 Client 选择进行身份验证，则必须发送 Certificate，CertificateVerify，Finished 消息。如果 Client 拒绝身份验证，它必须发送一个 Certificate 证书消息，其中不包含证书，然后是 Finished 消息。响应 Server 的所有 Client 消息必须连续出现在线路上，中间不能有其他类型的消息。


在没有发送 "post\_handshake\_auth" 扩展的情况下接收 CertificateRequest 消息的 Client 必须发送 "unexpected\_message" alert 消息。


注意：由于 Client 身份验证可能涉及提示用户，因此 Server 必须做好一些延迟的准备，包括在发送 CertificateRequest 和接收响应之间接收任意数量的其他消息。此外，Client 如果连续接收到了多个 CertificateRequests 消息，Client 可能会以不同于它们的顺序响应它们(certificate\_request\_context 值允许服务器消除响应的歧义)



#### (3) Key and Initialization Vector Update

KeyUpdate 握手消息用于表示发送方正在更新其自己的发送加密密钥。任何对等方在发送 Finished 消息后都可以发送此消息。在接收 Finished 消息之前接收 KeyUpdate 消息的，实现方必须使用 "unexpected\_message" alert 消息终止连接。发送 KeyUpdate 消息后，如第 7.2 节所描述的计算方法，发送方应使用新一代的密钥发送其所有流量。收到 KeyUpdate 后，接收方必须更新其接收密钥。


```c
      enum {
          update_not_requested(0), update_requested(1), (255)
      } KeyUpdateRequest;

      struct {
          KeyUpdateRequest request_update;
      } KeyUpdate;
```

- request\_update:  
	这个字段表示 KeyUpdate 的收件人是否应使用自己的 KeyUpdate 进行响应。 如果实现接收到任何其他的值，则必须使用 "illegal\_parameter" alert 消息终止连接。
	

如果 request\_update 字段设置为 "update\_requested"，则接收方必须在发送其下一个应用数据记录之前发送自己的 KeyUpdate，其中 request\_update 设置为 "update\_not\_requested"。此机制允许任何一方强制更新整个连接，但会导致一个实现方接收多个 KeyUpdates，并且它还是静默的响应单个更新。请注意，实现方可能在发送 KeyUpdate (把 request\_update 设置为 "update\_requested") 与接收对等方的 KeyUpdate 之间接收任意数量的消息，因为这些消息可能早就已经在传输中了。但是，由于发送和接收密钥是从独立的流量密钥中导出的，因此保留接收流量密钥并不会影响到发送方更改密钥之前发送的数据的前向保密性。


如果实现方独立地发送它们自己的 KeyUpdates，其 request\_update 设置为 "update\_requested" 并且它们的消息都是传输中，结果是双方都会响应，双方都会更新密钥。


发送方和接收方都必须使用旧密钥加密其 KeyUpdate 消息。另外，在接受使用新密钥加密的任何消息之前，双方必须强制接收带有旧密钥的 KeyUpdate。如果不这样做，可能会引起消息截断攻击。