# TLS 1.3 Overview

The TLS protocol primarily consists of two parts:

- Handshake Protocol: Decides the version of TLS and type of encryption to be used and performs key sharing.
- Record Protocol: Encrypts communication using the shared key obtained from the handshake protocol.

The Handshake Protocol spans from ClientHello to Finished. After that, the Record Protocol begins, transmitting and receiving encrypted messages, ApplicationData.

The TLS 1.3 handshake is as follows, also known as a full handshake.

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

- `+` indicates extensions. For example, the ClientHello message contains the key_share extension.
- `*` indicates messages or extensions that are transmitted as needed.
- `{}` indicates encryption with handshake_traffic_secret.
- `[]` indicates encryption with application_traffic_secret_N. N is an incrementing value for each transmission of Application Data.

As shown in the diagram above, the handshake consists of three stages: "Key Exchange," "Server Parameters," and "Authentication."

### 1. Key Exchange (Key Exch)

Sends parameters for shared key creation using the Diffie-Hellman key exchange.

First, the client sends the ClientHello message, and the server responds with the ServerHello message. The ClientHello message includes a random number (ClientHello.random), a list of protocol versions, a list of combinations of shared key encryption and hash-based key derivation function HKDF, etc. On the other hand, the ServerHello message returns the chosen results from the list of protocols and algorithms that the client side supports.

### 2. Server Parameters (Server Params)

Sends parameters other than key exchange.
The messages include EncryptedExtensions and CertificateRequest.

EncryptedExtensions: Replies to the TLS extensions of the ClientHello.
CertificateRequest: Sent if communication is only with users authenticated by client certificates. For general web servers and others where client authentication is not required, this message is omitted.

### 3. Authentication (Auth)

Finally, the server (and client) certificates are transmitted to the communication partner.
The messages include Certificate, CertificateVerify, Finished.

- Certificate: The server sends its server certificate. The client sends the client certificate only when it has received the CertificateRequest message.
- CertificateVerify: Generates and sends a signature from the messages received so far. The contents of this message are used to verify the signature on the received certificate. If the verification is successful, it confirms that the certificate indeed belongs to the counterpart.
- Finished: Indicates the successful completion of key exchange and authentication processes.

Upon sending Finished, the handshake protocol is complete.
After the handshake protocol ends, the record protocol begins.
In the record protocol, data is encrypted using the shared key obtained from the key exchange and transmitted and received as ApplicationData messages.

