# TLS 1.3 Alerts

> 参考：[RFC 8446 - Sec 6 - Alerts](https://tools.ietf.org/html/rfc8446#section-6)
>
> 对应代码：`/src/protocal_alert.py`
>
> 本项目完整实现了这部分内容，但不算重点，故不在本节介绍，请读者自行阅读 RFC 8446。


RFC 8446 中用 C 结构体定义如下：

```c
enum { warning(1), fatal(2), (255) } AlertLevel;

enum {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    record_overflow(22),
    handshake_failure(40),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    inappropriate_fallback(86),
    user_canceled(90),
    missing_extension(109),
    unsupported_extension(110),
    unrecognized_name(112),
    bad_certificate_status_response(113),
    unknown_psk_identity(115),
    certificate_required(116),
    no_application_protocol(120),
    (255)
} AlertDescription;

struct {
    AlertLevel level;
    AlertDescription description;
} Alert;
```

本项目中，实现在 `/src/protocol_alert.py - AlertLevel`，`/src/protocol_alert.py - AlertDescription`，`/src/protocol_alert.py - Alert` 中。如下。

```python
class AlertLevel(Enum):
    elem_t = Uint8

    warning = Uint8(1)
    fatal = Uint8(2)

class AlertDescription(Enum):
    elem_t = Uint8

    close_notify = Uint8(0)
    unexpected_message = Uint8(10)
    bad_record_mac = Uint8(20)
    record_overflow = Uint8(22)
    handshake_failure = Uint8(40)
    bad_certificate = Uint8(42)
    unsupported_certificate = Uint8(43)
    certificate_revoked = Uint8(44)
    certificate_expired = Uint8(45)
    certificate_unknown = Uint8(46)
    illegal_parameter = Uint8(47)
    unknown_ca = Uint8(48)
    access_denied = Uint8(49)
    decode_error = Uint8(50)
    decrypt_error = Uint8(51)
    protocol_version = Uint8(70)
    insufficient_security = Uint8(71)
    internal_error = Uint8(80)
    inappropriate_fallback = Uint8(86)
    user_canceled = Uint8(90)
    missing_extension = Uint8(109)
    unsupported_extension = Uint8(110)
    unrecognized_name = Uint8(112)
    bad_certificate_status_response = Uint8(113)
    unknown_psk_identity = Uint8(115)
    certificate_required = Uint8(116)
    no_application_protocol = Uint8(120)

@meta.struct
class Alert(meta.StructMeta):
    level: AlertLevel
    description: AlertDescription
```