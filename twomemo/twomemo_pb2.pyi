"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.message
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class OMEMOMessage(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    N_FIELD_NUMBER: builtins.int
    PN_FIELD_NUMBER: builtins.int
    DH_PUB_FIELD_NUMBER: builtins.int
    CIPHERTEXT_FIELD_NUMBER: builtins.int
    n: builtins.int
    pn: builtins.int
    dh_pub: builtins.bytes
    ciphertext: builtins.bytes
    def __init__(self,
        *,
        n: typing.Optional[builtins.int] = ...,
        pn: typing.Optional[builtins.int] = ...,
        dh_pub: typing.Optional[builtins.bytes] = ...,
        ciphertext: typing.Optional[builtins.bytes] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["ciphertext",b"ciphertext","dh_pub",b"dh_pub","n",b"n","pn",b"pn"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["ciphertext",b"ciphertext","dh_pub",b"dh_pub","n",b"n","pn",b"pn"]) -> None: ...
global___OMEMOMessage = OMEMOMessage

class OMEMOAuthenticatedMessage(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    MAC_FIELD_NUMBER: builtins.int
    MESSAGE_FIELD_NUMBER: builtins.int
    mac: builtins.bytes
    message: builtins.bytes
    """Byte-encoding of an OMEMOMessage"""

    def __init__(self,
        *,
        mac: typing.Optional[builtins.bytes] = ...,
        message: typing.Optional[builtins.bytes] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["mac",b"mac","message",b"message"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["mac",b"mac","message",b"message"]) -> None: ...
global___OMEMOAuthenticatedMessage = OMEMOAuthenticatedMessage

class OMEMOKeyExchange(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PK_ID_FIELD_NUMBER: builtins.int
    SPK_ID_FIELD_NUMBER: builtins.int
    IK_FIELD_NUMBER: builtins.int
    EK_FIELD_NUMBER: builtins.int
    MESSAGE_FIELD_NUMBER: builtins.int
    pk_id: builtins.int
    spk_id: builtins.int
    ik: builtins.bytes
    ek: builtins.bytes
    @property
    def message(self) -> global___OMEMOAuthenticatedMessage: ...
    def __init__(self,
        *,
        pk_id: typing.Optional[builtins.int] = ...,
        spk_id: typing.Optional[builtins.int] = ...,
        ik: typing.Optional[builtins.bytes] = ...,
        ek: typing.Optional[builtins.bytes] = ...,
        message: typing.Optional[global___OMEMOAuthenticatedMessage] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["ek",b"ek","ik",b"ik","message",b"message","pk_id",b"pk_id","spk_id",b"spk_id"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["ek",b"ek","ik",b"ik","message",b"message","pk_id",b"pk_id","spk_id",b"spk_id"]) -> None: ...
global___OMEMOKeyExchange = OMEMOKeyExchange
