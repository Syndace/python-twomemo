from __future__ import annotations

import base64
import secrets
from typing import Dict, Final, Optional, Tuple, cast

import doubleratchet
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)
from doubleratchet.recommended.crypto_provider_impl import CryptoProviderImpl
import google.protobuf.message
import x3dh
import x3dh.identity_key_pair

from omemo.backend import Backend, DecryptionFailed, KeyExchangeFailed
from omemo.bundle import Bundle
from omemo.identity_key_pair import IdentityKeyPair, IdentityKeyPairSeed
from omemo.message import Content, EncryptedKeyMaterial, PlainKeyMaterial, KeyExchange
from omemo.session import Initiation, Session
from omemo.storage import Storage
from omemo.types import JSONType
import xeddsa

# https://github.com/PyCQA/pylint/issues/4987
from .twomemo_pb2 import (  # pylint: disable=no-name-in-module
    OMEMOAuthenticatedMessage,
    OMEMOKeyExchange,
    OMEMOMessage
)


__all__ = [
    "Twomemo",
    "NAMESPACE",
    "AEADImpl",
    "BundleImpl",
    "ContentImpl",
    "DoubleRatchetImpl",
    "EncryptedKeyMaterialImpl",
    "KeyExchangeImpl",
    "MessageChainKDFImpl",
    "PlainKeyMaterialImpl",
    "RootChainKDFImpl",
    "SessionImpl",
    "StateImpl"
]


NAMESPACE: Final = "urn:xmpp:omemo:2"


class RootChainKDFImpl(kdf_hkdf.KDF):
    """
    The root chain KDF implementation used by this version of the specification.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "OMEMO Root Chain".encode("ASCII")


class MessageChainKDFImpl(kdf_separate_hmacs.KDF):
    """
    The message chain KDF implementation used by this version of the specification.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256


class AEADImpl(aead_aes_hmac.AEAD):
    """
    The AEAD used by this backend as part of the Double Ratchet. While this implementation derives from
    :class:`doubleratchet.recommended.aead_aes_hmac.AEAD`, it actually doesn't use any of its code. This is
    due to a minor difference in the way the associated data is built. The derivation only has symbolic value.

    Can only be used with :class:`DoubleRatchetImpl`, due to the reliance on a certain structure of the
    associated data.
    """

    AUTHENTICATION_TAG_TRUNCATED_LENGTH: Final = 16

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "OMEMO Message Key Material".encode("ASCII")

    @classmethod
    async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function()

        encryption_key, authentication_key, iv = await cls.__derive(key, hash_function, cls._get_info())

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, after padding it with PKCS#7
        ciphertext = await CryptoProviderImpl.aes_cbc_encrypt(encryption_key, iv, plaintext)

        # Parse the associated data
        associated_data, header = cls.__parse_associated_data(associated_data)

        # Build an OMEMOMessage including the header and the ciphertext
        omemo_message = OMEMOMessage(
            n=header.sending_chain_length,
            pn=header.previous_sending_chain_length,
            dh_pub=header.ratchet_pub,
            ciphertext=ciphertext
        ).SerializeToString()

        # Calculate the authentication tag over the associated data and the OMEMOMessage, truncate the
        # authentication tag to AUTHENTICATION_TAG_TRUNCATED_LENGTH bytes
        auth = (await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            hash_function,
            associated_data + omemo_message
        ))[:AEADImpl.AUTHENTICATION_TAG_TRUNCATED_LENGTH]

        # Serialize the authentication tag with the OMEMOMessage in an OMEMOAuthenticatedMessage.
        return OMEMOAuthenticatedMessage(mac=auth, message=omemo_message).SerializeToString()

    @classmethod
    async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function()

        decryption_key, authentication_key, iv = await cls.__derive(key, hash_function, cls._get_info())

        # Parse the associated data
        associated_data, header = cls.__parse_associated_data(associated_data)

        # Parse the ciphertext as an OMEMOAuthenticatedMessage
        try:
            omemo_authenticated_message = OMEMOAuthenticatedMessage.FromString(ciphertext)
        except google.protobuf.message.DecodeError as e:
            raise doubleratchet.DecryptionFailedException() from e

        # Calculate and verify the authentication tag
        new_auth = (await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            hash_function,
            associated_data + omemo_authenticated_message.message
        ))[:AEADImpl.AUTHENTICATION_TAG_TRUNCATED_LENGTH]

        if new_auth != omemo_authenticated_message.mac:
            raise doubleratchet.aead.AuthenticationFailedException("Authentication tags do not match.")

        # Parse the OMEMOMessage contained in the OMEMOAuthenticatedMessage
        try:
            omemo_message = OMEMOMessage.FromString(omemo_authenticated_message.message)
        except google.protobuf.message.DecodeError as e:
            raise doubleratchet.DecryptionFailedException() from e

        # Make sure that the headers match as a little additional consistency check
        if header != doubleratchet.Header(omemo_message.dh_pub, omemo_message.pn, omemo_message.n):
            raise doubleratchet.aead.AuthenticationFailedException("Header mismatch.")

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, and unpad the resulting plaintext with PKCS#7
        return await CryptoProviderImpl.aes_cbc_decrypt(decryption_key, iv, omemo_message.ciphertext)

    @staticmethod
    async def __derive(key: bytes, hash_function: HashFunction, info: bytes) -> Tuple[bytes, bytes, bytes]:
        # Prepare the salt, a zero-filled byte sequence with the size of the hash digest
        salt = b"\x00" * hash_function.hash_size

        # Derive 80 bytes
        hkdf_out = await CryptoProviderImpl.hkdf_derive(
            hash_function=hash_function,
            length=80,
            salt=salt,
            info=info,
            key_material=key
        )

        # Split these 80 bytes into three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    @staticmethod
    def __parse_associated_data(associated_data: bytes) -> Tuple[bytes, doubleratchet.Header]:
        """
        Parse the associated data as built by :meth:`DoubleRatchetImpl._build_associated_data`.

        Args:
            associated_data: The associated data.

        Returns:
            The original associated data and the header used to build it.

        Raises:
            doubleratchet.DecryptionFailedException: if the data is malformed.
        """

        associated_data_length = StateImpl.IDENTITY_KEY_ENCODING_LENGTH * 2

        try:
            omemo_message = OMEMOMessage.FromString(associated_data[associated_data_length:])
        except google.protobuf.message.DecodeError as e:
            raise doubleratchet.DecryptionFailedException() from e

        associated_data = associated_data[:associated_data_length]

        return associated_data, doubleratchet.Header(omemo_message.dh_pub, omemo_message.pn, omemo_message.n)


class DoubleRatchetImpl(doubleratchet.DoubleRatchet):
    """
    The Double Ratchet implementation used by this version of the specification.
    """

    MESSAGE_CHAIN_CONSTANT: Final = b"\x02\x01"

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: doubleratchet.Header) -> bytes:
        return associated_data + OMEMOMessage(
            n=header.sending_chain_length,
            pn=header.previous_sending_chain_length,
            dh_pub=header.ratchet_pub
        ).SerializeToString()


class StateImpl(x3dh.BaseState):
    """
    The X3DH state implementation used by this version of the specification.
    """

    INFO: Final = "OMEMO X3DH".encode("ASCII")
    IDENTITY_KEY_ENCODING_LENGTH: Final = 32

    @staticmethod
    def _encode_public_key(key_format: x3dh.IdentityKeyFormat, pub: bytes) -> bytes:
        return pub


class BundleImpl(Bundle):
    """
    :class:`~omemo.bundle.Bundle` implementation as a simple storage type.
    """

    def __init__(
        self,
        bare_jid: str,
        device_id: int,
        bundle: x3dh.Bundle,
        signed_pre_key_id: int,
        pre_key_ids: Dict[bytes, int]
    ) -> None:
        """
        Args:
            bare_jid: The bare JID this bundle belongs to.
            device_id: The device id of the specific device this bundle belongs to.
            bundle: The bundle to store in this instance.
            signed_pre_key_id: The id of the signed pre key referenced in the bundle.
            pre_key_ids: A dictionary that maps each pre key referenced in the bundle to its id.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__bundle = bundle
        self.__signed_pre_key_id = signed_pre_key_id
        self.__pre_key_ids = dict(pre_key_ids)

    @property
    def namespace(self) -> str:
        return NAMESPACE

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def identity_key(self) -> bytes:
        return self.__bundle.identity_key

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BundleImpl):
            return (
                other.bare_jid == self.bare_jid
                and other.device_id == self.device_id
                and other.bundle == self.bundle
                and other.signed_pre_key_id == self.signed_pre_key_id
                and other.pre_key_ids == self.pre_key_ids
            )

        return False

    def __hash__(self) -> int:
        return hash((
            self.bare_jid,
            self.device_id,
            self.bundle,
            self.signed_pre_key_id,
            frozenset(self.pre_key_ids.items())
        ))

    @property
    def bundle(self) -> x3dh.Bundle:
        """
        Returns:
            The bundle held by this instance.
        """

        return self.__bundle

    @property
    def signed_pre_key_id(self) -> int:
        """
        Returns:
            The id of the signed pre key referenced in the bundle.
        """

        return self.__signed_pre_key_id

    @property
    def pre_key_ids(self) -> Dict[bytes, int]:
        """
        Returns:
            A dictionary that maps each pre key referenced in the bundle to its id.
        """

        return dict(self.__pre_key_ids)


class ContentImpl(Content):
    """
    :class:`~omemo.message.Content` implementation as a simple storage type.
    """

    def __init__(self, ciphertext: bytes) -> None:
        """
        Args:
            ciphertext: The ciphertext to store in this instance.

        Note:
            For empty OMEMO messages as per the specification, the ciphertext is set to an empty byte string.
        """

        self.__ciphertext = ciphertext

    @property
    def empty(self) -> bool:
        return self.__ciphertext == b""

    @staticmethod
    def make_empty() -> ContentImpl:
        """
        Returns:
            An "empty" instance, i.e. one that corresponds to an empty OMEMO message as per the specification.
            The ciphertext stored in empty instances is a byte string of zero length.
        """

        return ContentImpl(b"")

    @property
    def ciphertext(self) -> bytes:
        """
        Returns:
            The ciphertext held by this instance.
        """

        return self.__ciphertext


class EncryptedKeyMaterialImpl(EncryptedKeyMaterial):
    """
    :class:`~omemo.message.EncryptedKeyMaterial` implementation as a simple storage type.
    """

    def __init__(
        self,
        bare_jid: str,
        device_id: int,
        encrypted_message: doubleratchet.EncryptedMessage
    ) -> None:
        """
        Args:
            bare_jid: The bare JID of the other party.
            device_id: The device id of the specific device of the other party.
            encrypted_message: The encrypted Double Ratchet message to store in this instance.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__encrypted_message = encrypted_message

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def encrypted_message(self) -> doubleratchet.EncryptedMessage:
        """
        Returns:
            The encrypted Double Ratchet message held by this instance.
        """

        return self.__encrypted_message

    def serialize(self) -> bytes:
        """
        Returns:
            A serialized OMEMOAuthenticatedMessage message structure representing the content of this
            instance.
        """

        # The ciphertext field contains the result of :meth:`AEADImpl.encrypt`, which is a serialized
        # OMEMOAuthenticatedMessage with all fields already correctly set, thus it can be used here as is.
        return self.__encrypted_message.ciphertext

    @staticmethod
    def parse(authenticated_message: bytes, bare_jid: str, device_id: int) -> EncryptedKeyMaterialImpl:
        """
        Args:
            authenticated_message: A serialized OMEMOAuthenticatedMessage message structure.
            bare_jid: The bare JID of the other party.
            device_id: The device id of the specific device of the other party.

        Returns:
            An instance of this class, parsed from the OMEMOAuthenticatedMessage.

        Raises:
            ValueError: if the data is malformed.
        """

        # Parse the OMEMOAuthenticatedMessage and OMEMOMessage structures to extract the header.
        try:
            message = OMEMOMessage.FromString(OMEMOAuthenticatedMessage.FromString(
                authenticated_message
            ).message)
        except google.protobuf.message.DecodeError as e:
            raise ValueError() from e

        return EncryptedKeyMaterialImpl(
            bare_jid,
            device_id,
            doubleratchet.EncryptedMessage(
                doubleratchet.Header(message.dh_pub, message.pn, message.n),
                authenticated_message
            )
        )


class PlainKeyMaterialImpl(PlainKeyMaterial):
    """
    :class:`~omemo.message.PlainKeyMaterial` implementation as a simple storage type.
    """

    KEY_LENGTH: Final = 32

    def __init__(self, key: bytes, auth_tag: bytes) -> None:
        """
        Args:
            key: The key to store in this instance.
            auth_tag: The authentication tag to store in this instance.

        Note:
            For empty OMEMO messages as per the specification, the key is set to :attr:`KEY_LENGTH`
            zero-bytes, and the auth tag is set to an empty byte string.
        """

        self.__key = key
        self.__auth_tag = auth_tag

    @property
    def key(self) -> bytes:
        """
        Returns:
            The key held by this instance.
        """

        return self.__key

    @property
    def auth_tag(self) -> bytes:
        """
        Returns:
            The authentication tag held by this instance.
        """

        return self.__auth_tag

    @staticmethod
    def make_empty() -> PlainKeyMaterialImpl:
        """
        Returns:
            An "empty" instance, i.e. one that corresponds to an empty OMEMO message as per the specification.
            The key stored in empty instances is a byte string of :attr:`KEY_LENGTH` zero-bytes, and the auth
            tag is an empty byte string.
        """

        return PlainKeyMaterialImpl(b"\x00" * PlainKeyMaterialImpl.KEY_LENGTH, b"")


class KeyExchangeImpl(KeyExchange):
    """
    :class:`~omemo.message.KeyExchange` implementation as a simple storage type.

    There are two kinds of instances:

    - Completely filled instances
    - Partially filled instances received via network

    Empty fields are filled with filler values such that the data types and lengths still match expectations.
    """

    def __init__(self, header: x3dh.Header, signed_pre_key_id: int, pre_key_id: int) -> None:
        """
        Args:
            header: The header to store in this instance.
            signed_pre_key_id: The id of the signed pre key referenced in the header.
            pre_key_id: The id of the pre key referenced in the header.
        """

        self.__header = header
        self.__signed_pre_key_id = signed_pre_key_id
        self.__pre_key_id = pre_key_id

    @property
    def identity_key(self) -> bytes:
        return self.__header.identity_key

    def builds_same_session(self, other: KeyExchange) -> bool:
        # The signed pre key id and pre key id are enough for uniqueness; ignoring the actual signed pre key
        # and pre key bytes here makes it possible to compare network instances with completely filled
        # instances.
        return isinstance(other, KeyExchangeImpl) and (
            other.header.identity_key == self.header.identity_key
            and other.header.ephemeral_key == self.header.ephemeral_key
            and other.signed_pre_key_id == self.signed_pre_key_id
            and other.pre_key_id == self.pre_key_id
        )

    @property
    def header(self) -> x3dh.Header:
        """
        Returns:
            The header held by this instance.
        """

        return self.__header

    @property
    def signed_pre_key_id(self) -> int:
        """
        Returns:
            The id of the signed pre key referenced in the header.
        """

        return self.__signed_pre_key_id

    @property
    def pre_key_id(self) -> int:
        """
        Returns:
            The id of the pre key referenced in the header.
        """

        return self.__pre_key_id

    def is_network_instance(self) -> bool:
        """
        Returns:
            Returns whether this is a network instance. A network instance has all fields filled except for
            the signed pre key and pre key byte data. The missing byte data can be restored by looking it up
            from storage using the respective ids.
        """

        return self.__header.signed_pre_key == b"" and self.__header.pre_key == b""

    def serialize(self, authenticated_message: bytes) -> bytes:
        """
        Args:
            authenticated_message: The serialized OMEMOAuthenticatedMessage message structure to include with
                the key exchange information.

        Returns:
            A serialized OMEMOKeyExchange message structure representing the content of this instance.

        Raises:
            ValueError: if the serialized OMEMOAuthenticatedMessage is malformed.
        """

        try:
            authenticated_message_parsed = OMEMOAuthenticatedMessage.FromString(authenticated_message)
        except google.protobuf.message.DecodeError as e:
            raise ValueError() from e

        return OMEMOKeyExchange(
            pk_id=self.__pre_key_id,
            spk_id=self.__signed_pre_key_id,
            ik=self.__header.identity_key,
            ek=self.__header.ephemeral_key,
            message=authenticated_message_parsed
        ).SerializeToString()

    @staticmethod
    def parse(key_exchange: bytes) -> Tuple[KeyExchangeImpl, bytes]:
        """
        Args:
            key_exchange: A serialized OMEMOKeyExchange message structure.

        Returns:
            An instance of this class, parsed from the OMEMOKeyExchange, and the serialized
            OMEMOAuthenticatedMessage extracted from the OMEMOKeyExchange.

        Raises:
            ValueError: if the data is malformed.

        Warning:
            The OMEMOKeyExchange message structure only contains the ids of the signed pre key and the pre key
            used for the key exchange, not the full public keys. Since the job of this method is just parsing,
            the X3DH header is initialized without the public keys here, and the code using instances of this
            class has to handle the public key lookup from the ids. Use :meth:`is_network_instance` to check
            whether the header is a full or a partial (network) instance.
        """

        try:
            parsed = OMEMOKeyExchange.FromString(key_exchange)
        except google.protobuf.message.DecodeError as e:
            raise ValueError() from e

        return KeyExchangeImpl(
            x3dh.Header(parsed.ik, parsed.ek, b"", b""),
            parsed.spk_id,
            parsed.pk_id
        ), parsed.message.SerializeToString()


class SessionImpl(Session):
    """
    :class:`~omemo.session.Session` implementation as a simple storage type.
    """

    def __init__(
        self,
        bare_jid: str,
        device_id: int,
        initiation: Initiation,
        key_exchange: KeyExchangeImpl,
        associated_data: bytes,
        double_ratchet: DoubleRatchetImpl,
        confirmed: bool = False
    ):
        """
        Args:
            bare_jid: The bare JID of the other party.
            device_id: The device id of the specific device of the other party.
            initiation: Whether this session was built through active or passive session initiation.
            key_exchange: The key exchange information to store in this instance.
            associated_data: The associated data to store in this instance.
            double_ratchet: The Double Ratchet to store in this instance.
            confirmed: Whether the session was confirmed, i.e. whether a message was decrypted after actively
                initiating the session. Leave this at the default value for passively initiated sessions.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__initiation = initiation
        self.__key_exchange = key_exchange
        self.__associated_data = associated_data
        self.__double_ratchet = double_ratchet
        self.__confirmed = confirmed

    @property
    def namespace(self) -> str:
        return NAMESPACE

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def initiation(self) -> Initiation:
        return self.__initiation

    @property
    def confirmed(self) -> bool:
        return self.__confirmed

    @property
    def key_exchange(self) -> KeyExchangeImpl:
        return self.__key_exchange

    @property
    def receiving_chain_length(self) -> Optional[int]:
        return self.__double_ratchet.receiving_chain_length

    @property
    def sending_chain_length(self) -> int:
        return self.__double_ratchet.sending_chain_length

    @property
    def associated_data(self) -> bytes:
        """
        Returns:
            The associated data held by this instance.
        """

        return self.__associated_data

    @property
    def double_ratchet(self) -> DoubleRatchetImpl:
        """
        Returns:
            The Double Ratchet held by this instance.
        """

        return self.__double_ratchet

    def confirm(self) -> None:
        """
        Mark this session as confirmed.
        """

        self.__confirmed = True


class Twomemo(Backend):
    """
    :class:`~omemo.backend.Backend` implementation providing OMEMO in the `urn:xmpp:omemo:2` namespace.
    """

    def __init__(
        self,
        storage: Storage,
        max_num_per_session_skipped_keys: int = 1000,
        max_num_per_message_skipped_keys: Optional[int] = None
    ) -> None:
        """
        Args:
            storage: The storage to store backend-specific data in. Note that all data keys are prefixed with
                the backend namespace to avoid name clashes between backends.
            max_num_per_session_skipped_keys: The maximum number of skipped message keys to keep around per
                session. Once the maximum is reached, old message keys are deleted to make space for newer
                ones. Accessible via :attr:`~omemo.backend.Backend.max_num_per_session_skipped_keys`.
            max_num_per_message_skipped_keys: The maximum number of skipped message keys to accept in a single
                message. When set to ``None`` (the default), this parameter defaults to the per-session
                maximum (i.e. the value of the ``max_num_per_session_skipped_keys`` parameter). This parameter
                may only be 0 if the per-session maximum is 0, otherwise it must be a number between 1 and the
                per-session maximum. Accessible via
                :attr:`~omemo.backend.Backend.max_num_per_message_skipped_keys`.
        """

        super().__init__(max_num_per_session_skipped_keys, max_num_per_message_skipped_keys)

        self.__storage = storage

    async def __get_state(self) -> StateImpl:
        """
        Returns:
            The loaded or newly created X3DH state.
        """

        def check_type(value: JSONType) -> x3dh.types.JSONObject:
            if isinstance(value, dict):
                return cast(x3dh.types.JSONObject, value)

            raise TypeError(
                f"Stored StateImpl under key /{self.namespace}/x3dh corrupt: not a JSON object: {value}"
            )

        state, _ = (await self.__storage.load(
            f"/{self.namespace}/x3dh"
        )).fmap(check_type).fmap(lambda serialized: StateImpl.from_json(
            serialized,
            x3dh.IdentityKeyFormat.ED_25519,
            x3dh.HashFunction.SHA_256,
            StateImpl.INFO
        )).maybe((None, False))

        if state is None:
            identity_key_pair = await IdentityKeyPair.get(self.__storage)

            state = StateImpl.create(
                x3dh.IdentityKeyFormat.ED_25519,
                x3dh.HashFunction.SHA_256,
                StateImpl.INFO,
                (
                    x3dh.identity_key_pair.IdentityKeyPairSeed(identity_key_pair.seed)
                    if isinstance(identity_key_pair, IdentityKeyPairSeed)
                    else x3dh.identity_key_pair.IdentityKeyPairPriv(identity_key_pair.as_priv().priv)
                )
            )

            await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return state

    @property
    def namespace(self) -> str:
        return NAMESPACE

    async def load_session(self, bare_jid: str, device_id: int) -> Optional[SessionImpl]:
        def check_type(value: JSONType) -> doubleratchet.types.JSONObject:
            if isinstance(value, dict):
                return cast(doubleratchet.types.JSONObject, value)

            raise TypeError(
                f"Stored DoubleRatchetImpl under key"
                f" /{self.namespace}/{bare_jid}/{device_id}/double_ratchet corrupt: not a JSON object:"
                f" {value}"
            )

        try:
            double_ratchet = (await self.__storage.load(
                f"/{self.namespace}/{bare_jid}/{device_id}/double_ratchet"
            )).fmap(check_type).fmap(lambda serialized: DoubleRatchetImpl.from_json(
                serialized,
                diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
                RootChainKDFImpl,
                MessageChainKDFImpl,
                DoubleRatchetImpl.MESSAGE_CHAIN_CONSTANT,
                self.max_num_per_message_skipped_keys,
                self.max_num_per_session_skipped_keys,
                AEADImpl
            )).maybe(None)
        except doubleratchet.InconsistentSerializationException:
            return None

        if double_ratchet is None:
            return None

        initiation = Initiation((await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/initiation",
            str
        )).from_just())

        identity_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/identity_key"
        )).from_just()

        ephemeral_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/ephemeral_key"
        )).from_just()

        signed_pre_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key"
        )).from_just()

        signed_pre_key_id = (await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key_id",
            int
        )).from_just()

        pre_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key"
        )).from_just()

        pre_key_id = (await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key_id",
            int
        )).from_just()

        associated_data = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/associated_data"
        )).from_just()

        confirmed = (await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/confirmed",
            bool
        )).from_just()

        return SessionImpl(bare_jid, device_id, initiation, KeyExchangeImpl(
            x3dh.Header(identity_key, ephemeral_key, signed_pre_key, pre_key),
            signed_pre_key_id,
            pre_key_id
        ), associated_data, double_ratchet, confirmed)

    async def store_session(self, session: Session) -> None:
        assert isinstance(session, SessionImpl)

        assert session.key_exchange.header.pre_key is not None

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/initiation",
            session.initiation.name
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/identity_key",
            session.key_exchange.header.identity_key
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/ephemeral_key",
            session.key_exchange.header.ephemeral_key
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/signed_pre_key",
            session.key_exchange.header.signed_pre_key
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/signed_pre_key_id",
            session.key_exchange.signed_pre_key_id
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key",
            session.key_exchange.header.pre_key
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key_id",
            session.key_exchange.pre_key_id
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/associated_data",
            session.associated_data
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/double_ratchet",
            session.double_ratchet.json
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/confirmed",
            session.confirmed
        )

        # Keep track of bare JIDs with stored sessions
        bare_jids = set((await self.__storage.load_list(f"/{self.namespace}/bare_jids", str)).maybe([]))
        bare_jids.add(session.bare_jid)
        await self.__storage.store(f"/{self.namespace}/bare_jids", list(bare_jids))

        # Keep track of device ids with stored sessions
        device_ids = set((await self.__storage.load_list(
            f"/{self.namespace}/{session.bare_jid}/device_ids",
            int
        )).maybe([]))
        device_ids.add(session.device_id)
        await self.__storage.store(f"/{self.namespace}/{session.bare_jid}/device_ids", list(device_ids))

    async def build_session_active(
        self,
        bare_jid: str,
        device_id: int,
        bundle: Bundle,
        plain_key_material: PlainKeyMaterial
    ) -> Tuple[SessionImpl, EncryptedKeyMaterialImpl]:
        assert isinstance(bundle, BundleImpl)
        assert isinstance(plain_key_material, PlainKeyMaterialImpl)

        try:
            state = await self.__get_state()
            shared_secret, associated_data, header = await state.get_shared_secret_active(bundle.bundle)
        except x3dh.KeyAgreementException as e:
            raise KeyExchangeFailed() from e

        assert header.pre_key is not None

        double_ratchet, encrypted_message = await DoubleRatchetImpl.encrypt_initial_message(
            diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
            RootChainKDFImpl,
            MessageChainKDFImpl,
            DoubleRatchetImpl.MESSAGE_CHAIN_CONSTANT,
            self.max_num_per_message_skipped_keys,
            self.max_num_per_session_skipped_keys,
            AEADImpl,
            shared_secret,
            bundle.bundle.signed_pre_key,
            plain_key_material.key + plain_key_material.auth_tag,
            associated_data
        )

        session = SessionImpl(
            bare_jid,
            device_id,
            Initiation.ACTIVE,
            KeyExchangeImpl(
                header,
                bundle.signed_pre_key_id,
                bundle.pre_key_ids[header.pre_key]
            ),
            associated_data,
            double_ratchet
        )

        encrypted_key_material = EncryptedKeyMaterialImpl(bare_jid, device_id, encrypted_message)

        return session, encrypted_key_material

    async def build_session_passive(
        self,
        bare_jid: str,
        device_id: int,
        key_exchange: KeyExchange,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> Tuple[SessionImpl, PlainKeyMaterialImpl]:
        assert isinstance(key_exchange, KeyExchangeImpl)
        assert isinstance(encrypted_key_material, EncryptedKeyMaterialImpl)

        state = await self.__get_state()

        if key_exchange.is_network_instance():
            # Perform lookup of the signed pre key and pre key public keys in case the header is not filled
            signed_pre_keys_by_id = { v: k for k, v in (await self.__get_signed_pre_key_ids()).items() }
            if key_exchange.signed_pre_key_id not in signed_pre_keys_by_id:
                raise KeyExchangeFailed(f"No signed pre key with id {key_exchange.signed_pre_key_id} known.")

            pre_keys_by_id = { v: k for k, v in (await self.__get_pre_key_ids()).items() }
            if key_exchange.pre_key_id not in pre_keys_by_id:
                raise KeyExchangeFailed(f"No pre key with id {key_exchange.pre_key_id} known.")

            # Update the key exchange information with the filled header
            key_exchange = KeyExchangeImpl(
                x3dh.Header(
                    key_exchange.header.identity_key,
                    key_exchange.header.ephemeral_key,
                    signed_pre_keys_by_id[key_exchange.signed_pre_key_id],
                    pre_keys_by_id[key_exchange.pre_key_id]
                ),
                key_exchange.signed_pre_key_id,
                key_exchange.pre_key_id
            )

        try:
            shared_secret, associated_data, signed_pre_key = await state.get_shared_secret_passive(
                key_exchange.header
            )
        except x3dh.KeyAgreementException as e:
            raise KeyExchangeFailed() from e

        try:
            double_ratchet, decrypted_message = await DoubleRatchetImpl.decrypt_initial_message(
                diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
                RootChainKDFImpl,
                MessageChainKDFImpl,
                DoubleRatchetImpl.MESSAGE_CHAIN_CONSTANT,
                self.max_num_per_message_skipped_keys,
                self.max_num_per_session_skipped_keys,
                AEADImpl,
                shared_secret,
                signed_pre_key.priv,
                encrypted_key_material.encrypted_message,
                associated_data
            )
        except Exception as e:
            raise DecryptionFailed(
                "Decryption of the initial message as part of passive session building failed."
            ) from e

        session = SessionImpl(
            bare_jid,
            device_id,
            Initiation.PASSIVE,
            key_exchange,
            associated_data,
            double_ratchet
        )

        plain_key_material = PlainKeyMaterialImpl(
            decrypted_message[:PlainKeyMaterialImpl.KEY_LENGTH],
            decrypted_message[PlainKeyMaterialImpl.KEY_LENGTH:]
        )

        return session, plain_key_material

    async def encrypt_plaintext(self, plaintext: bytes) -> Tuple[ContentImpl, PlainKeyMaterialImpl]:
        # Generate KEY_LENGTH bytes of cryptographically secure random data for the key
        key = secrets.token_bytes(PlainKeyMaterialImpl.KEY_LENGTH)

        # Derive 80 bytes from the key using HKDF-SHA-256
        key_material = await CryptoProviderImpl.hkdf_derive(
            hash_function=HashFunction.SHA_256,
            length=80,
            salt=b"\x00" * 32,
            info="OMEMO Payload".encode("ASCII"),
            key_material=key
        )

        # Split those 80 bytes into an encryption key, authentication key and an initialization vector
        encryption_key = key_material[:32]
        authentication_key = key_material[32:64]
        initialization_vector = key_material[64:]

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, after padding it with PKCS#7
        ciphertext = await CryptoProviderImpl.aes_cbc_encrypt(
            encryption_key,
            initialization_vector,
            plaintext
        )

        # Calculate the authentication tag and truncate it to AUTHENTICATION_TAG_TRUNCATED_LENGTH bytes
        auth_tag = (await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            HashFunction.SHA_256,
            ciphertext
        ))[:AEADImpl.AUTHENTICATION_TAG_TRUNCATED_LENGTH]

        return ContentImpl(ciphertext), PlainKeyMaterialImpl(key, auth_tag)

    async def encrypt_empty(self) -> Tuple[ContentImpl, PlainKeyMaterialImpl]:
        return ContentImpl.make_empty(), PlainKeyMaterialImpl.make_empty()

    async def encrypt_key_material(
        self,
        session: Session,
        plain_key_material: PlainKeyMaterial
    ) -> EncryptedKeyMaterialImpl:
        assert isinstance(session, SessionImpl)
        assert isinstance(plain_key_material, PlainKeyMaterialImpl)

        return EncryptedKeyMaterialImpl(
            session.bare_jid,
            session.device_id,
            await session.double_ratchet.encrypt_message(
                plain_key_material.key + plain_key_material.auth_tag,
                session.associated_data
            )
        )

    async def decrypt_plaintext(self, content: Content, plain_key_material: PlainKeyMaterial) -> bytes:
        assert isinstance(content, ContentImpl)
        assert isinstance(plain_key_material, PlainKeyMaterialImpl)

        assert not content.empty

        # Derive 80 bytes from the key using HKDF-SHA-256
        key_material = await CryptoProviderImpl.hkdf_derive(
            hash_function=HashFunction.SHA_256,
            length=80,
            salt=b"\x00" * 32,
            info="OMEMO Payload".encode("ASCII"),
            key_material=plain_key_material.key
        )

        # Split those 80 bytes into an encryption key, authentication key and an initialization vector
        decryption_key = key_material[:32]
        authentication_key = key_material[32:64]
        initialization_vector = key_material[64:]

        # Calculate and verify the authentication tag after truncating it to
        # AUTHENTICATION_TAG_TRUNCATED_LENGTH bytes
        auth_tag = (await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            HashFunction.SHA_256,
            content.ciphertext
        ))[:AEADImpl.AUTHENTICATION_TAG_TRUNCATED_LENGTH]

        if auth_tag != plain_key_material.auth_tag:
            raise DecryptionFailed("Authentication tag verification failed.")

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, and unpad the resulting plaintext with PKCS#7
        return await CryptoProviderImpl.aes_cbc_decrypt(
            decryption_key,
            initialization_vector,
            content.ciphertext
        )

    async def decrypt_key_material(
        self,
        session: Session,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> PlainKeyMaterialImpl:
        assert isinstance(session, SessionImpl)
        assert isinstance(encrypted_key_material, EncryptedKeyMaterialImpl)

        try:
            decrypted_message = await session.double_ratchet.decrypt_message(
                encrypted_key_material.encrypted_message,
                session.associated_data
            )
        except Exception as e:
            raise DecryptionFailed("Key material decryption failed.") from e

        session.confirm()

        return PlainKeyMaterialImpl(
            decrypted_message[:PlainKeyMaterialImpl.KEY_LENGTH],
            decrypted_message[PlainKeyMaterialImpl.KEY_LENGTH:]
        )

    async def signed_pre_key_age(self) -> int:
        return (await self.__get_state()).signed_pre_key_age()

    async def rotate_signed_pre_key(self) -> None:
        state = await self.__get_state()

        state.rotate_signed_pre_key()

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def hide_pre_key(self, session: Session) -> bool:
        assert isinstance(session, SessionImpl)

        # This method is only called with KeyExchangeImpl instances that have the pre key byte data set. We do
        # not have to worry about the field containing a filler value and the assertion is merely there to
        # satisfy the type system.
        assert session.key_exchange.header.pre_key is not None

        state = await self.__get_state()

        hidden = state.hide_pre_key(session.key_exchange.header.pre_key)

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return hidden

    async def delete_pre_key(self, session: Session) -> bool:
        assert isinstance(session, SessionImpl)

        # This method is only called with KeyExchangeImpl instances that have the pre key byte data set. We do
        # not have to worry about the field containing a filler value and the assertion is merely there to
        # satisfy the type system.
        assert session.key_exchange.header.pre_key is not None

        state = await self.__get_state()

        deleted = state.delete_pre_key(session.key_exchange.header.pre_key)

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return deleted

    async def delete_hidden_pre_keys(self) -> None:
        state = await self.__get_state()

        state.delete_hidden_pre_keys()

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def get_num_visible_pre_keys(self) -> int:
        return (await self.__get_state()).get_num_visible_pre_keys()

    async def generate_pre_keys(self, num_pre_keys: int) -> None:
        state = await self.__get_state()

        state.generate_pre_keys(num_pre_keys)

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def get_bundle(self, bare_jid: str, device_id: int) -> BundleImpl:
        bundle = (await self.__get_state()).bundle

        return BundleImpl(
            bare_jid,
            device_id,
            bundle,
            (await self.__get_signed_pre_key_ids())[bundle.signed_pre_key],
            {
                pre_key: pre_key_id
                for pre_key, pre_key_id
                in (await self.__get_pre_key_ids()).items()
                if pre_key in bundle.pre_keys
            }
        )

    @property
    def supports_labels(self) -> bool:
        return True

    async def sign_own_label(self, label: str) -> bytes:
        return xeddsa.ed25519_priv_sign(
            (await IdentityKeyPair.get(self.__storage)).as_priv().priv,
            label.encode("UTF-8")
        )

    async def verify_label_signature(self, label: str, signature: bytes, identity_key: bytes) -> bool:
        return xeddsa.ed25519_verify(signature, identity_key, label.encode("UTF-8"))

    async def purge(self) -> None:
        for bare_jid in (await self.__storage.load_list(f"/{self.namespace}/bare_jids", str)).maybe([]):
            await self.purge_bare_jid(bare_jid)

        await self.__storage.delete(f"/{self.namespace}/bare_jids")
        await self.__storage.delete(f"/{self.namespace}/x3dh")
        await self.__storage.delete(f"/{self.namespace}/signed_pre_key_ids")
        await self.__storage.delete(f"/{self.namespace}/pre_key_ids")
        await self.__storage.delete(f"/{self.namespace}/pre_key_id_counter")

    async def purge_bare_jid(self, bare_jid: str) -> None:
        storage = self.__storage

        for device_id in (await storage.load_list(f"/{self.namespace}/{bare_jid}/device_ids", int)).maybe([]):
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/initiation")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/identity_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/ephemeral_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key_id")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key_id")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/associated_data")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/double_ratchet")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/confirmed")

        await storage.delete(f"/{self.namespace}/{bare_jid}/device_ids")

        bare_jids = set((await storage.load_list(f"/{self.namespace}/bare_jids", str)).maybe([]))
        bare_jids.remove(bare_jid)
        await storage.store(f"/{self.namespace}/bare_jids", list(bare_jids))

    async def __get_signed_pre_key_ids(self) -> Dict[bytes, int]:
        """
        Assigns an id to each signed pre key currently available in the X3DH state, both the current signed
        pre key and the old signed pre key that is kept around for one more rotation period. Once assigned to
        a signed pre key, its id will never change.

        Returns:
            The mapping from signed pre key to id.
        """

        state = await self.__get_state()

        signed_pre_key = state.bundle.signed_pre_key
        old_signed_pre_key = state.old_signed_pre_key

        # Load the existing signed pre key ids from the storage
        signed_pre_key_ids = {
            base64.b64decode(signed_pre_key_b64): signed_pre_key_id
            for signed_pre_key_b64, signed_pre_key_id
            in (await self.__storage.load_dict(
                f"/{self.namespace}/signed_pre_key_ids",
                int
            )).maybe({}).items()
        }

        # Take note of the highest id that was assigned, default to 0 if no ids were assigned yet
        signed_pre_key_id_counter = max(
            signed_pre_key_id
            for _, signed_pre_key_id
            in signed_pre_key_ids.items()
        ) if len(signed_pre_key_ids) > 0 else 0

        # Prepare the dictionary to hold updated signed pre key ids
        new_signed_pre_key_ids: Dict[bytes, int] = {}

        # Assign the next highest id to the signed pre key, if there is no id assigned to it yet.
        signed_pre_key_id_counter += 1
        new_signed_pre_key_ids[signed_pre_key] = signed_pre_key_ids.get(
            signed_pre_key,
            signed_pre_key_id_counter
        )

        # Assign the next highest id to the old signed pre key, if there is no id assigned to it yet. This
        # should never happen, since the old signed pre key should have been assigned an id when it was the
        # (non-old) signed pre key, however there might be edge cases of the signed pre key rotating twice
        # before the assigned ids are updated.
        if old_signed_pre_key is not None:
            signed_pre_key_id_counter += 1
            new_signed_pre_key_ids[old_signed_pre_key] = signed_pre_key_ids.get(
                old_signed_pre_key,
                signed_pre_key_id_counter
            )

        # If the ids have changed, store them
        if new_signed_pre_key_ids != signed_pre_key_ids:
            await self.__storage.store(f"/{self.namespace}/signed_pre_key_ids", {
                base64.b64encode(signed_pre_key).decode("ASCII"): signed_pre_key_id
                for signed_pre_key, signed_pre_key_id
                in new_signed_pre_key_ids.items()
            })

        return new_signed_pre_key_ids

    async def __get_pre_key_ids(self) -> Dict[bytes, int]:
        """
        Assigns an id to each pre key currently available in the X3DH state, both hidden and visible pre keys.
        Once assigned to a pre key, its id will never change.

        Returns:
            The mapping from pre key to id.
        """

        state = await self.__get_state()

        pre_keys = state.bundle.pre_keys | state.hidden_pre_keys

        # Load the existing pre key ids from the storage
        pre_key_ids = {
            base64.b64decode(pre_key_b64): pre_key_id
            for pre_key_b64, pre_key_id
            in (await self.__storage.load_dict(f"/{self.namespace}/pre_key_ids", int)).maybe({}).items()
        }

        # Load the pre key id counter from the storage
        pre_key_id_counter = (await self.__storage.load_primitive(
            f"/{self.namespace}/pre_key_id_counter",
            int
        )).maybe(0)

        # Prepare the dictionary to hold updated pre key ids
        new_pre_key_ids: Dict[bytes, int] = {}

        # Assign the next highest id to each pre key if there is no existing id assigned to it
        for pre_key in pre_keys:
            pre_key_id_counter += 1
            new_pre_key_ids[pre_key] = pre_key_ids.get(pre_key, pre_key_id_counter)

        # If the ids have changed, store them
        if new_pre_key_ids != pre_key_ids:
            await self.__storage.store(f"/{self.namespace}/pre_key_ids", {
                base64.b64encode(pre_key).decode("ASCII"): pre_key_id
                for pre_key, pre_key_id
                in new_pre_key_ids.items()
            })

            await self.__storage.store(f"/{self.namespace}/pre_key_id_counter", pre_key_id_counter)

        return new_pre_key_ids
