# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: twomemo.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rtwomemo.proto\x12\x07twomemo\"I\n\x0cOMEMOMessage\x12\t\n\x01n\x18\x01 \x02(\r\x12\n\n\x02pn\x18\x02 \x02(\r\x12\x0e\n\x06\x64h_pub\x18\x03 \x02(\x0c\x12\x12\n\nciphertext\x18\x04 \x01(\x0c\"9\n\x19OMEMOAuthenticatedMessage\x12\x0b\n\x03mac\x18\x01 \x02(\x0c\x12\x0f\n\x07message\x18\x02 \x02(\x0c\"~\n\x10OMEMOKeyExchange\x12\r\n\x05pk_id\x18\x01 \x02(\r\x12\x0e\n\x06spk_id\x18\x02 \x02(\r\x12\n\n\x02ik\x18\x03 \x02(\x0c\x12\n\n\x02\x65k\x18\x04 \x02(\x0c\x12\x33\n\x07message\x18\x05 \x02(\x0b\x32\".twomemo.OMEMOAuthenticatedMessage')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'twomemo_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _OMEMOMESSAGE._serialized_start=26
  _OMEMOMESSAGE._serialized_end=99
  _OMEMOAUTHENTICATEDMESSAGE._serialized_start=101
  _OMEMOAUTHENTICATEDMESSAGE._serialized_end=158
  _OMEMOKEYEXCHANGE._serialized_start=160
  _OMEMOKEYEXCHANGE._serialized_end=286
# @@protoc_insertion_point(module_scope)
