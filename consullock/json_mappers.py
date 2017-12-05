from hgijson import MappingJSONEncoderClassBuilder, JsonPropertyMapping, MappingJSONDecoderClassBuilder, \
    DatetimeISOFormatJSONEncoder, DatetimeISOFormatJSONDecoder

from consullock.models import ConsulLockInformation


mapping_schema = [
    JsonPropertyMapping("key", "key", "key"),
    JsonPropertyMapping("session", "session_id", "session_id"),
    JsonPropertyMapping("created", "created", "created",
                        encoder_cls=DatetimeISOFormatJSONEncoder, decoder_cls=DatetimeISOFormatJSONDecoder),
    JsonPropertyMapping("secondsToLock", "seconds_to_lock", "seconds_to_lock"),
    JsonPropertyMapping("metadata", "metadata", "metadata", optional=True)
]
ConsulLockInformationJSONEncoder = MappingJSONEncoderClassBuilder(ConsulLockInformation, mapping_schema).build()
ConsulLockInformationJSONDecoder = MappingJSONDecoderClassBuilder(ConsulLockInformation, mapping_schema).build()
