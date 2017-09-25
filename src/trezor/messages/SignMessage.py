# Automatically generated by pb2py
import protobuf as p


class SignMessage(p.MessageType):
    FIELDS = {
        1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
        2: ('message', p.BytesType, 0),  # required
        3: ('coin_name', p.UnicodeType, 0),  # default='Bitcoin'
        4: ('script_type', p.UVarintType, 0),  # default=0
    }
    MESSAGE_WIRE_TYPE = 38
