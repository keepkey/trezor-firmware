# Automatically generated by pb2py
import protobuf as p


class SignTx(p.MessageType):
    FIELDS = {
        1: ('outputs_count', p.UVarintType, 0),  # required
        2: ('inputs_count', p.UVarintType, 0),  # required
        3: ('coin_name', p.UnicodeType, 0),  # default='Bitcoin'
        4: ('version', p.UVarintType, 0),  # default=1
        5: ('lock_time', p.UVarintType, 0),  # default=0
    }
    MESSAGE_WIRE_TYPE = 15
