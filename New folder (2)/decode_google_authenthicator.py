import base64
import urllib.parse
from google.protobuf import descriptor_pool, descriptor_pb2
from google.protobuf.message_factory import GetMessageClass

# ---------------------------------------------------------
# Build proto definition dynamically (Google Auth migration)
# ---------------------------------------------------------

pool = descriptor_pool.Default()

file_desc_proto = descriptor_pb2.FileDescriptorProto()
file_desc_proto.name = "migration.proto"
file_desc_proto.package = "google_auth"

# ----- Enums -----

algorithm_enum = descriptor_pb2.EnumDescriptorProto(
    name="Algorithm",
    value=[
        descriptor_pb2.EnumValueDescriptorProto(name="ALGO_UNSPECIFIED", number=0),
        descriptor_pb2.EnumValueDescriptorProto(name="ALGO_SHA1", number=1),
        descriptor_pb2.EnumValueDescriptorProto(name="ALGO_SHA256", number=2),
        descriptor_pb2.EnumValueDescriptorProto(name="ALGO_SHA512", number=3),
        descriptor_pb2.EnumValueDescriptorProto(name="ALGO_MD5", number=4),
    ],
)

otp_type_enum = descriptor_pb2.EnumDescriptorProto(
    name="OtpType",
    value=[
        descriptor_pb2.EnumValueDescriptorProto(name="OTP_TYPE_UNSPECIFIED", number=0),
        descriptor_pb2.EnumValueDescriptorProto(name="OTP_TYPE_HOTP", number=1),
        descriptor_pb2.EnumValueDescriptorProto(name="OTP_TYPE_TOTP", number=2),
    ],
)

# ----- Messages -----

otp_parameters = descriptor_pb2.DescriptorProto(
    name="OTPParameters",
    field=[
        descriptor_pb2.FieldDescriptorProto(
            name="secret", number=1, type=descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="name", number=2, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="issuer", number=3, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="algorithm",
            number=4,
            type=descriptor_pb2.FieldDescriptorProto.TYPE_ENUM,
            type_name="Algorithm",
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="digits", number=5, type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="type",
            number=6,
            type=descriptor_pb2.FieldDescriptorProto.TYPE_ENUM,
            type_name="OtpType",
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="counter", number=7, type=descriptor_pb2.FieldDescriptorProto.TYPE_INT64
        ),
    ],
)

migration_payload = descriptor_pb2.DescriptorProto(
    name="MigrationPayload",
    field=[
        descriptor_pb2.FieldDescriptorProto(
            name="otp_parameters",
            number=1,
            label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
            type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
            type_name="OTPParameters",
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="version", number=2, type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="batch_size", number=3, type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="batch_index", number=4, type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
        ),
        descriptor_pb2.FieldDescriptorProto(
            name="batch_id", number=5, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
        ),
    ],
)

file_desc_proto.enum_type.extend([algorithm_enum, otp_type_enum])
file_desc_proto.message_type.extend([otp_parameters, migration_payload])

pool.Add(file_desc_proto)

# ---------------------------------------------------------
# Get dynamic message class (protobuf 6.x compatible)
# ---------------------------------------------------------

desc = pool.FindMessageTypeByName("google_auth.MigrationPayload")
MigrationPayload = GetMessageClass(desc)

# ---------------------------------------------------------
# Decode migration URL
# ---------------------------------------------------------

with open("migration.txt") as f:
    url = f.read().strip()

parsed = urllib.parse.urlparse(url)
query = urllib.parse.parse_qs(parsed.query)
data_param = query.get("data", [None])[0]

if not data_param:
    raise ValueError("No 'data=' parameter found in migration.txt")

binary_data = base64.urlsafe_b64decode(data_param)

payload = MigrationPayload()
payload.ParseFromString(binary_data)

# ---------------------------------------------------------
# Output standard otpauth URIs
# ---------------------------------------------------------

for otp in payload.otp_parameters:
    secret_b32 = (
        base64.b32encode(otp.secret)
        .decode("utf-8")
        .rstrip("=")
    )

    issuer = otp.issuer or "Unknown"
    name = otp.name or "Unnamed"

    if otp.type == 1:  # HOTP
        uri = (
            f"otpauth://hotp/{issuer}:{name}"
            f"?secret={secret_b32}&issuer={issuer}&counter={otp.counter}"
        )
    else:  # TOTP (default)
        uri = (
            f"otpauth://totp/{issuer}:{name}"
            f"?secret={secret_b32}&issuer={issuer}"
        )

    print(uri)