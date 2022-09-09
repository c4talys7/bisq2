package bisq.network.p2p.node.authorization;

import bisq.common.proto.ProtoEnum;
import bisq.common.util.ProtobufUtils;

public enum AuthorizationTokenType implements ProtoEnum {
    UNRESTRICTED,
    EQUIHASH_POW,
    ACCOUNT_AGE;

    @Override
    public bisq.network.protobuf.AuthorizationTokenType toProto() {
        return bisq.network.protobuf.AuthorizationTokenType.valueOf(name());
    }

    public static AuthorizationTokenType fromProto(bisq.network.protobuf.AuthorizationTokenType proto) {
        return ProtobufUtils.enumFromProto(AuthorizationTokenType.class, proto.name());
    }
}

