/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.network.p2p.node.authorization;

import bisq.common.proto.Proto;
import bisq.security.pow.ProofOfWork;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@Slf4j
@ToString
@EqualsAndHashCode
public final class AuthorizationToken implements Proto {

    @Getter
    private final AuthorizationTokenType authTokenType;
    @Getter
    private final Optional<ProofOfWork> pow;

    public AuthorizationToken(AuthorizationTokenType authTokenType,
                              Optional<ProofOfWork> pow) {
        this.authTokenType = authTokenType;
        this.pow = pow;
    }

    public bisq.network.protobuf.AuthorizationToken toProto() {
        bisq.network.protobuf.AuthorizationToken.Builder builder = bisq.network.protobuf.AuthorizationToken.newBuilder()
                .setAuthTokenType(authTokenType.toProto());
        pow.ifPresent(powData -> builder.setPow(powData.toProto()));
        return builder.build();
    }

    public static AuthorizationToken fromProto(bisq.network.protobuf.AuthorizationToken proto) {
        Optional<ProofOfWork> pow = proto.hasPow() ? Optional.of(ProofOfWork.fromProto(proto.getPow())) : Optional.empty();
        return new AuthorizationToken(AuthorizationTokenType.fromProto(proto.getAuthTokenType()),
                pow);
    }
}
