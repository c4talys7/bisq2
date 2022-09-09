package bisq.network.p2p.node.authorization;

import bisq.common.data.ByteArray;
import bisq.network.p2p.message.NetworkMessage;
import bisq.persistence.PersistenceService;
import bisq.security.DigestUtil;
import bisq.security.pow.EquihashProofOfWorkService;
import bisq.security.pow.ProofOfWork;
import bisq.security.pow.ProofOfWorkService;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class EquihashAuthorizationService implements AuthorizationService{

    private final ByteArray localPayload;
    private final PersistenceService persistenceService;

    public EquihashAuthorizationService(ByteArray localPayload, PersistenceService persistenceService) {
        this.localPayload = localPayload;
        this.persistenceService = persistenceService;
    }

    public EquihashAuthorizationService() {
        this.localPayload = null;
        this.persistenceService = null;
    }

    /**
     * @param networkMessage 
     * @param authorizationToken
     * @return
     */
    @Override
    public boolean isAuthorized(NetworkMessage networkMessage, AuthorizationToken authorizationToken) {
        if(authorizationToken.getPow().isEmpty())
            return false;
        byte[] pubKeyHash = DigestUtil.hash(localPayload.getBytes());
        ProofOfWorkService pows = new EquihashProofOfWorkService(persistenceService);
        return pows.verify(authorizationToken.getPow().get());
    }

    /**
     * @param authorizationToken 
     * @return
     */
    @Override
    public boolean isAuthorized(AuthorizationToken authorizationToken) {
        if(authorizationToken.getPow().isEmpty())
            return false;
        byte[] pubKeyHash = DigestUtil.hash(localPayload.getBytes());
        ProofOfWorkService pows = new EquihashProofOfWorkService(persistenceService);
        return pows.verify(authorizationToken.getPow().get());
    }

    /**
     * @param message 
     * @return
     */
    @Override
    public CompletableFuture<AuthorizationToken> createTokenAsync(ByteArray payload, Class<? extends NetworkMessage> message) {
        Optional<ProofOfWork> pow = getPoW(payload);
        return CompletableFuture.completedFuture(new AuthorizationToken(AuthorizationTokenType.EQUIHASH_POW, pow));
    }

    /**
     * @param message 
     * @return
     */
    @Override
    public AuthorizationToken createToken(ByteArray payload, Class<? extends NetworkMessage> message) {
        Optional<ProofOfWork> pow = getPoW(payload);
        return new AuthorizationToken(AuthorizationTokenType.EQUIHASH_POW, pow);
    }

    private Optional<ProofOfWork> getPoW(ByteArray payload){
        byte[] pubKeyHash = DigestUtil.hash(payload.getBytes());
        ProofOfWorkService pows = new EquihashProofOfWorkService(persistenceService);
        //(byte[] payload, @Nullable byte[] challenge, double difficulty)
        ProofOfWork pow = null;
        try {
            pow = (pows.mint(pubKeyHash, null, 65536.0)).get();
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return Optional.of(pow);
    }

    /**
     * 
     */
    @Override
    public void shutdown() {

    }
}
