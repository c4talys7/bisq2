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

package bisq.wallets.electrum;

import bisq.common.util.NetworkUtils;
import bisq.wallets.bitcoind.rpc.BitcoindWallet;
import bisq.wallets.core.model.AddressType;
import bisq.wallets.electrum.notifications.ElectrumNotifyApi;
import bisq.wallets.electrum.notifications.ElectrumNotifyWebServer;
import bisq.wallets.electrum.regtest.ElectrumExtension;
import bisq.wallets.electrum.regtest.electrum.ElectrumRegtestSetup;
import bisq.wallets.electrum.regtest.electrum.MacLinuxElectrumRegtestSetup;
import bisq.wallets.electrum.rpc.ElectrumDaemon;
import bisq.wallets.electrum.rpc.responses.*;
import bisq.wallets.regtest.bitcoind.RemoteBitcoind;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(ElectrumExtension.class)
public class ElectrumTxAndPasswordIntegrationTests {


    private final RemoteBitcoind remoteBitcoind;
    private final ElectrumRegtestSetup electrumRegtestSetup;
    private ElectrumDaemon electrumDaemon;

    private String fundingAddress;
    private String fundingTxId;

    public ElectrumTxAndPasswordIntegrationTests(RemoteBitcoind remoteBitcoind,
                                                 ElectrumRegtestSetup electrumRegtestSetup) {
        this.remoteBitcoind = remoteBitcoind;
        this.electrumRegtestSetup = electrumRegtestSetup;
    }

    @BeforeEach
    void setUp() {
        electrumDaemon = electrumRegtestSetup.getElectrumDaemon();
    }

    @Test
    void changePasswordTest() {
        String expectedSeed = electrumDaemon.getSeed(MacLinuxElectrumRegtestSetup.WALLET_PASSPHRASE);

        String newPassword = "My new password.";
        electrumDaemon.password(MacLinuxElectrumRegtestSetup.WALLET_PASSPHRASE, newPassword);

        String seed = electrumDaemon.getSeed(newPassword);
        assertThat(seed).isEqualTo(expectedSeed);

        // Change back otherwise other tests could fail.
        electrumDaemon.password(newPassword, MacLinuxElectrumRegtestSetup.WALLET_PASSPHRASE);
    }

    @Test
    void listUnspentGetTxAndHistoryTest() throws InterruptedException {
        fundElectrumWallet();

        // UTXO
        List<ElectrumListUnspentResponseEntry> unspentResponseEntries = electrumDaemon.listUnspent();
        assertThat(unspentResponseEntries).hasSize(1);

        ElectrumListUnspentResponseEntry firstEntry = unspentResponseEntries.get(0);
        assertThat(firstEntry.getAddress()).isEqualTo(fundingAddress);
        assertThat(firstEntry.getValue()).isEqualTo("10");

        // Transaction
        String tx = electrumDaemon.getTransaction(fundingTxId);
        ElectrumDeserializeResponse deserializedTx = electrumDaemon.deserialize(tx);
        ElectrumDeserializeOutputResponse[] outputs = deserializedTx.getOutputs();

        assertThat(outputs).hasSize(2);

        boolean hasFundingAddress = false;
        for (ElectrumDeserializeOutputResponse o : outputs) {
            if (o.getAddress().equals(fundingAddress) && o.getValueSats() == 1_000_000_000) {
                hasFundingAddress = true;
                break;
            }
        }
        assertThat(hasFundingAddress).isTrue();

        // OnChainHistory
        ElectrumOnChainHistoryResponse electrumOnChainHistoryResponse = electrumDaemon.onChainHistory();
        List<ElectrumOnChainTransactionResponse> transactions = electrumOnChainHistoryResponse.getTransactions();
        boolean foundFundingTxInHistory = false;
        for (ElectrumOnChainTransactionResponse t : transactions) {
            if (t.getTxId().equals(fundingTxId)) {
                foundFundingTxInHistory = true;
                assertThat(t.getBcBalance()).isEqualTo("10.");
                assertThat(t.getBcValue()).isEqualTo("10.");
                assertThat(t.getConfirmations()).isEqualTo(1);
            }
        }
        assertThat(foundFundingTxInHistory).isTrue();
    }

    private void fundElectrumWallet() throws InterruptedException {
        var electrumProcessedTxLatch = new CountDownLatch(1);
        ElectrumNotifyApi.registerListener((address, status) -> {
            if (status != null) {
                electrumProcessedTxLatch.countDown();
            }
        });

        int freePort = NetworkUtils.findFreeSystemPort();
        ElectrumNotifyWebServer electrumNotifyWebServer = new ElectrumNotifyWebServer(freePort);
        electrumNotifyWebServer.startServer();

        fundingAddress = electrumDaemon.getUnusedAddress();
        electrumDaemon.notify(fundingAddress, electrumNotifyWebServer.getNotifyEndpointUrl());

        fundingTxId = electrumRegtestSetup.fundAddress(fundingAddress, 10);

        // Wait until electrum sees transaction
        boolean isSuccess = electrumProcessedTxLatch.await(30, TimeUnit.SECONDS);
        assertThat(isSuccess).isTrue();

        BitcoindWallet minerWallet = remoteBitcoind.getMinerWallet();
        String receiverAddress = minerWallet.getNewAddress(AddressType.BECH32, "");

        String unsignedTx = electrumDaemon.payTo(MacLinuxElectrumRegtestSetup.WALLET_PASSPHRASE, receiverAddress, 5);
        String signedTx = electrumDaemon.signTransaction(MacLinuxElectrumRegtestSetup.WALLET_PASSPHRASE, unsignedTx);

        electrumDaemon.broadcast(signedTx);
        electrumNotifyWebServer.stopServer();
    }
}
