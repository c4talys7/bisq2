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

package bisq.chat.discuss.pub;

import bisq.chat.channel.PublicChannelService;
import bisq.chat.message.Quotation;
import bisq.common.observable.ObservableArray;
import bisq.network.NetworkService;
import bisq.network.p2p.services.data.storage.DistributedData;
import bisq.network.p2p.services.data.storage.auth.AuthenticatedData;
import bisq.persistence.Persistence;
import bisq.persistence.PersistenceService;
import bisq.user.identity.UserIdentityService;
import bisq.user.profile.UserProfile;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.Optional;

@Slf4j
public class PublicDiscussionChannelService extends PublicChannelService<PublicDiscussionChatMessage, PublicDiscussionChannel, PublicDiscussionChannelStore> {
    @Getter
    private final PublicDiscussionChannelStore persistableStore = new PublicDiscussionChannelStore();
    @Getter
    private final Persistence<PublicDiscussionChannelStore> persistence;

    public PublicDiscussionChannelService(PersistenceService persistenceService,
                                          NetworkService networkService,
                                          UserIdentityService userIdentityService) {
        super(networkService, userIdentityService);

        persistence = persistenceService.getOrCreatePersistence(this, persistableStore);
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // DataService.Listener
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onAuthenticatedDataAdded(AuthenticatedData authenticatedData) {
        DistributedData distributedData = authenticatedData.getDistributedData();
        if (distributedData instanceof PublicDiscussionChatMessage) {
            processAddedMessage((PublicDiscussionChatMessage) distributedData);
        }
    }

    @Override
    public void onAuthenticatedDataRemoved(AuthenticatedData authenticatedData) {
        DistributedData distributedData = authenticatedData.getDistributedData();
        if (distributedData instanceof PublicDiscussionChatMessage) {
            processRemovedMessage((PublicDiscussionChatMessage) distributedData);
        }
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // PublicChannelService 
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public ObservableArray<PublicDiscussionChannel> getChannels() {
        return persistableStore.getChannels();
    }

    @Override
    protected PublicDiscussionChatMessage createNewChatMessage(String text,
                                                               Optional<Quotation> quotedMessage,
                                                               PublicDiscussionChannel publicChannel,
                                                               UserProfile userProfile) {
        return new PublicDiscussionChatMessage(publicChannel.getId(),
                userProfile.getId(),
                text,
                quotedMessage,
                new Date().getTime(),
                false);
    }

    @Override
    protected PublicDiscussionChatMessage createNewChatMessage(PublicDiscussionChatMessage originalChatMessage,
                                                               String editedText,
                                                               UserProfile userProfile) {
        return new PublicDiscussionChatMessage(originalChatMessage.getChannelId(),
                userProfile.getId(),
                editedText,
                originalChatMessage.getQuotation(),
                originalChatMessage.getDate(),
                true);
    }

    @Override
    protected void maybeAddDefaultChannels() {
        if (!getChannels().isEmpty()) {
            return;
        }
        PublicDiscussionChannel defaultDiscussionChannel = new PublicDiscussionChannel("bisq");
        ObservableArray<PublicDiscussionChannel> channels = getChannels();
        channels.add(defaultDiscussionChannel);
        channels.add(new PublicDiscussionChannel("bitcoin"));
        channels.add(new PublicDiscussionChannel("monero"));
        channels.add(new PublicDiscussionChannel("markets"));
        channels.add(new PublicDiscussionChannel("economy"));
        channels.add(new PublicDiscussionChannel("offTopic"));
        persist();
    }
}