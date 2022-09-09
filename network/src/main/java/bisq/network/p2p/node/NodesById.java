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

package bisq.network.p2p.node;


import bisq.common.data.ByteArray;
import bisq.common.util.CompletableFutureUtils;
import bisq.network.p2p.message.NetworkMessage;
import bisq.network.p2p.services.peergroup.BanList;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Maintains a map with nodes by nodeId.
 * Provides delegate methods to node with given nodeId
 */
public class NodesById implements Node.Listener {
    public interface Listener {
        void onNodeAdded(Node node);

        default void onNodeRemoved(Node node) {
        }
    }

    private final Map<String, Node> map = new ConcurrentHashMap<>();
    private final BanList banList;
    private final Node.Config nodeConfig;
    private final Set<Listener> listeners = new CopyOnWriteArraySet<>();
    private final Set<Node.Listener> nodeListeners = new CopyOnWriteArraySet<>();
    private final ByteArray payload;

    public NodesById(BanList banList, Node.Config nodeConfig, ByteArray payload) {
        this.banList = banList;
        this.nodeConfig = nodeConfig;
        this.payload = payload;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // API
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    public void initialize(String nodeId, int serverPort) {
        getOrCreateNode(nodeId).initialize(serverPort);
    }

    public Connection getConnection(String nodeId, Address address) {
        return getOrCreateNode(nodeId).getConnection(address);
    }

    public Connection send(String senderNodeId, NetworkMessage networkMessage, Address address) {
        return getOrCreateNode(senderNodeId).send(networkMessage, address);
    }

    public Connection send(String senderNodeId, NetworkMessage networkMessage, Connection connection) {
        return getOrCreateNode(senderNodeId).send(networkMessage, connection);
    }

    public CompletableFuture<Boolean> shutdown() {
        Stream<CompletableFuture<Boolean>> futures = map.values().stream().map(Node::shutdown);
        return CompletableFutureUtils.allOf(futures)
                .orTimeout(10, TimeUnit.SECONDS)
                .handle((list, throwable) -> {
                    map.clear();
                    listeners.clear();
                    nodeListeners.clear();
                    return throwable == null && list.stream().allMatch(e -> e);
                });
    }

    public Node getOrCreateDefaultNode() {
        return getOrCreateNode(Node.DEFAULT);
    }

    public boolean isNodeInitialized(String nodeId) {
        return findNode(nodeId)
                .map(Node::isInitialized)
                .orElse(false);
    }

    public void assertNodeIsInitialized(String nodeId) {
        checkArgument(isNodeInitialized(nodeId), "Node must be present and initialized");
    }

    public Optional<Address> findMyAddress(String nodeId) {
        return findNode(nodeId).flatMap(Node::findMyAddress);
    }

    public Optional<Node> findNode(String nodeId) {
        return Optional.ofNullable(map.get(nodeId));
    }

    public Collection<Node> getAllNodes() {
        return map.values();
    }

    /**
     * @return Addresses of nodes which have completed creating the server (e.g. hidden service is published).
     * Before the server creation is complete we do not know our address.
     */
    public Map<String, Address> getAddressesByNodeId() {
        //noinspection OptionalGetWithoutIsPresent
        return map.entrySet().stream()
                .filter(e -> e.getValue().findMyAddress().isPresent())
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().findMyAddress().get()));
    }

    public void addNodeListener(Node.Listener listener) {
        nodeListeners.add(listener);
    }

    public void removeNodeListener(Node.Listener listener) {
        nodeListeners.remove(listener);
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Node.Listener
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onMessage(NetworkMessage networkMessage, Connection connection, String nodeId) {
        nodeListeners.forEach(listener -> listener.onMessage(networkMessage, connection, nodeId));
    }

    @Override
    public void onConnection(Connection connection) {
    }

    @Override
    public void onDisconnect(Connection connection, CloseReason closeReason) {
    }

    @Override
    public void onShutdown(Node node) {
        map.remove(node.getNodeId());
        node.removeListener(this);
        listeners.forEach(listener -> listener.onNodeRemoved(node));
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Private
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    private Node getOrCreateNode(String nodeId) {
        return findNode(nodeId)
                .orElseGet(() -> {
                    Node node = new Node(banList, nodeConfig, nodeId, payload);
                    map.put(nodeId, node);
                    node.addListener(this);
                    listeners.forEach(listener -> listener.onNodeAdded(node));
                    return node;
                });
    }
}




