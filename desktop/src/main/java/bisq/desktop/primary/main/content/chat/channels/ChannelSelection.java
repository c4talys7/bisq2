package bisq.desktop.primary.main.content.chat.channels;

import bisq.chat.ChatService;
import bisq.chat.channel.Channel;
import bisq.chat.channel.PrivateChannel;
import bisq.chat.discuss.pub.PublicDiscussionChannel;
import bisq.chat.events.pub.PublicEventsChannel;
import bisq.chat.support.pub.PublicSupportChannel;
import bisq.chat.trade.priv.PrivateTradeChannel;
import bisq.chat.trade.pub.PublicTradeChannel;
import bisq.common.observable.Pin;
import bisq.desktop.common.threading.UIThread;
import bisq.desktop.common.utils.Layout;
import bisq.desktop.components.containers.Spacer;
import bisq.user.identity.UserIdentityService;
import javafx.beans.InvalidationListener;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;

import javax.annotation.Nullable;

@Slf4j
public abstract class ChannelSelection {
    protected static abstract class Controller implements bisq.desktop.common.view.Controller {
        protected final ChatService chatService;

        protected Pin selectedChannelPin;
        protected Pin channelsPin;

        protected Controller(ChatService chatService) {
            this.chatService = chatService;
        }

        @Override
        public void onActivate() {
        }

        protected abstract Model getChannelSelectionModel();

        @Override
        public void onDeactivate() {
            selectedChannelPin.unbind();
            if (channelsPin != null) {
                channelsPin.unbind();
            }
        }

        abstract protected void onSelected(View.ChannelItem channelItem);
    }


    protected static class Model implements bisq.desktop.common.view.Model {
        ObjectProperty<View.ChannelItem> selectedChannelItem = new SimpleObjectProperty<>();
        View.ChannelItem previousSelectedChannelItem;
        ObservableList<View.ChannelItem> channelItems = FXCollections.observableArrayList();
        FilteredList<View.ChannelItem> filteredList = new FilteredList<>(channelItems);
        SortedList<View.ChannelItem> sortedList = new SortedList<>(filteredList);

        public Model() {
        }
    }

    @Slf4j
    public static abstract class View<M extends ChannelSelection.Model, C extends ChannelSelection.Controller> extends bisq.desktop.common.view.View<AnchorPane, M, C> {
        protected final ListView<ChannelItem> listView;
        private final InvalidationListener channelsChangedListener;
        protected final HBox headerBox;
        protected Subscription listViewSelectedChannelSubscription, modelSelectedChannelSubscription;
        protected int adjustHeightCounter = 0;

        protected View(M model, C controller) {
            super(new AnchorPane(), model, controller);

            Label headline = new Label(getHeadlineText());
            headline.getStyleClass().add("bisq-text-8");
            HBox.setMargin(headline, new Insets(26, 0, 10, 22));

            // subclasses add settings icon, so we put it into a box
            headerBox = new HBox(20, headline, Spacer.fillHBox());
            headerBox.setMinHeight(54);

            listView = new ListView<>(model.sortedList);
            listView.getStyleClass().add("channel-selection-list-view");
            listView.setFocusTraversable(false);
            listView.setCellFactory(p -> getListCell());

            VBox vBox = new VBox(10, headerBox, listView);
            Layout.pinToAnchorPane(vBox, 0, 0, 0, 0);
            root.getChildren().add(vBox);

            channelsChangedListener = observable -> adjustHeight();
        }

        protected abstract String getHeadlineText();

        @Override
        protected void onViewAttached() {
            listViewSelectedChannelSubscription = EasyBind.subscribe(listView.getSelectionModel().selectedItemProperty(),
                    channelItem -> {
                        if (channelItem != null) {
                            if (model.previousSelectedChannelItem != null) {
                                model.previousSelectedChannelItem.setSelected(false);
                            }
                            channelItem.setSelected(true);
                            model.previousSelectedChannelItem = channelItem;
                            controller.onSelected(channelItem);
                        }
                    });
            modelSelectedChannelSubscription = EasyBind.subscribe(model.selectedChannelItem,
                    channelItem -> {
                        if (channelItem == null) {
                            listView.getSelectionModel().clearSelection();
                        } else if (!channelItem.equals(listView.getSelectionModel().getSelectedItem())) {
                            if (model.previousSelectedChannelItem != null) {
                                model.previousSelectedChannelItem.setSelected(false);
                            }
                            channelItem.setSelected(true);
                            model.previousSelectedChannelItem = channelItem;
                            listView.getSelectionModel().select(channelItem);
                        }
                    });
            model.sortedList.addListener(channelsChangedListener);

            adjustHeightCounter = 0;
            adjustHeight();
        }

        @Override
        protected void onViewDetached() {
            listViewSelectedChannelSubscription.unsubscribe();
            modelSelectedChannelSubscription.unsubscribe();
            model.sortedList.removeListener(channelsChangedListener);
        }

        protected abstract ListCell<ChannelItem> getListCell();

        private void adjustHeight() {
            adjustHeightCounter++;
            UIThread.runOnNextRenderFrame(() -> {
                Node lookupNode = listView.lookup(".list-cell");
                if (lookupNode instanceof ListCell) {
                    //noinspection rawtypes
                    double height = ((ListCell) lookupNode).getHeight();
                    listView.setPrefHeight(height * listView.getItems().size() + 10);
                    adjustHeightCounter = 10;
                } else {
                    if (!listView.getItems().isEmpty() && adjustHeightCounter < 10) {
                        UIThread.run(this::adjustHeight);
                    }
                }
            });
        }

        protected void initCell(ListCell<ChannelItem> cell, Label label, ImageView iconImageView, HBox hBox) {
            cell.setCursor(Cursor.HAND);
            cell.setPrefHeight(40);
            cell.setPadding(new Insets(0, 0, -20, 0));
            cell.setPadding(new Insets(0, 0, -20, 0));
            label.setGraphic(iconImageView);
            label.setGraphicTextGap(8);
            hBox.setSpacing(10);
            hBox.setAlignment(Pos.CENTER_LEFT);
            hBox.getChildren().add(label);
        }

        protected void updateCell(ListCell<ChannelItem> cell, ChannelItem item, Label label, ImageView iconImageView) {
            label.setText(item.getDisplayString().toUpperCase());

            if (item.getIconId() != null) {
                if (item.isSelected) {
                    iconImageView.setId(item.iconIdSelected);
                } else {
                    iconImageView.setId(item.iconId);
                }

                cell.setOnMouseEntered(e -> {
                    if (!item.isSelected) {
                        iconImageView.setId(item.iconIdHover);
                    }
                });
                cell.setOnMouseExited(e -> {
                    if (item.isSelected) {
                        iconImageView.setId(item.iconIdSelected);
                    } else {
                        iconImageView.setId(item.iconId);
                    }
                });

                cell.setOnMousePressed(e -> {
                    iconImageView.setId(item.iconIdSelected);
                });
                cell.setOnMouseReleased(e -> {
                    iconImageView.setId(item.iconIdSelected);
                });
            }
        }

        protected Subscription setupCellBinding(ListCell<ChannelItem> cell, ChannelItem item, Label label, ImageView iconImageView) {
            return EasyBind.subscribe(cell.widthProperty(), w -> {
                if (w.doubleValue() > 0) {
                    label.setMaxWidth(cell.getWidth() - 70);
                }
            });
        }

        @EqualsAndHashCode(onlyExplicitlyIncluded = true)
        @Getter
        static class ChannelItem {
            @EqualsAndHashCode.Include
            private final String id;
            private final Channel<?> channel;
            private final String displayString;
            private final boolean hasMultipleProfiles;
            private boolean mediationActivated;
            private String iconId;
            private String iconIdHover;
            private String iconIdSelected;

            private boolean isSelected;

            public ChannelItem(Channel<?> channel) {
                this(channel, null);
            }

            public ChannelItem(Channel<?> channel, @Nullable UserIdentityService userIdentityService) {
                this.channel = channel;
                hasMultipleProfiles = userIdentityService != null && userIdentityService.getUserIdentities().size() > 1;

                id = channel.getId();

                String type = null;
                if (channel instanceof PublicEventsChannel) {
                    type = "-events-";
                } else if (channel instanceof PublicDiscussionChannel) {
                    type = "-discussion-";
                } else if (channel instanceof PublicSupportChannel) {
                    type = "-support-";
                }
                if (type != null) {
                    iconIdSelected = "channels" + type + channel.getId();
                    iconIdHover = "channels" + type + channel.getId() + "-white";
                    iconId = "channels" + type + channel.getId() + "-grey";
                }


                if (channel instanceof PrivateChannel) {
                    PrivateChannel<?> privateChannel = (PrivateChannel<?>) channel;
                    String label = privateChannel.getPeer().getUserName();
                    if (channel instanceof PrivateTradeChannel) {
                        PrivateTradeChannel privateTradeChannel = (PrivateTradeChannel) channel;
                        mediationActivated = privateTradeChannel.getMediator().isPresent() && privateTradeChannel.getMediationActivated().get();
                        if (mediationActivated) {
                            label += ", " + privateTradeChannel.getMediator().get().getUserName();
                        }
                    }
                    if (hasMultipleProfiles) {
                        // If we have more than 1 user profiles we add our profile as well
                        label += " [" + privateChannel.getMyUserIdentity().getUserName() + "]";
                    }
                    displayString = label;
                } else if (channel instanceof PublicTradeChannel) {
                    displayString = ((PublicTradeChannel) channel).getMarket().getMarketCodes();
                } else {
                    displayString = channel.getDisplayString();
                }
            }

            public void setSelected(boolean selected) {
                isSelected = selected;
            }
        }
    }
}
