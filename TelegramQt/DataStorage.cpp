/*
   Copyright (C) 2018 Alexander Akulich <akulichalexander@gmail.com>

   This file is a part of TelegramQt library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

 */

#include "DataStorage_p.hpp"

#include "ApiUtils.hpp"
#include "RandomGenerator.hpp"
#include "TLTypesDebug.hpp"
#include "Debug_p.hpp"

#include "TelegramNamespace_p.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <QLoggingCategory>

namespace Telegram {

namespace Client {

/*!
    \class Telegram::Client::DataStorage
    \brief Provides public API to get data.

    \inmodule TelegramQt
    \ingroup Client

    \sa AccountStorage
*/

DataStorage::DataStorage(QObject *parent) :
    DataStorage(new DataStoragePrivate(), parent)
{
}

DcConfiguration DataStorage::serverConfiguration() const
{
    Q_D(const DataStorage);
    return d->m_serverConfig;
}

void DataStorage::setServerConfiguration(const DcConfiguration &configuration)
{
    Q_D(DataStorage);
    d->m_serverConfig = configuration;
}

QVector<Peer> DataStorage::dialogs() const
{
    Q_D(const DataStorage);
    QVector<Peer> result;
    result.reserve(d->m_api->dialogs().count());
    for (const UserDialog *dialog : d->m_api->dialogs()) {
        result.append(dialog->peer);
    }
    return result;
}

QVector<Peer> DataStorage::pinnedDialogs() const
{
    Q_D(const DataStorage);
    return d->m_api->pinnedDialogs();
}

QVector<Peer> DataStorage::contactList() const
{
    Q_D(const DataStorage);
    const TLVector<TLContact> contacts = d->m_api->contactList();
    QVector<Peer> result;
    result.reserve(contacts.count());
    for (const TLContact &contact : contacts) {
        result.append(Peer::fromUserId(contact.userId));
    }
    return result;
}

quint32 DataStorage::selfUserId() const
{
    Q_D(const DataStorage);
    return d->m_api->selfUserId();
}

bool DataStorage::getDialogInfo(DialogInfo *info, const Peer &peer) const
{
    Q_D(const DataStorage);
    for (const UserDialog *dialog : d->m_api->dialogs()) {
        if (dialog->peer == peer) {
            UserDialog *infoData = Telegram::DialogInfo::Private::get(info);
            *infoData = *dialog;
            return true;
        }
    }
    qDebug() << Q_FUNC_INFO << "Unknown dialog" << peer.toString();
    return false;
}

bool DataStorage::getUserInfo(UserInfo *info, quint32 userId) const
{
    Q_D(const DataStorage);
    const QHash<quint32, TLUser *> &users = d->m_api->users();
    if (!users.contains(userId)) {
        qDebug() << Q_FUNC_INFO << "Unknown user" << userId;
        return false;
    }

    const TLUser *user = users.value(userId);
    TLUser *infoData = Telegram::UserInfo::Private::get(info);
    *infoData = *user;
    return true;
}

bool DataStorage::getChatInfo(ChatInfo *info, const Telegram::Peer &peer) const
{
    Q_D(const DataStorage);
    const quint32 chatId = peer.id;
    const QHash<quint32, TLChat *> &chats = d->m_api->chats();
    if (!chats.contains(chatId)) {
        qDebug() << Q_FUNC_INFO << "Unknown chat" << chatId;
        return false;
    }

    const TLChat *chat = chats.value(chatId);
    TLChat *infoData = Telegram::ChatInfo::Private::get(info);
    *infoData = *chat;
    return true;
}

bool DataStorage::getMessage(Message *message, const Peer &peer, quint32 messageId)
{
    Q_D(const DataStorage);
    const TLMessage *m = d->m_api->getMessage(peer, messageId);
    if (!m) {
        qDebug() << Q_FUNC_INFO << "Unknown message" << peer << messageId;
        return false;
    }
    const TLMessageMedia &media = m->media;

    message->setPeer(peer);
    message->id = messageId;
    message->type = Telegram::Utils::getPublicMessageType(media);
    message->fromId = m->fromId;
    message->timestamp = m->date;
    message->text = m->message;
    message->flags = TelegramNamespace::MessageFlagNone;
    if (m->out()) {
        message->flags |= TelegramNamespace::MessageFlagOut;
    }
    if (m->flags & TLMessage::FwdFrom) {
        message->flags |= TelegramNamespace::MessageFlagForwarded;
        if (m->fwdFrom.flags & TLMessageFwdHeader::FromId) {
            //message->setForwardFromPeer((m->fwdFrom))
        }
    }
    return true;
}

bool DataStorage::getMessageMediaInfo(MessageMediaInfo *info, const Peer &peer, quint32 messageId)
{
    Q_D(const DataStorage);
    const TLMessage *m = d->m_api->getMessage(peer, messageId);
    if (!m) {
        qDebug() << Q_FUNC_INFO << "Unknown message" << peer << messageId;
        return false;
    }
    const TLMessageMedia &media = m->media;

    MessageMediaInfo::Private *privateInfo = MessageMediaInfo::Private::get(info);
    *privateInfo = media;
    return true;
}

bool DataStorage::getNotificationSettings(NotificationSettings *settings, const Peer &peer) const
{
    return true;
}

DataStorage::DataStorage(DataStoragePrivate *priv, QObject *parent)
    : QObject(parent),
      d(priv)
{
    d->m_api = new DataInternalApi(this);
}

InMemoryDataStorage::InMemoryDataStorage(QObject *parent) :
    DataStorage(parent)
{
}

QByteArray InMemoryDataStorage::saveState() const
{
    Q_D(const DataStorage);

    QJsonArray dialogArray;
    qDebug() << "Dialogs to save:";
    const QHash<Peer, DialogState> *dialogState = d->internalApi()->dialogStates();

    for (const Peer &dialog : dialogState->keys()) {
        DialogState state = dialogState->value(dialog);
        qWarning() << "dialog:" << dialog.toString() << "last message id:" << state.syncedMessageId;
        QJsonObject dialogObject;
        dialogObject[QLatin1String("peer")] = dialog.toString();
        dialogObject[QLatin1String("lastMessageId")] = static_cast<int>(state.syncedMessageId);
        dialogArray.append(dialogObject);
    }
    QJsonObject root;
    root[QLatin1String("version")] = 1;
    root[QLatin1String("dialogs")] = dialogArray;
    return QJsonDocument(root).toJson();
}

void InMemoryDataStorage::loadState(const QByteArray &data)
{
    Q_D(DataStorage);
    QHash<Peer, DialogState> *dialogState = d->internalApi()->dialogStates();
    dialogState->clear();

    // m_syncFinished = false;

    const QJsonObject root = QJsonDocument::fromJson(data).object();
    const QJsonArray dialogArray = root.value(QLatin1String("dialogs")).toArray();
    for (const QJsonValue &dialogValue : dialogArray) {
        const QJsonObject dialogObject = dialogValue.toObject();
        const Telegram::Peer peer = Telegram::Peer::fromString(dialogObject.value(QLatin1String("peer")).toString());
        if (!peer.isValid()) {
            qWarning() << Q_FUNC_INFO << "Invalid dialog peer:" << dialogObject.value(QLatin1String("peer"));
            continue;
        }
        DialogState state;
        state.syncedMessageId = static_cast<quint32>(dialogObject.value(QLatin1String("lastMessageId")).toInt());
        dialogState->insert(peer, state);
    }

    qDebug() << "Loaded dialogs:";
    for (const Telegram::Peer &dialog : dialogState->keys()) {
        DialogState state = dialogState->value(dialog);
        qDebug() << "dialog:" << dialog.toString() << "last message id:" << state.syncedMessageId;
    }
}

DataInternalApi::DataInternalApi(QObject *parent) :
    QObject(parent)
{
}

DataInternalApi::~DataInternalApi()
{
}

const TLUser *DataInternalApi::getSelfUser() const
{
    if (!m_selfUserId) {
        return nullptr;
    }
    return m_users.value(m_selfUserId);
}

const TLMessage *DataInternalApi::getMessage(const Peer &peer, quint32 messageId) const
{
    if (peer.type == Peer::Channel) {
        quint64 key = DataInternalApi::channelMessageToKey(peer.id, messageId);
        return m_channelMessages.value(key);
    }
    return m_clientMessages.value(messageId);
}

/*!

   Returns \c true if the message is actually a new one.
*/
bool DataInternalApi::processNewMessage(const TLMessage &message, quint32 pts)
{
    processData(message);

    const Peer dialogPeer = Utils::getMessageDialogPeer(message, selfUserId());
    UserDialog *dialog = ensureDialog(dialogPeer);
    if (dialog->topMessage < message.id) {
        dialog->topMessage = message.id;
        dialog->date = message.date;
    }
    if (dialog->pts < pts) {
        dialog->pts = pts;
    }
    ++dialog->unreadCount;

    updateDialogsOrder();

    return true;
}

void DataInternalApi::processPinnedDialogs(const TLVector<TLDialog> &dialogs)
{
    m_pinnedDialogs.clear();
    for (const TLDialog &dialog : dialogs) {
        if (dialog.pinned()) {
            m_pinnedDialogs.append(Telegram::Utils::toPublicPeer(dialog.peer));
        }
    }
}

void DataInternalApi::processData(const TLMessage &message)
{
    TLMessage *m = nullptr;
    if (message.toId.tlType == TLValue::PeerChannel) {
        const quint64 key = channelMessageToKey(message.toId.channelId, message.id);
        if (!m_channelMessages.contains(key)) {
            m_channelMessages.insert(key, new TLMessage());
        }
        m = m_channelMessages.value(key);
    } else {
        const quint32 key = message.id;
        if (!m_clientMessages.contains(key)) {
            m_clientMessages.insert(key, new TLMessage());
        }
        m = m_clientMessages.value(key);
    }
    *m = message;
}

void DataInternalApi::processData(const TLVector<TLChat> &chats)
{
    for (const TLChat &chat : chats) {
        processData(chat);
    }
}

void DataInternalApi::processData(const TLChat &chat)
{
    if (!m_chats.contains(chat.id)) {
        TLChat *newChatInstance = new TLChat(chat);
        m_chats.insert(chat.id, newChatInstance);
    } else {
        return;
        TLChat *existsChat = m_chats[chat.id];
        *existsChat = chat;
    }
}

void DataInternalApi::processData(const TLVector<TLUser> &users)
{
    for (const TLUser &user : users) {
        processData(user);
    }
}

void DataInternalApi::processData(const TLUser &user)
{
    TLUser *existsUser = m_users.value(user.id);
    if (existsUser) {
        *existsUser = user;
    } else {
        m_users.insert(user.id, new TLUser(user));
    }
    if (user.self()) {
        if (m_selfUserId && (m_selfUserId != user.id)) {
            qWarning() << "Got self user with different id.";
        }
        m_selfUserId = user.id;
    }
}

void DataInternalApi::processData(const TLAuthAuthorization &authorization)
{
    processData(authorization.user);
}

void DataInternalApi::processData(const TLMessagesDialogs &dialogs)
{
    if (m_dialogs.isEmpty()) {
        m_dialogs.reserve(dialogs.count);
    }
    processData(dialogs.users);
    processData(dialogs.chats);
    for (const TLMessage &message : dialogs.messages) {
        processData(message);
    }
    for (const TLDialog &tlDialog : dialogs.dialogs) {
        Peer peer = Utils::toPublicPeer(tlDialog.peer);
        UserDialog *dialog = ensureDialog(peer);

        dialog->readInboxMaxId = tlDialog.readInboxMaxId;
        dialog->readOutboxMaxId = tlDialog.readOutboxMaxId;
        dialog->unreadCount = tlDialog.unreadCount;
        dialog->unreadMentionsCount = tlDialog.unreadMentionsCount;
        dialog->pts = tlDialog.pts;
        dialog->draftText = tlDialog.draft.message;
        dialog->flags = tlDialog.flags;

        NotificationSettingsData settings;
        settings.flags = tlDialog.notifySettings.flags;
        settings.muteUntil = tlDialog.notifySettings.muteUntil;
        settings.sound = tlDialog.notifySettings.sound;
        setNotificationSettings(peer, settings);

        const TLMessage *message = getMessage(peer, tlDialog.topMessage);
        if (message) {
            dialog->topMessage = message->id;
            dialog->date = message->date;
        }
    }
    updateDialogsOrder();
}

void DataInternalApi::processData(const TLMessagesMessages &messages)
{
    processData(messages.users);
    processData(messages.chats);
    for (const TLMessage &message : messages.messages) {
        processData(message);
    }
}

void DataInternalApi::setContactList(const TLVector<TLContact> &contacts)
{
    m_contactList = contacts;
}

quint64 DataInternalApi::enqueueMessage(const Telegram::Peer peer, const QString &message, quint32 replyToMsgId)
{
    SentMessage sentMessage;
    sentMessage.peer = peer;
    sentMessage.text = message;
    sentMessage.replyToMsgId = replyToMsgId;
    sentMessage.randomId = RandomGenerator::instance()->generate<quint64>();
    m_queuedMessages.append(sentMessage);
    return sentMessage.randomId;
}

DataInternalApi::SentMessage DataInternalApi::getQueuedMessage(quint64 randomMessageId) const
{
    for (const SentMessage &message : m_queuedMessages) {
        if (message.randomId == randomMessageId) {
            return message;
        }
    }
    return SentMessage();
}

DataInternalApi::SentMessage DataInternalApi::dequeueMessage(quint64 messageRandomId, quint32 messageId)
{
    if (m_queuedMessages.isEmpty()) {
        qWarning() << Q_FUNC_INFO << "Invalid dequeue request (message queue is empty):" << messageRandomId << messageId;
        return SentMessage();
    }
    if (m_queuedMessages.head().randomId == messageRandomId) {
        return m_queuedMessages.dequeue();
    }
    for (int i = 0; i < m_queuedMessages.count(); ++i) {
        if (m_queuedMessages.at(i).randomId == messageRandomId) {
            return m_queuedMessages.takeAt(i);
        }
    }
    qWarning() << Q_FUNC_INFO << "Invalid dequeue request (message not found):" << messageRandomId << messageId;
    return SentMessage();
}

/*!
  \fn void DataInternalApi::enqueueMessageRead(const Peer peer, quint32 messageId)

  Save in local storage that the dialog with \a peer is read up to \a messageId
*/
void DataInternalApi::enqueueMessageRead(const Peer peer, quint32 messageId)
{

}

void DataInternalApi::dequeueMessageRead(const Peer peer, quint32 messageId)
{
    updateInboxRead(peer, messageId);
}

/*!

    Returns \c true if the dialog read status is actually changed.
*/
bool DataInternalApi::updateInboxRead(const Telegram::Peer peer, quint32 messageId)
{
    return true;
}

/*!

    Returns \c true if the dialog read status is actually changed.
*/
bool DataInternalApi::updateOutboxRead(const Telegram::Peer peer, quint32 messageId)
{
    return true;
}

TLInputPeer DataInternalApi::toInputPeer(const TLPeer &peer) const
{
    return toInputPeer(Utils::toPublicPeer(peer));
}

TLInputPeer DataInternalApi::toInputPeer(const Peer &peer) const
{
    TLInputPeer inputPeer;
    switch (peer.type) {
    case Telegram::Peer::Chat:
        inputPeer.tlType = TLValue::InputPeerChat;
        inputPeer.chatId = peer.id;
        break;
    case Telegram::Peer::Channel:
        if (m_chats.contains(peer.id)) {
            inputPeer.tlType = TLValue::InputPeerChannel;
            inputPeer.channelId = peer.id;
            inputPeer.accessHash = m_chats.value(peer.id)->accessHash;
        } else {
            qWarning() << Q_FUNC_INFO << "Unknown public channel id" << peer.id;
        }
        break;
    case Telegram::Peer::User:
        if (peer.id == m_selfUserId) {
            inputPeer.tlType = TLValue::InputPeerSelf;
        } else {
            if (m_users.contains(peer.id)) {
                inputPeer.tlType = TLValue::InputPeerUser;
                inputPeer.userId = peer.id;
                inputPeer.accessHash = m_users.value(peer.id)->accessHash;
            } else {
                qWarning() << Q_FUNC_INFO << "Unknown user" << peer.id;
            }
        }
        break;
    }
    return inputPeer;
}

TLInputUser DataInternalApi::toInputUser(quint32 userId) const
{
    TLInputUser inputUser;
    if (userId == selfUserId()) {
        inputUser.tlType = TLValue::InputUserSelf;
        return inputUser;
    }
    const TLUser *user = m_users.value(userId);
    if (user) {
        if (user->tlType == TLValue::User) {
            inputUser.tlType = TLValue::InputUser;
            inputUser.userId = user->id;
            inputUser.accessHash = user->accessHash;
        } else {
            qWarning() << Q_FUNC_INFO << "Unknown user type: " << QString::number(user->tlType, 16);
        }
    } else {
        qWarning() << Q_FUNC_INFO << "Unknown user" << userId;
    }
    return inputUser;
}

TLInputChannel DataInternalApi::toInputChannel(quint32 channelId) const
{
    TLInputChannel inputChannel;
    const TLChat *channel = m_chats.value(channelId);
    if (channel) {
        inputChannel.tlType = TLValue::InputChannel;
        inputChannel.channelId = channelId;
        inputChannel.accessHash = channel->accessHash;
    } else {
        qWarning() << Q_FUNC_INFO << "Unknown channel" << channelId;
        inputChannel.tlType = TLValue::InputChannelEmpty;
    }
    return inputChannel;
}

quint64 DataInternalApi::channelMessageToKey(quint32 channelId, quint32 messageId)
{
    quint64 key = channelId;
    return (key << 32) + messageId;
}

UserDialog *DataInternalApi::getDialog(const Peer &peer) const
{
    for (UserDialog *dialog : m_dialogs) {
        if (dialog->peer == peer) {
            return dialog;
        }
    }
    return nullptr;
}

UserDialog *DataInternalApi::ensureDialog(const Peer &peer)
{
    UserDialog *dialog = getDialog(peer);
    if (!dialog) {
        dialog = new UserDialog();
        qWarning() << Q_FUNC_INFO << "New dialog for peer" << peer;
        dialog->peer = peer;
        m_dialogs.append(dialog);
    }
    return dialog;
}

const NotificationSettingsData *DataInternalApi::getNotificationSettings(const Peer &peer)
{
    const NotificationSettingsData *result = m_notificationSettings.value(peer);
    if (!result) {
        return NotificationSettingsData::getDefaultSettingsData();
    }
    return result;
}

void DataInternalApi::setNotificationSettings(const Peer &peer, const NotificationSettingsData &settings)
{
    if (!m_notificationSettings.contains(peer)) {
        m_notificationSettings.insert(peer, new NotificationSettingsData(settings));
    } else {
        *m_notificationSettings[peer] = settings;
    }
}

DialogState *DataInternalApi::ensureDialogState(const Peer peer)
{
    if (!m_dialogStates.contains(peer)) {
        qDebug() << CALL_INFO << "New dialog" << peer;
        m_dialogStates.insert(peer, DialogState());
    }
    return &m_dialogStates[peer];
}

const DialogState DataInternalApi::getDialogState(const Peer peer) const
{
    return m_dialogStates.value(peer);
}

void DataInternalApi::updateDialogsOrder()
{
    std::sort(m_dialogs.begin(), m_dialogs.end(), [](const UserDialog *left, const UserDialog *right) -> bool {
        // return true if the first arg should be placed before the second one
        return left->date > right->date;
    });
}

DataStoragePrivate *DataStoragePrivate::get(DataStorage *parent)
{
    return parent->d;
}

} // Client namespace

} // Telegram namespace
