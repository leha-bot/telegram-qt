#include "TelegramServer.hpp"

#include <QLoggingCategory>
#include <QTcpServer>
#include <QTcpSocket>

#include <QJsonDocument>

#include <QFile>

#include "ApiUtils.hpp"
#include "TelegramServerUser.hpp"
#include "RemoteClientConnection.hpp"
#include "RemoteServerConnection.hpp"
#include "Session.hpp"

#include "CServerTcpTransport.hpp"

// Generated RPC Operation Factory includes
#include "AccountOperationFactory.hpp"
#include "AuthOperationFactory.hpp"
#include "BotsOperationFactory.hpp"
#include "ChannelsOperationFactory.hpp"
#include "ContactsOperationFactory.hpp"
#include "HelpOperationFactory.hpp"
#include "LangpackOperationFactory.hpp"
#include "MessagesOperationFactory.hpp"
#include "PaymentsOperationFactory.hpp"
#include "PhoneOperationFactory.hpp"
#include "PhotosOperationFactory.hpp"
#include "StickersOperationFactory.hpp"
#include "UpdatesOperationFactory.hpp"
#include "UploadOperationFactory.hpp"
#include "UsersOperationFactory.hpp"
// End of generated RPC Operation Factory includes

#include "ServerMessageData.hpp"
#include "ServerDhLayer.hpp"
#include "ServerRpcLayer.hpp"
#include "ServerUtils.hpp"
#include "Storage.hpp"
#include "Debug_p.hpp"
#include "Utils.hpp"

#include "TelegramJson_p.hpp"

Q_LOGGING_CATEGORY(loggingCategoryServer, "telegram.server.main", QtDebugMsg)
Q_LOGGING_CATEGORY(loggingCategoryServerApi, "telegram.server.api", QtDebugMsg)

QJsonValue toJsonValue(const Telegram::UserDialog &userDialog)
{
    QJsonObject dialogObject;
    dialogObject[QLatin1String("peer")] = toJsonValue(userDialog.peer);
    dialogObject[QLatin1String("pts")] = toJsonValue(userDialog.pts);
    dialogObject[QLatin1String("topMessage")] = toJsonValue(userDialog.topMessage);
    dialogObject[QLatin1String("date")] = toJsonValue(userDialog.date);
    dialogObject[QLatin1String("readInboxMaxId")] = toJsonValue(userDialog.readInboxMaxId);
    dialogObject[QLatin1String("readOutboxMaxId")] = toJsonValue(userDialog.readOutboxMaxId);
    dialogObject[QLatin1String("unreadCount")] = toJsonValue(userDialog.unreadCount);
    dialogObject[QLatin1String("unreadMentionsCount")] = toJsonValue(userDialog.unreadMentionsCount);
    dialogObject[QLatin1String("draftText")] = toJsonValue(userDialog.draftText);
    return dialogObject;
}

namespace Telegram {

namespace Server {

Server::Server(QObject *parent) :
    QObject(parent)
{
    m_rpcOperationFactories = {
        // Generated RPC Operation Factory initialization
        new AccountOperationFactory(),
        new AuthOperationFactory(),
        new BotsOperationFactory(),
        new ChannelsOperationFactory(),
        new ContactsOperationFactory(),
        new HelpOperationFactory(),
        new LangpackOperationFactory(),
        new MessagesOperationFactory(),
        new PaymentsOperationFactory(),
        new PhoneOperationFactory(),
        new PhotosOperationFactory(),
        new StickersOperationFactory(),
        new UpdatesOperationFactory(),
        new UploadOperationFactory(),
        new UsersOperationFactory(),
        // End of generated RPC Operation Factory initialization
    };
    m_serverSocket = new QTcpServer(this);
    connect(m_serverSocket, &QTcpServer::newConnection, this, &Server::onNewConnection);
}

Server::~Server()
{
    qDeleteAll(m_sessions);
    qDeleteAll(m_users);
    qDeleteAll(m_rpcOperationFactories);
}

void Server::setDcOption(const DcOption &option)
{
    m_dcOption = option;
}

void Server::setServerPrivateRsaKey(const Telegram::RsaKey &key)
{
    m_key = key;
}

bool Server::start()
{
    if (!m_dcOption.id) {
        qCCritical(loggingCategoryServer).noquote().nospace() << "Unable to start server: Invalid (null) DC id.";
        return false;
    }
    if (!m_serverSocket->listen(QHostAddress(m_dcOption.address), m_dcOption.port)) {
        qCCritical(loggingCategoryServer).noquote().nospace() << "Unable to listen port " << m_dcOption.port
                                                              << " ("  << m_serverSocket->serverError() << ")";
        return false;
    }
    qCInfo(loggingCategoryServer).nospace().noquote() << this << " start server (DC " << m_dcOption.id << ") "
                                                      << "on " << m_dcOption.address << ":" << m_dcOption.port
                                                      << "; Key:" << hex << showbase << m_key.fingerprint;
    return true;
}

void Server::stop()
{
    qCInfo(loggingCategoryServer).nospace().noquote() << this << " stop server (DC " << m_dcOption.id << ") "
                                                      << "on " << m_dcOption.address << ":" << m_dcOption.port;
    if (m_serverSocket) {
        m_serverSocket->close();
    }

    // Connections removed from the set on disconnected.
    // Copy connections to a variable to iterate over a constant container instead of
    // (virtually) simultanously mutated member variable.
    QSet<RemoteClientConnection*> activeConnections = m_activeConnections;
    for (RemoteClientConnection *client : activeConnections) {
        client->transport()->disconnectFromHost();
    }
}

void Server::saveData() const
{
    QJsonObject root;
    root[QLatin1String("version")] = 1;
    root[QLatin1String("authKeys")] = toJsonArray(m_authorizations.values());

    {
        QJsonArray sessionArray;
        for (const Session *session : m_sessions) {
            QJsonObject sessionObject;
            sessionObject[QLatin1String("id")]             = toJsonValue(session->id());
            sessionObject[QLatin1String("layer")]          = toJsonValue(session->layer());
            sessionObject[QLatin1String("getServerSalt")]  = toJsonValue(session->getServerSalt());
            sessionObject[QLatin1String("ip")]             = toJsonValue(session->ip);
            sessionObject[QLatin1String("timestamp")]      = toJsonValue(session->timestamp);
            sessionObject[QLatin1String("appId")]          = toJsonValue(session->appId);
            sessionObject[QLatin1String("appVersion")]     = toJsonValue(session->appVersion);
            sessionObject[QLatin1String("osInfo")]         = toJsonValue(session->osInfo);
            sessionObject[QLatin1String("deviceInfo")]     = toJsonValue(session->deviceInfo);
            sessionObject[QLatin1String("sequenceNumber")] = toJsonValue(session->lastSequenceNumber);
            sessionObject[QLatin1String("messageNumber")]  = toJsonValue(session->lastMessageNumber);
            sessionObject[QLatin1String("systemLanguage")] = toJsonValue(session->systemLanguage);
            sessionObject[QLatin1String("languagePack")]   = toJsonValue(session->languagePack);
            sessionObject[QLatin1String("languageCode")]   = toJsonValue(session->languageCode);
            sessionArray.append(sessionObject);
        }
        root[QLatin1String("sessions")] = sessionArray;
    }

    {
        QJsonArray usersArray;
        for (const LocalUser *user : m_users) {
            QJsonObject userObject;
            userObject[QLatin1String("id")] = toJsonValue(user->id());
            userObject[QLatin1String("phoneNumber")] = user->phoneNumber();
            userObject[QLatin1String("firstName")] = user->firstName();
            userObject[QLatin1String("lastName")] = user->lastName();
            if (!user->userName().isEmpty()) {
                userObject[QLatin1String("userName")] = user->userName();
            }

            QJsonArray sessionArray;
            for (const Session *session : user->sessions()) {
                sessionArray.append(toJsonValue(session->id()));
            }
            userObject[QLatin1String("sessions")] = sessionArray;
            userObject[QLatin1String("authorizations")] = toJsonArray(user->authorizations());

            const QHash<quint32,quint64> messageKeys = user->getPostBox()->getAllMessageKeys();
            QJsonObject messages;
            for (quint32 i = 0; i <= user->getPostBox()->lastMessageId(); ++i) {
                messages[QString::number(i)] = toJsonValue(messageKeys.value(i));
            }

            userObject[QLatin1String("messages")] = messages;

            const QVector<UserDialog *> dialogs = user->dialogs();
            QJsonArray dialogArray;
            for (const UserDialog *dialog : dialogs) {
                dialogArray.append(toJsonValue(*dialog));
            }
            userObject[QLatin1String("dialogs")] = dialogArray;
            usersArray.append(userObject);
        }
        root[QLatin1String("users")] = usersArray;
    }

    QFile data(QStringLiteral("server%1.json").arg(dcId()));
    data.open(QIODevice::WriteOnly);
    data.write(QJsonDocument(root).toJson());
}

void Server::loadData()
{
    QFile data(QStringLiteral("server%1.json").arg(dcId()));
    data.open(QIODevice::ReadOnly);
    const QJsonObject root = QJsonDocument::fromJson(data.readAll()).object();

    {
        const QJsonArray authKeysArray = root.value(QLatin1String("authKeys")).toArray();
        for (const QJsonValue &authKeyValue : authKeysArray) {
            const QByteArray authKey = fromJson<QByteArray>(authKeyValue);
            const quint64 keyId = Telegram::Utils::getFingerprints(authKey, Telegram::Utils::Lower64Bits);
            registerAuthKey(keyId, authKey);
        }
    }

    {
        const QJsonArray sessionArray = root.value(QLatin1String("sessions")).toArray();
        for (const QJsonValue &sessionArrayValue : sessionArray) {
            const QJsonObject sessionObject = sessionArrayValue.toObject();

            quint64 sessionId = fromJson<quint64>(sessionObject[QLatin1String("id")]);

            Session *session = addSession(sessionId);
            session->setLayer(fromJson<quint32>(sessionObject[QLatin1String("layer")]));
            session->setInitialServerSalt(fromJson<quint64>(sessionObject[QLatin1String("getServerSalt")]));

            fromJson(&session->ip, sessionObject[QLatin1String("ip")]);
            fromJson(&session->timestamp, sessionObject[QLatin1String("timestamp")]);
            fromJson(&session->appId, sessionObject[QLatin1String("appId")]);
            fromJson(&session->appVersion, sessionObject[QLatin1String("appVersion")]);
            fromJson(&session->osInfo, sessionObject[QLatin1String("osInfo")]);
            fromJson(&session->deviceInfo, sessionObject[QLatin1String("deviceInfo")]);
            fromJson(&session->lastSequenceNumber, sessionObject[QLatin1String("lastSequenceNumber")]);
            fromJson(&session->lastMessageNumber, sessionObject[QLatin1String("lastMessageNumber")]);
            fromJson(&session->systemLanguage, sessionObject[QLatin1String("systemLanguage")]);
            fromJson(&session->languagePack, sessionObject[QLatin1String("languagePack")]);
            fromJson(&session->languageCode, sessionObject[QLatin1String("languageCode")]);
        }
    }

    {
        const QJsonArray usersArray = root.value(QLatin1String("users")).toArray();
        for (const QJsonValue &userValue : usersArray) {
            const QJsonObject userObject = userValue.toObject();

            const quint32 userId = fromJson<quint32>(userObject[QLatin1String("id")]);
            const QString phoneNumber = fromJson<QString>(userObject[QLatin1String("phoneNumber")]);

            LocalUser *user = new LocalUser(userId, phoneNumber);
            user->setDcId(dcId());
            user->setFirstName(userObject[QLatin1String("firstName")].toString());
            user->setLastName(userObject[QLatin1String("lastName")].toString());
            user->setUserName(userObject[QLatin1String("userName")].toString());
            insertUser(user);

            const QJsonArray sessionArray = userObject[QLatin1String("sessions")].toArray();
            const QVector<quint64> sessions = fromJson< QVector<quint64> >(sessionArray);
            for (const quint64 &sessionId : sessions) {
                Session *session = getSessionById(sessionId);
                if (!session) {
                    continue;
                }
                user->addSession(session);
            }
            const QJsonArray authorizationsArray = userObject[QLatin1String("authorizations")].toArray();
            const QVector<quint64> authKeys = fromJson< QVector<quint64> >(authorizationsArray);

            for (const quint64 &authKeyId : authKeys) {
                if (getAuthKeyById(authKeyId).isEmpty()) {
                    continue;
                }
                addUserAuthorization(user, authKeyId);
            }
        }
    }
}

void Server::setServerConfiguration(const DcConfiguration &config)
{
    m_dcConfiguration = config;
}

void Server::addServerConnection(RemoteServerConnection *remoteServer)
{
    m_remoteServers.insert(remoteServer);
}

quint32 Server::getDcIdForUserIdentifier(const QString &phoneNumber)
{
    if (m_phoneToUserId.contains(phoneNumber)) {
        return m_dcOption.id;
    }
    return 0;
}

void Server::setAuthorizationProvider(Authorization::Provider *provider)
{
    m_authProvider = provider;
}

void Server::setStorage(Storage *storage)
{
    m_storage = storage;
}

void Server::onNewConnection()
{
    QTcpSocket *socket = m_serverSocket->nextPendingConnection();
    if (!socket) {
        qCDebug(loggingCategoryServer) << "expected pending connection does not exist";
        return;
    }
    qCInfo(loggingCategoryServer) << CALL_INFO << socket->peerAddress().toString();
    TcpTransport *transport = new TcpTransport(socket, this);
    socket->setParent(transport);
    RemoteClientConnection *client = new RemoteClientConnection(this);
    connect(client, &BaseConnection::statusChanged, this, &Server::onClientConnectionStatusChanged);
    client->setServerRsaKey(m_key);
    client->setTransport(transport);
    client->setServerApi(this);
    client->setRpcFactories(m_rpcOperationFactories);

    m_activeConnections.insert(client);
}

Session *Server::addSession(quint64 sessionId)
{
    Session *session = new Session(sessionId);
    m_sessions.insert(sessionId, session);
    return session;
}

void Server::onClientConnectionStatusChanged()
{
    RemoteClientConnection *client = qobject_cast<RemoteClientConnection*>(sender());
    if (client->status() == RemoteClientConnection::Status::HasDhKey) {
        if (!client->session()) {
            registerAuthKey(client->authId(), client->authKey());
            qCDebug(loggingCategoryServer) << Q_FUNC_INFO << "Connected a client with a new auth key"
                                              << "from" << client->transport()->remoteAddress();
        }
    } else if (client->status() == RemoteClientConnection::Status::Disconnected) {
        if (client->session()) {
            qCInfo(loggingCategoryServer) << this << __func__ << "Disconnected a client with session id"
                                          << hex << showbase << client->session()->id()
                                          << "from" << client->transport()->remoteAddress();
            client->session()->setConnection(nullptr);
        } else {
            qCInfo(loggingCategoryServer) << this << __func__ << "Disconnected a client without a session"
                                          << "from" << client->transport()->remoteAddress();
        }
        // TODO: Initiate session cleanup after session expiration time out
        m_activeConnections.remove(client);
        client->deleteLater();
    }
}

Peer Server::getPeer(const TLInputPeer &peer, const LocalUser *applicant) const
{
    switch (peer.tlType) {
    case TLValue::InputPeerEmpty:
        return Peer();
    case TLValue::InputPeerSelf:
        return Peer::fromUserId(applicant->id());
    case TLValue::InputPeerChat:
        return Peer::fromChatId(peer.chatId);
    case TLValue::InputPeerUser:
        return Peer::fromUserId(peer.userId);
    case TLValue::InputPeerChannel:
        return Peer::fromChannelId(peer.channelId);
    default:
        qCWarning(loggingCategoryServerApi) << this << __func__ << "Invalid input peer type" << peer.tlType;
        return Peer();
    };
}

MessageRecipient *Server::getRecipient(const Peer &peer, const LocalUser *applicant) const
{
    Q_UNUSED(applicant)
    switch (peer.type) {
    case Telegram::Peer::User:
        return getUser(peer.id);
    case Telegram::Peer::Chat:
        // recipient = api()->getChannel(arguments.peer.groupId, arguments.peer.accessHash);
        break;
    case Telegram::Peer::Channel:
        //recipient = api()->getChannel(arguments.peer.channelId, arguments.peer.accessHash);
        break;
    }
    return nullptr;
}

LocalUser *Server::getUser(const QString &identifier) const
{
    const quint32 id = m_phoneToUserId.value(identifier);
    if (!id) {
        return nullptr;
    }
    return m_users.value(id);
}

LocalUser *Server::getUser(quint32 userId) const
{
    return m_users.value(userId);
}

Peer Server::peerByUserName(const QString &userName) const
{
    // iterate over all users (too bad?)
    for (LocalUser *user: m_users) {
        if (user->userName() == userName) {
            return user->toPeer();
        }
    }
    return Peer();  // not found
}

AbstractUser *Server::getUser(const TLInputUser &inputUser, LocalUser *self) const
{
    switch (inputUser.tlType) {
    case TLValue::InputUserSelf:
        return self;
    case TLValue::InputUser:
        return tryAccessUser(inputUser.userId, inputUser.accessHash, self);
    case TLValue::InputUserEmpty:
        return nullptr;
    default:
        return nullptr;
    }
}

AbstractUser *Server::tryAccessUser(quint32 userId, quint64 accessHash, LocalUser *applicant) const
{
    AbstractUser *u = getAbstractUser(userId);
    // TODO: Check access hash
    return u;
}

LocalUser *Server::addUser(const QString &identifier)
{
    qCDebug(loggingCategoryServerApi) << Q_FUNC_INFO << identifier;
    LocalUser *user = new LocalUser();
    user->setPhoneNumber(identifier);
    user->setDcId(dcId());
    insertUser(user);
    return user;
}

void Server::registerAuthKey(quint64 authId, const QByteArray &authKey)
{
    m_authorizations.insert(authId, authKey);
}

bool Server::bindClientSession(RemoteClientConnection *client, quint64 sessionId)
{
    Session *session = getSessionById(sessionId);

    if (!session) {
        session = addSession(sessionId);
        session->ip = client->transport()->remoteAddress();

        if (client->dhLayer()->state() == DhLayer::State::HasKey) {
            session->setInitialServerSalt(client->dhLayer()->serverSalt());
        } else {
            session->generateInitialServerSalt();
        }

        const quint32 userId = getUserIdByAuthId(client->authId());
        if (userId) {
            session->setUser(getUser(userId));
        }
    }

    client->setSession(session);
    return true;
}

Session *Server::getSessionById(quint64 sessionId) const
{
    return m_sessions.value(sessionId);
}

void Server::bindUserSession(LocalUser *user, Session *session)
{
    user->addSession(session);
    addUserAuthorization(user, session->getConnection()->authId());
}

QByteArray Server::getAuthKeyById(quint64 authId) const
{
    return m_authorizations.value(authId);
}

quint32 Server::getUserIdByAuthId(quint64 authId) const
{
    return m_authToUserId.value(authId);
}

void Server::addUserAuthorization(LocalUser *user, quint64 authKeyId)
{
    m_authToUserId.insert(authKeyId, user->userId());
    user->addAuthKey(authKeyId);
}

/*
    Process the message data, deliver the message to all recipients, add
    the new message to dialogs and generate UpdateNotification list.

    The sender notification (if any) will be the first one in the result list.
 */
QVector<UpdateNotification> Server::processMessage(MessageData *messageData)
{
    const Peer targetPeer = messageData->toPeer();
    LocalUser *fromUser = getUser(messageData->fromId());
    MessageRecipient *recipient = getRecipient(targetPeer, fromUser);
    QVector<PostBox *> boxes = recipient->postBoxes();
    if ((targetPeer.type == Peer::User) && !messageData->isMessageToSelf()) {
        boxes.append(fromUser->getPostBox());
    }
    // Boxes:
    // message to contact
    //    Users (self and recipient (if not self))
    //
    // message to group chat
    //    Users (each member)
    //
    // message to megagroup or broadcast
    //    Channel (the channel)

    QVector<UpdateNotification> notifications;

    // Result and broadcasted Updates date seems to be always older than the message date,
    // so prepare the request date right on the start.
    const quint32 requestDate = Telegram::Utils::getCurrentTime();
    for (PostBox *box : boxes) {
        const quint32 newMessageId = box->addMessage(messageData);
        UpdateNotification notification;
        notification.type = UpdateNotification::Type::NewMessage;
        notification.date = requestDate;
        notification.messageId = newMessageId;
        notification.pts = box->pts();
        for (const quint32 userId : box->users()) {
            notification.userId = userId;
            if (targetPeer.type == Peer::User) {
                if (userId == fromUser->id()) {
                    notification.dialogPeer = targetPeer;
                } else {
                    notification.dialogPeer = fromUser->toPeer();
                }
            } else {
                notification.dialogPeer = targetPeer;
            }
            LocalUser *user = getUser(userId);
            user->addNewMessage(notification.dialogPeer, newMessageId, messageData->date64());
            if (user != fromUser) {
                user->bumpDialogUnreadCount(notification.dialogPeer);
            }

            if ((userId == fromUser->id()) && !notifications.isEmpty()) {
                // Keep the sender Notification on the first place
                notifications.append(notifications.constFirst());
                notifications.first() = notification;
                continue;
            }

            notifications.append(notification);
        }
    }

    return notifications;
}

void Server::queueUpdates(const QVector<UpdateNotification> &notifications)
{
    for (const UpdateNotification &notification : notifications) {
        LocalUser *recipient = getUser(notification.userId);
        if (!recipient) {
            qWarning() << Q_FUNC_INFO << "Invalid user!" << notification.userId;
        }

        TLUpdates updates;
        updates.tlType = TLValue::Updates;
        updates.date = notification.date;

        QSet<Peer> interestingPeers;
        switch (notification.type) {
        case UpdateNotification::Type::NewMessage: {
            TLUpdate update;
            update.tlType = TLValue::UpdateNewMessage;

            const quint64 globalMessageId = recipient->getPostBox()->getMessageGlobalId(notification.messageId);
            const MessageData *messageData = storage()->getMessage(globalMessageId);

            if (!messageData) {
                qWarning() << Q_FUNC_INFO << "no message";
                continue;
            }
            Utils::setupTLMessage(&update.message, messageData, notification.messageId, recipient);
            update.pts = notification.pts;
            update.ptsCount = 1;

            interestingPeers.insert(messageData->toPeer());
            if (update.message.fromId) {
                interestingPeers.insert(Peer::fromUserId(update.message.fromId));
            }

            updates.seq = 0; // ??
            updates.updates = { update };
        }
            break;
        case UpdateNotification::Type::MessageAction:
        {
            TLUpdate &update = updates.update;
            update.tlType = TLValue::UpdateUserTyping;
            update.userId = notification.fromId;
            // Note: action depends on Layer. Process this to support different layers.
            update.action.tlType = notification.actionType;
            update.action.progress = notification.progress;
            updates.tlType = TLValue::UpdateShort;
        }
            break;
        case UpdateNotification::Type::ReadInbox:
        case UpdateNotification::Type::ReadOutbox:
        {
            TLUpdate update;
            update.tlType = notification.type == UpdateNotification::Type::ReadInbox
                      ? TLValue::UpdateReadHistoryInbox
                      : TLValue::UpdateReadHistoryOutbox;
            update.pts = notification.pts;
            update.ptsCount = 1;
            update.peer = Telegram::Utils::toTLPeer(notification.dialogPeer);
            update.maxId = notification.messageId;

            updates.seq = 0; // ??
            updates.updates = { update };
        }
            break;
        case UpdateNotification::Type::Invalid:
            break;
        }

        Utils::setupTLPeers(&updates, interestingPeers, this, recipient);
        for (Session *session : recipient->activeSessions()) {
            if (session == notification.excludeSession) {
                continue;
            }
            session->rpcLayer()->sendUpdates(updates);
        }
    }
}

void Server::insertUser(LocalUser *user)
{
    qCDebug(loggingCategoryServerApi) << Q_FUNC_INFO << user << user->phoneNumber() << user->id();
    m_users.insert(user->id(), user);
    m_phoneToUserId.insert(user->phoneNumber(), user->id());
}

PhoneStatus Server::getPhoneStatus(const QString &identifier) const
{
    PhoneStatus result;
    AbstractUser *user = getAbstractUser(identifier);
    if (user) {
        result.online = user->isOnline();
        result.dcId = user->dcId();
    }
    return result;
}

PasswordInfo Server::getPassword(const QString &identifier)
{
    PasswordInfo result;
    LocalUser *user = getUser(identifier);
    if (user && user->hasPassword()) {
        result.currentSalt = user->passwordSalt();
        result.hint = user->passwordHint();
    }
    return result;
}

bool Server::checkPassword(const QString &identifier, const QByteArray &hash)
{
    LocalUser *user = getUser(identifier);
    if (user && user->hasPassword()) {
        return user->passwordHash() == hash;
    }
    return false;

}

bool Server::identifierIsValid(const QString &identifier) const
{
    const bool result = identifier.length() > 4;
    qCDebug(loggingCategoryServerApi) << "identifierIsValid(" << identifier << "):" << result;
    return result;
}

QString Server::normalizeIdentifier(const QString &identifier) const
{
    if (identifier.startsWith(QLatin1Char('+'))) {
        return identifier.mid(1);
    }
    return identifier;
}

AbstractUser *Server::getAbstractUser(quint32 userId) const
{
    AbstractUser *user = getUser(userId);
    if (!user) {
        user = getRemoteUser(userId);
    }
    return user;
}

AbstractUser *Server::getAbstractUser(const QString &identifier) const
{
    AbstractUser *user = getUser(identifier);
    if (!user) {
        user = getRemoteUser(identifier);
    }
    return user;
}

AbstractUser *Server::getRemoteUser(quint32 userId) const
{
    for (RemoteServerConnection *remoteServer : m_remoteServers) {
        AbstractUser *u = remoteServer->api()->getUser(userId);
        if (u) {
            return u;
        }
    }
    return nullptr;
}

AbstractUser *Server::getRemoteUser(const QString &identifier) const
{
    for (RemoteServerConnection *remoteServer : m_remoteServers) {
        AbstractUser *u = remoteServer->api()->getUser(identifier);
        if (u) {
            return u;
        }
    }
    return nullptr;
}

} // Server namespace

} // Telegram namespace
