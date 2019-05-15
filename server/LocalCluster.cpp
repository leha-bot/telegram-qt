#include "LocalCluster.hpp"

#include "TelegramServer.hpp"
#include "RemoteServerConnection.hpp"
#include "Storage.hpp"
#include "TelegramServerUser.hpp"
#include "DefaultAuthorizationProvider.hpp"

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(c_loggingClusterCategory, "telegram.server.cluster", QtWarningMsg)

namespace Telegram {

namespace Server {

LocalCluster::LocalCluster(QObject *parent)
    : QObject(parent)
{
    m_constructor = [](QObject *parent) { return new Server(parent); };
}

void LocalCluster::setServerContructor(LocalCluster::ServerConstructor constructor)
{
    m_constructor = constructor;
}

void LocalCluster::setStorage(Storage *storage)
{
    m_storage = storage;
}

void LocalCluster::setAuthorizationProvider(Authorization::Provider *provider)
{
    m_authProvider = provider;
}

void LocalCluster::setServerConfiguration(const DcConfiguration &config)
{
    m_serverConfiguration = config;
}

void LocalCluster::setServerPrivateRsaKey(const Telegram::RsaKey &key)
{
    m_key = key;
}

bool LocalCluster::start()
{
    if (m_serverConfiguration.dcOptions.isEmpty()) {
        qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Unable to start cluster: DC options is empty.";
        return false;
    }

    if (!m_key.isPrivate()) {
        qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Unable to start cluster: Invalid private key.";
        return false;
    }

    if (!m_storage) {
        qCDebug(c_loggingClusterCategory) << Q_FUNC_INFO << "Fallback to default Storage implementation";
        m_storage = new Storage(this);
    }

    if (!m_authProvider) {
        qCDebug(c_loggingClusterCategory) << Q_FUNC_INFO << "Fallback to default auth provider";
        m_authProvider = new Authorization::DefaultProvider();
    }

    m_storage->loadData();

    for (const DcOption &dc : m_serverConfiguration.dcOptions) {
        if (!dc.id) {
            qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Invalid configuration: DC id is null.";
            return false;
        }
        if (!dc.port) {
            qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Invalid configuration: Server port is not set.";
            return false;
        }
        if (dc.address.isEmpty()) {
            qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Invalid configuration: Server address is not set.";
            return false;
        }
        Server *server = m_constructor(this);
        server->setServerConfiguration(m_serverConfiguration);
        server->setDcOption(dc);
        server->setServerPrivateRsaKey(m_key);
        server->setStorage(m_storage);
        server->setAuthorizationProvider(m_authProvider);
        m_serverInstances.append(server);
    }

    bool hasFails = false;
    for (Server *server : m_serverInstances) {
        for (Server *peer : m_serverInstances) {
            if (server == peer) {
                continue;
            }
            RemoteServerConnection *remote = new RemoteServerConnection(server);
            remote->setRemoteServer(peer);
            server->addServerConnection(remote);
        }

        if (!server->start()) {
            qCCritical(c_loggingClusterCategory) << Q_FUNC_INFO << "Unable to start server" << server->dcId();
            hasFails = true;
        }
    }
    for (Server *server : m_serverInstances) {
        server->loadData();
    }
    return !hasFails;
}

void LocalCluster::stop()
{
    for (Server *server : m_serverInstances) {
        server->stop();
        server->saveData();
    }
    m_storage->saveData();
}

LocalUser *LocalCluster::addUser(const QString &identifier, quint32 dcId)
{
    if (getUser(identifier)) {
        qCWarning(c_loggingClusterCategory) << Q_FUNC_INFO << "Unable to add user"
                                            << identifier << "(the identifier is already taken)";
        return nullptr;
    }
    Server *server = getServerInstance(dcId);
    if (!server) {
        qCWarning(c_loggingClusterCategory) << Q_FUNC_INFO << "Unable to add user"
                                            << identifier << "to unknown server id" << dcId;
        return nullptr;
    }
    return server->addUser(identifier);
}

LocalUser *LocalCluster::getUser(const QString &identifier)
{
    AbstractUser *u = m_serverInstances.first()->getAbstractUser(identifier);
    if (!u) {
        return nullptr;
    }
    Server *s = getServerInstance(u->dcId());
    return s->getUser(identifier);
}

Server *LocalCluster::getServerInstance(quint32 dcId)
{
    for (Server *server : m_serverInstances) {
        if (server->dcId() == dcId) {
            return server;
        }
    }
    return nullptr;
}

ServerApi *LocalCluster::getServerApiInstance(quint32 dcId)
{
    return getServerInstance(dcId);
}

} // Server namespace

} // Telegram namespace
