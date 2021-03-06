/*
   Copyright (C) 2018 Alexandr Akulich <akulichalexander@gmail.com>

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

#ifndef TELEGRAM_SERVER_CLUSTER_HPP
#define TELEGRAM_SERVER_CLUSTER_HPP

#include <QObject>
#include <QVector>

#include "DcConfiguration.hpp"
#include "RsaKey.hpp"

namespace Telegram {

namespace Server {

namespace Authorization {

class Provider;

} // Authorization namespace

class Server;
class Session;
class ServerApi;
class Storage;
class LocalUser;
class AbstractUser;

class LocalCluster : public QObject
{
    Q_OBJECT
public:
    explicit LocalCluster(QObject *parent = nullptr);
    using ServerConstructor = Server *(*)(QObject *parent);
    void setServerContructor(ServerConstructor constructor);

    void setStorage(Storage *storage);
    void setAuthorizationProvider(Authorization::Provider *provider);

    DcConfiguration serverConfiguration() { return m_serverConfiguration; }
    void setServerConfiguration(const DcConfiguration &config);

    RsaKey serverRsaKey() const { return m_key; }
    void setServerPrivateRsaKey(const Telegram::RsaKey &key);

    bool start();
    void stop();

    LocalUser *addUser(const QString &identifier, quint32 dcId);
    LocalUser *getUser(const QString &identifier);

    QVector<Server*> getServerInstances() { return m_serverInstances; }
    Server *getServerInstance(quint32 dcId);
    ServerApi *getServerApiInstance(quint32 dcId);

protected:
    ServerConstructor m_constructor;
    QVector<Server*> m_serverInstances;
    DcConfiguration m_serverConfiguration;
    RsaKey m_key;
    Storage *m_storage = nullptr;
    Authorization::Provider *m_authProvider = nullptr;
};

} // Server namespace

} // Telegram namespace

#endif // TELEGRAM_SERVER_CLUSTER_HPP
