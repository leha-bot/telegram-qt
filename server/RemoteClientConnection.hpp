#ifndef TELEGRAM_SERVER_CLIENT_CONNECTION_HPP
#define TELEGRAM_SERVER_CLIENT_CONNECTION_HPP

#include <QObject>
#include <QVector>

#include "Connection.hpp"

namespace Telegram {

namespace Server {

class ServerApi;
class RpcLayer;
class RpcOperationFactory;
class Session;

class RemoteClientConnection : public BaseConnection
{
    Q_OBJECT
public:
    explicit RemoteClientConnection(QObject *parent = nullptr);

    RpcLayer *rpcLayer() const;
    BaseDhLayer *dhLayer() const;

    void setRpcFactories(const QVector<RpcOperationFactory*> &rpcFactories);

    ServerApi *api() const;
    void setServerApi(ServerApi *api);

    Session *session() const;
    void setSession(Session *session);

protected slots:
    void sendKeyError();

protected:
    bool processAuthKey(quint64 authKeyId) override;
};

} // Server namespace

} // Telegram namespace

#endif // TELEGRAM_SERVER_CLIENT_CONNECTION_HPP
