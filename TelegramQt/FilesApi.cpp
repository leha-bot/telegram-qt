#include "FilesApi_p.hpp"

namespace Telegram {

namespace Client {

FilesApiPrivate::FilesApiPrivate(FilesApi *parent) :
    ClientApiPrivate(parent)
{
}

FilesApiPrivate *FilesApiPrivate::get(FilesApi *parent)
{
    return reinterpret_cast<FilesApiPrivate*>(parent->d);
}

FileOperation *FilesApiPrivate::getFile(const RemoteFile *file)
{
    return nullptr;
}

FileOperation *FilesApiPrivate::getPeerPicture(const Peer &peer, PeerPictureSize size)
{
    return nullptr;
}

/*!
    \class Telegram::Client::FilesApi
    \brief Provides an API to work download and upload files.

    \inmodule TelegramQt
    \ingroup Client
*/
FilesApi::FilesApi(QObject *parent) :
    ClientApi(parent)
{
    d = new FilesApiPrivate(this);
}

FileOperation *FilesApi::getFile(const RemoteFile *file)
{
    Q_D(FilesApi);
    return d->getFile(file);
}

FileOperation *FilesApi::getPeerPicture(const Peer &peer, PeerPictureSize size)
{
    Q_D(FilesApi);
    return d->getPeerPicture(peer, size);
}

} // Client namespace

} // Telegram namespace
