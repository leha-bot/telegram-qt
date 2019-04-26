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

#ifndef TELEGRAMQT_CLIENT_FILES_API_HPP
#define TELEGRAMQT_CLIENT_FILES_API_HPP

#include "ClientApi.hpp"
#include "TelegramNamespace.hpp"

namespace Telegram {

namespace Client {

class FileOperation;
class FilesApiPrivate;

class TELEGRAMQT_EXPORT FilesApi : public ClientApi
{
    Q_OBJECT
public:
    explicit FilesApi(QObject *parent = nullptr);

    FileOperation *getFile(const Telegram::RemoteFile *file);
    FileOperation *getPeerPicture(const Telegram::Peer &peer, Telegram::PeerPictureSize size = Telegram::PeerPictureSize::Small);

protected:
    Q_DECLARE_PRIVATE_D(d, FilesApi)
};

} // Client namespace

} // Telegram namespace

#endif // TELEGRAMQT_CLIENT_FILES_API_HPP
