/*
   Copyright (C) 2019 Alexander Akulich <akulichalexander@gmail.com>

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

#ifndef TELEGRAMQT_CLIENT_FILES_API_PRIVATE_HPP
#define TELEGRAMQT_CLIENT_FILES_API_PRIVATE_HPP

#include "ClientApi_p.hpp"

#include "FilesApi.hpp"

namespace Telegram {

namespace Client {

class FilesApiPrivate : public ClientApiPrivate
{
    Q_OBJECT
    Q_DECLARE_PUBLIC(FilesApi)
public:
    explicit FilesApiPrivate(FilesApi *parent = nullptr);
    static FilesApiPrivate *get(FilesApi *parent);

    FileOperation *getFile(const RemoteFile *file);
    FileOperation *getPeerPicture(const Peer &peer, PeerPictureSize size);
};

} // Client namespace

} // Telegram namespace

#endif // TELEGRAMQT_CLIENT_FILES_API_PRIVATE_HPP
