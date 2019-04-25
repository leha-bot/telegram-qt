#ifndef TELEGRAM_QT_JSON_P_HPP
#define TELEGRAM_QT_JSON_P_HPP

/* This file contains Telegram types to/from JSON converters */

#include "JsonUtils_p.hpp"

#include "TelegramNamespace.hpp"

inline QJsonValue toJsonValue(const Telegram::Peer &peer)
{
    return toJsonValue(peer.toString());
}

#endif // TELEGRAM_QT_JSON_P_HPP
