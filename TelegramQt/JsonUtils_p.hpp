/*
   Copyright (C) 2019 Alexandr Akulich <akulichalexander@gmail.com>

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

#ifndef TELEGRAM_QT_JSON_UTILS_P_HPP
#define TELEGRAM_QT_JSON_UTILS_P_HPP

/* This file contains built-in and Qt types to/from JSON converters */

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QVariant>

template<typename T>
struct json_always_false : std::false_type {};

template <typename T>
inline QJsonValue toJsonValue(T)
{
    static_assert(json_always_false<T>::value , "toJsonValue() has no specialization for this type");
    return QJsonValue();
}

inline QJsonValue toJsonValue(quint64 v)
{
    return QString::number(v);
}

inline QJsonValue toJsonValue(quint32 v)
{
    return QJsonValue(static_cast<int>(v));
}

inline QJsonValue toJsonValue(const QString &v)
{
    return QJsonValue(v);
}

inline QJsonValue toJsonValue(const QByteArray &v)
{
    return QJsonValue::fromVariant(QVariant::fromValue(v.toHex()));
}

template <typename Key, typename Value>
inline QJsonValue toJsonValue(Key key, Value value)
{
    QJsonObject result;
    result[QLatin1String("key")] = toJsonValue(key);
    result[QLatin1String("value")] = toJsonValue(value);
    return result;
}

template <typename T>
inline QJsonArray toJsonArray(const T &container)
{
    QJsonArray result;
    for (const auto &value : container) {
        result.append(toJsonValue(value));
    }
    return result;
}

template <typename T>
inline T fromJson(const QJsonValue &v)
{
    return v.toVariant().value<T>();
}

template <>
inline QByteArray fromJson(const QJsonValue &v)
{
    return QByteArray::fromHex(v.toVariant().toByteArray());
}

template <typename T>
inline T fromJson(const QJsonArray &array)
{
    T result;
    for (const QJsonValue &value : array) {
        result.append(fromJson<decltype (result.takeFirst())>(value));
    }
    return result;
}

template <typename T>
inline void fromJson(T *dest, const QJsonValue &v)
{
    *dest = fromJson<T>(v);
}

template <typename T>
inline void fromJson(T *dest, const QJsonArray &a)
{
    *dest = fromJson<T>(a);
}

#endif // TELEGRAM_QT_JSON_UTILS_P_HPP
