#ifndef TELEGRAM_SERVER_UTILS_HPP
#define TELEGRAM_SERVER_UTILS_HPP

#include <QSet>

#include "TelegramNamespace_p.hpp"

namespace Telegram {

namespace Server {

class AbstractUser;
class LocalUser;
class MediaData;
class MessageData;
class ServerApi;

class FileDescriptor;
class ImageDescriptor;

namespace Utils {

void getInterestingPeers(QSet<Peer> *peers, const TLVector<TLMessage> &messages);

bool setupTLUser(TLUser *output, const AbstractUser *input, const LocalUser *forUser);
bool setupTLUpdatesState(TLUpdatesState *output, const LocalUser *forUser);
bool setupTLPeers(TLVector<TLUser> *users, TLVector<TLChat> *chats,
                  const QSet<Peer> &peers, const ServerApi *api, const LocalUser *forUser);
bool setupTLMessage(TLMessage *output, const MessageData *messageData, quint32 messageId,
                    const LocalUser *forUser);

bool setupTLMessageMedia(TLMessageMedia *output, const MediaData *mediaData);

template <typename T>
bool setupTLPeers(T *output,
                  const QSet<Peer> &peers, const ServerApi *api, const LocalUser *forUser)
{
    return setupTLPeers(&output->users, &output->chats,
                        peers, api, forUser);
}

bool setupTLPhoto(TLPhoto *output, const ImageDescriptor &image);
bool setupTLFileLocation(TLFileLocation *output, const FileDescriptor &file);
bool setupNotifySettings(TLPeerNotifySettings *output, const NotificationSettingsData &settings);

} // Utils namespace

} // Server namespace

} // Telegram namespace

#endif // TELEGRAM_SERVER_API_HPP
