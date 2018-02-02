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

#include "UploadOperationFactory.hpp"

#include "RpcOperationFactory_p.hpp"
// TODO: Instead of this include, add a generated cpp with all needed template instances
#include "ServerRpcOperation_p.hpp"

#include "ServerApi.hpp"
#include "ServerRpcLayer.hpp"
#include "TelegramServerUser.hpp"

#include "Debug_p.hpp"
#include "RpcError.hpp"
#include "RpcProcessingContext.hpp"
#include "Utils.hpp"

#include "CTelegramStreamExtraOperators.hpp"
#include "FunctionStreamOperators.hpp"

#include <QLoggingCategory>

namespace Telegram {

namespace Server {

// Generated process methods
bool UploadRpcOperation::processGetFile(RpcProcessingContext &context)
{
    setRunMethod(&UploadRpcOperation::runGetFile);
    context.inputStream() >> m_getFile;
    return !context.inputStream().error();
}

bool UploadRpcOperation::processSaveBigFilePart(RpcProcessingContext &context)
{
    setRunMethod(&UploadRpcOperation::runSaveBigFilePart);
    context.inputStream() >> m_saveBigFilePart;
    return !context.inputStream().error();
}

bool UploadRpcOperation::processSaveFilePart(RpcProcessingContext &context)
{
    setRunMethod(&UploadRpcOperation::runSaveFilePart);
    context.inputStream() >> m_saveFilePart;
    return !context.inputStream().error();
}
// End of generated process methods

// Generated run methods
void UploadRpcOperation::runGetFile()
{
    qWarning() << Q_FUNC_INFO << "The method is not implemented!";
    TLUploadFile result;
    sendRpcReply(result);
}

void UploadRpcOperation::runSaveBigFilePart()
{
    qWarning() << Q_FUNC_INFO << "The method is not implemented!";
    bool result;
    sendRpcReply(result);
}

void UploadRpcOperation::runSaveFilePart()
{
    qWarning() << Q_FUNC_INFO << "The method is not implemented!";
    bool result;
    sendRpcReply(result);
}
// End of generated run methods

void UploadRpcOperation::setRunMethod(UploadRpcOperation::RunMethod method)
{
    m_runMethod = method;
}

UploadRpcOperation::ProcessingMethod UploadRpcOperation::getMethodForRpcFunction(TLValue function)
{
    switch (function) {
    // Generated methodForRpcFunction cases
    case TLValue::UploadGetFile:
        return &UploadRpcOperation::processGetFile;
    case TLValue::UploadSaveBigFilePart:
        return &UploadRpcOperation::processSaveBigFilePart;
    case TLValue::UploadSaveFilePart:
        return &UploadRpcOperation::processSaveFilePart;
    // End of generated methodForRpcFunction cases
    default:
        return nullptr;
    }
}

RpcOperation *UploadOperationFactory::processRpcCall(RpcLayer *layer, RpcProcessingContext &context)
{
    return processRpcCallImpl<UploadRpcOperation>(layer, context);
}

} // Server

} // Telegram