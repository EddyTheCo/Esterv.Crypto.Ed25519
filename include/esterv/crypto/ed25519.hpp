#pragma once

#include <QByteArray>

namespace Esterv:Crypto:Ed25519
{
std::pair<QByteArray, QByteArray> create_keypair(const QByteArray &seed);
QByteArray sign(const std::pair<QByteArray, QByteArray> &key_pair, const QByteArray &message);
bool verify(const QByteArray &signature, const QByteArray &message, const QByteArray &public_key);

}; // namespace qcrypto
