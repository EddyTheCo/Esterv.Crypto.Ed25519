#include "crypto/qed25519.hpp"
#include "ed25519.h"

namespace qcrypto
{
namespace qed25519
{
std::pair<QByteArray, QByteArray> create_keypair(const QByteArray &seed)
{
    QByteArray public_key(32, 0);
    QByteArray private_key(64, 0);

    ed25519_create_keypair(reinterpret_cast<unsigned char *>(public_key.data()),
                           reinterpret_cast<unsigned char *>(private_key.data()),
                           reinterpret_cast<const unsigned char *>(seed.data()));
    return std::make_pair(public_key, private_key);
}
QByteArray sign(const std::pair<QByteArray, QByteArray> &key_pair, const QByteArray &message)
{
    QByteArray signature(64, 0);

    ed25519_sign(reinterpret_cast<unsigned char *>(signature.data()),
                 reinterpret_cast<const unsigned char *>(message.data()), (size_t)message.size(),
                 reinterpret_cast<const unsigned char *>(key_pair.first.data()),
                 reinterpret_cast<const unsigned char *>(key_pair.second.data()));
    return signature;
}
bool verify(const QByteArray &signature, const QByteArray &message, const QByteArray &public_key)
{

    return ed25519_verify(reinterpret_cast<const unsigned char *>(signature.data()),
                          reinterpret_cast<const unsigned char *>(message.data()), (size_t)message.size(),
                          reinterpret_cast<const unsigned char *>(public_key.data()));
}
} // namespace qed25519
} // namespace qcrypto
