#include"crypto/qed25519.hpp"

#ifdef USE_INTERNAL
#include"ed25519.h"
#endif
#ifdef USE_SODIUM
#include <sodium.h>
#endif
#include<iostream>
namespace qcrypto
{
	namespace qed25519
	{
		std::pair<QByteArray,QByteArray> create_keypair(const QByteArray& seed)
		{
			QByteArray public_key(32,0);
			QByteArray private_key(64,0);

#ifdef USE_INTERNAL
			ed25519_create_keypair(reinterpret_cast<unsigned char*> (public_key.data()),
					reinterpret_cast<unsigned char*> (private_key.data()),
					reinterpret_cast<const unsigned char*> (seed.data()));
			private_key.replace(0,32,seed);
			private_key.replace(32,32,public_key);
#endif
#ifdef USE_SODIUM
			crypto_sign_seed_keypair(reinterpret_cast<unsigned char*> (public_key.data()),
				       	reinterpret_cast<unsigned char*> (private_key.data()),
				       	reinterpret_cast<const unsigned char*> (seed.data()));
#endif

			return std::make_pair(public_key,private_key);
		}
		QByteArray sign(const std::pair<QByteArray,QByteArray>& key_pair, const QByteArray& message)
		{
			QByteArray signature(64,0);
#ifdef USE_INTERNAL
			ed25519_sign(reinterpret_cast<unsigned char*> (signature.data()),
					reinterpret_cast<const unsigned char*>(message.data()),
					(size_t)message.size(),
                    reinterpret_cast<const unsigned char*>(key_pair.second.data()));
#endif
#ifdef USE_SODIUM
			unsigned long long sign_len = 64;
			crypto_sign_ed25519_detached(reinterpret_cast<unsigned char*> (signature.data()),
				       	&sign_len,
                                      reinterpret_cast<const unsigned char*> (message.data()),
                                      message.size(),
                                      reinterpret_cast<const unsigned char*> (key_pair.second.data()));
#endif
			return signature;
		}
		bool verify(const QByteArray& signature,const QByteArray& message,const QByteArray& public_key)
		{
#ifdef USE_INTERNAL
			return ed25519_verify(reinterpret_cast<const unsigned char*> (signature.data()),
					reinterpret_cast<const unsigned char*>(message.data()),
					(size_t)message.size(),
					reinterpret_cast<const unsigned char*>(public_key.data()));
#endif
#ifdef USE_SODIUM
			return 
			crypto_sign_ed25519_verify_detached(reinterpret_cast<const unsigned char*> (signature.data()),
                                      reinterpret_cast<const unsigned char*>(message.data()),
                                      message.size(),
                                      reinterpret_cast<const unsigned char*> (public_key.data()));
#endif
		}
	}
}
