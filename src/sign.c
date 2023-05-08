#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include <string.h>
#include <stdio.h>

void ed25519_sign(unsigned char *sig, const unsigned char *m, size_t message_len, const unsigned char *sk) {
    sha512_context hs;
    unsigned char az[64];
    unsigned char hram[64];
    unsigned char nonce[64];
    ge_p3 R;



    sha512_init(&hs);


    sha512_context state;
    sha512_init(&state);
    sha512_update(&state, sk, 32);
    sha512_final(&state, az);



    sha512_update(&hs, az + 32, 32);
    sha512_update(&hs, m, message_len);
    sha512_final(&hs, nonce);


    memmove(sig+32,sk+32,32);

    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(sig, &R);


    sha512_init(&hs);
    sha512_update(&hs, sig, 64);
    sha512_update(&hs, m, message_len);
    sha512_final(&hs, hram);


    sc_reduce(hram);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;
    sc_muladd(sig + 32, hram, az, nonce);

}
