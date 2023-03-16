#ifndef _INCLUDES_base_const
#define _INCLUDES_base_const

#include <cstddef>
#include <map>
#include <string>


namespace cryptoAL
{

const std::string BASEDIGIT10 = "0123456789";
const std::string BASEDIGIT64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+="; // NOT STANDARD

const std::string RSA_MY_PRIVATE_DB             = "rsa_my_private.db";   	// (n,e,d) it includes public (n,e) and private key (n,d)
const std::string RSA_OTHER_PUBLIC_DB           = "rsa_other_public.db";	// (n,e)

const std::string CRYPTO_HISTORY_DECODE_DB      = "history_decode.db";
const std::string CRYPTO_HISTORY_ENCODE_DB      = "history_encode.db";

const std::string ECC_DOMAIN_DB      			= "ecc_domain.db";
const std::string ECCKEY_MY_PRIVATE_DB      	= "ecckey_my_private.db";
const std::string ECCKEY_OTHER_PUBLIC_DB      	= "ecckey_other_public.db";

}

#endif

