#ifndef _INCLUDES_base_const
#define _INCLUDES_base_const

#include <cstddef>
#include <map>
#include <string>


namespace cryptoAL
{

const std::string BASEDIGIT10 = "0123456789";
const std::string BASEDIGIT64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+="; // NOT STANDARD

#ifdef RSA_IN_DATA_FEATURE
#else
constexpr static uint32_t MAX_RSA_BITS          = 16384*4;   // 4x openssl recommended limit!
#endif

const std::string RSA_MY_PRIVATE_DB             = "rsa_my_private.db";   	// (n,e,d) it includes public (n,e) and private key (n,d)
const std::string RSA_OTHER_PUBLIC_DB           = "rsa_other_public.db";	// (n,e)

}

#endif

