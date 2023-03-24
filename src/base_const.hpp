#ifndef _INCLUDES_base_const
#define _INCLUDES_base_const

#include <cstddef>
#include <map>
#include <string>


namespace cryptoAL
{
const bool USE_AUTO_FEATURE = false; // prototype

const std::string BASEDIGIT10 = "0123456789";
const std::string BASEDIGIT64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+="; // NOT STANDARD

const std::string RSA_MY_PRIVATE_DB             = "rsa_my_private.db";   	// (n,e,d) it includes public (n,e) and private key (n,d)
const std::string RSA_MY_PUBLIC_DB              = "rsa_my_public.db";       // export from RSA_MY_PRIVATE_DB
const std::string RSA_OTHER_PUBLIC_DB           = "rsa_other_public.db";	// (n,e)

const std::string HHKEY_MY_PRIVATE_ENCODE_DB    = "hhkey_my_private_encode.db";		// when encoding SHA[0,1,2,...], when confirmed become keys
const std::string HHKEY_MY_PRIVATE_DECODE_DB    = "hhkey_my_private_decode.db";		// when decoding
const std::string HHKEY_MY_PUBLIC_DECODE_DB     = "hhkey_my_public_decode.db";		// export
const std::string HHKEY_OTHER_PUBLIC_DECODE_DB  = "hhkey_other_public_decode.db";	// short name of HHKEY_MY_PUBLIC_DECODE_DB

const std::string ECC_DOMAIN_DB      			= "ecc_domain.db";
const std::string ECCKEY_MY_PRIVATE_DB      	= "ecckey_my_private.db";
const std::string ECCKEY_MY_PUBLIC_DB      	    = "ecckey_my_public.db";    // export from ECCKEY_MY_PRIVATE_DB
const std::string ECCKEY_OTHER_PUBLIC_DB      	= "ecckey_other_public.db";

}

#endif

