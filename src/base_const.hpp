#ifndef _INCLUDES_base_const
#define _INCLUDES_base_const

#include <cstddef>
#include <map>
#include <string>


namespace cryptoAL
{
const bool USE_AUTO_FEATURE = true;
const bool USE_KEYURL_FEATURE = true;

const std::string BASEDIGIT10 = "0123456789";
const std::string BASEDIGIT64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+="; // NOT STANDARD
const std::string BASEDIGIT16 = "0123456789abcdef";

const std::string RSA_MY_PRIVATE_DB             = "rsa_my_private.db";   	// (n,e,d) it includes public (n,e) and private key (n,d)
const std::string RSA_MY_PUBLIC_DB              = "rsa_my_public.db";       // export from RSA_MY_PRIVATE_DB
const std::string RSA_OTHER_PUBLIC_DB           = "rsa_other_public.db";	// (n,e)

const std::string HHKEY_MY_PRIVATE_ENCODE_DB    = "hhkey_my_private_encode.db";		// when encoding SHA[0,1,2,...], when confirmed become keys
const std::string HHKEY_MY_PRIVATE_DECODE_DB    = "hhkey_my_private_decode.db";		// when decoding
const std::string HHKEY_MY_PUBLIC_DECODE_DB     = "hhkey_my_public_decode.db";		// export
const std::string HHKEY_OTHER_PUBLIC_DECODE_DB  = "hhkey_other_public_decode.db";	// recipient short name of HHKEY_MY_PUBLIC_DECODE_DB

const std::string RSA_MY_STATUS_DB     			= "rsa_my_status.db";		// export confirmed/deleted
const std::string ECC_MY_STATUS_DB     			= "ecc_my_status.db";		// export confirmed/deleted
const std::string ECCDOM_MY_STATUS_DB     		= "eccdom_my_status.db";	// export confirmed/deleted
const std::string HH_MY_STATUS_DB     			= "hh_my_status.db";		// export confirmed/deleted
const std::string RSA_OTHER_STATUS_DB     		= "rsa_other_status.db";	// export confirmed/deleted
const std::string ECC_OTHER_STATUS_DB     		= "ecc_other_status.db";	// export confirmed/deleted
const std::string ECCDOM_OTHER_STATUS_DB     	= "ecc_other_status.db";	// export confirmed/deleted
const std::string HH_OTHER_STATUS_DB     		= "hh_other_status.db";		// export confirmed/deleted

const std::string ECC_DOMAIN_DB      			= "ecc_domain.db";
const std::string ECC_DOMAIN_PUBLIC_DB      	= "ecc_domain_public.db";	// export
const std::string ECC_DOMAIN_OTHER_DB      		= "ecc_domain_other.db";

const std::string ECCKEY_MY_PRIVATE_DB      	= "ecckey_my_private.db";
const std::string ECCKEY_MY_PUBLIC_DB      	    = "ecckey_my_public.db";    // export from ECCKEY_MY_PRIVATE_DB
const std::string ECCKEY_OTHER_PUBLIC_DB      	= "ecckey_other_public.db";

}

#endif

