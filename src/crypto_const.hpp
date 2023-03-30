#ifndef _INCLUDES_crypto_const
#define _INCLUDES_crypto_const

#include "base_const.hpp"
#include <filesystem>
#include <curl/curl.h>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include <iostream>

namespace cryptoAL
{

enum class CRYPTO_ALGO : uint16_t
{
    ALGO_NONE = 0,

    ALGO_BIN_DES = 1,
    ALGO_BIN_AES_16_16_ecb,
    ALGO_BIN_AES_16_16_cbc,
    ALGO_BIN_AES_16_16_cfb,
	ALGO_BIN_AES_32_32_ecb,
    ALGO_BIN_AES_32_32_cbc,
    ALGO_BIN_AES_32_32_cfb,
    ALGO_TWOFISH,
    ALGO_Salsa20,
    ALGO_IDEA,
	ALGO_wbaes512,
	ALGO_wbaes1024,
	ALGO_wbaes2048,
	ALGO_wbaes4096,
	ALGO_wbaes8192,
	ALGO_wbaes16384,
	ALGO_wbaes32768,

	ALGO_LIMIT_MARKER
};
enum class CRYPTO_ALGO_AES
{
    ECB,
    CBC,
    CFB
};

inline std::string aes_subtype(uint16_t t)
{
    if      (t==(uint16_t)CRYPTO_ALGO_AES::ECB) return "ECB";
    else if (t==(uint16_t)CRYPTO_ALGO_AES::CBC) return "CBC";
    else if (t==(uint16_t)CRYPTO_ALGO_AES::CFB) return "CFB";
    return "";
}

inline CRYPTO_ALGO wbaes_algo_first() {return CRYPTO_ALGO::ALGO_wbaes512;}
inline CRYPTO_ALGO wbaes_algo_last()  {return CRYPTO_ALGO::ALGO_wbaes32768;}

inline std::string algo_wbaes_name(CRYPTO_ALGO t)
{
    if      (t==CRYPTO_ALGO::ALGO_wbaes512)   return "aes512";
    else if (t==CRYPTO_ALGO::ALGO_wbaes1024)  return "aes1024";
    else if (t==CRYPTO_ALGO::ALGO_wbaes2048)  return "aes2048";
    else if (t==CRYPTO_ALGO::ALGO_wbaes4096)  return "aes4096";
    else if (t==CRYPTO_ALGO::ALGO_wbaes8192)  return "aes8192";
    else if (t==CRYPTO_ALGO::ALGO_wbaes16384) return "aes16384";
    else if (t==CRYPTO_ALGO::ALGO_wbaes32768) return "aes32768";
    return "";
}
inline CRYPTO_ALGO wbaes_algo(const std::string& s)
{
    if      (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes512))  return CRYPTO_ALGO::ALGO_wbaes512;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes1024)) return CRYPTO_ALGO::ALGO_wbaes1024;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes2048)) return CRYPTO_ALGO::ALGO_wbaes2048;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes4096)) return CRYPTO_ALGO::ALGO_wbaes4096;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes8192)) return CRYPTO_ALGO::ALGO_wbaes8192;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes16384)) return CRYPTO_ALGO::ALGO_wbaes16384;
    else if (s == algo_wbaes_name(CRYPTO_ALGO::ALGO_wbaes32768)) return CRYPTO_ALGO::ALGO_wbaes32768;
    return CRYPTO_ALGO::ALGO_NONE;
}
inline CRYPTO_ALGO wbaes_algo_from_uint16(uint16_t t)
{
    if      (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes512) return CRYPTO_ALGO::ALGO_wbaes512;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes1024) return CRYPTO_ALGO::ALGO_wbaes1024;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes2048) return CRYPTO_ALGO::ALGO_wbaes2048;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes4096) return CRYPTO_ALGO::ALGO_wbaes4096;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes8192) return CRYPTO_ALGO::ALGO_wbaes8192;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes16384) return CRYPTO_ALGO::ALGO_wbaes16384;
    else if (t==(uint16_t)CRYPTO_ALGO::ALGO_wbaes32768) return CRYPTO_ALGO::ALGO_wbaes32768;
    return CRYPTO_ALGO::ALGO_NONE;
}
inline std::string token_wbaes_algo(CRYPTO_ALGO t)
{
    std::string s = algo_wbaes_name(t);
    if (s.size() > 0)
    {
        return "[" + s + "]";
    }
    return "";
}


enum class CRYPTO_FILE_TYPE : uint32_t
{
	Unknown 	= 0,
	CryptoPack	= 100,
    RAW 		= 200,
    PuzzleQA 	= 300,
    RSA_PUBLIC 	= 400,
	ECC_DOMAIN 	= 500,
	ECC_PUBLIC 	= 550,
	HH_PUBLIC 	= 600,
	RAW_LOCAL 	= 700,
	RSA_KEY_STATUS 	= 1000, // Public RSA keys requiring receive confirmation or deletion (marked for delete)
	ECC_KEY_STATUS 	= 1010,
	ECC_DOM_STATUS 	= 1030,
	HH_KEY_STATUS 	= 1040,
	CryptoEncoder = 9999
};


//constexpr E b = to_enum<E>(200);
template< typename E , typename T>
constexpr inline typename std::enable_if< std::is_enum<E>::value &&
                                          std::is_integral<T>::value, E
                                         >::type
 to_enum( T value ) noexcept
 {
     return static_cast<E>( value );
 }

constexpr static uint32_t BASE              = 255*256; // BASE*BASE >= FILE_SIZE_LIM, BASE < 256*256 (64k)
constexpr static int16_t MAGIC_SIZE         = 4;
constexpr static int16_t KEYPOS_ENCODESIZE  = 8;
constexpr static int16_t URL_LEN_ENCODESIZE = 2;
constexpr static int16_t CRYPTO_ALGO_ENCODESIZE = 2;
constexpr static uint32_t URL_MIN_SIZE      = 4;
constexpr static uint32_t URL_MAX_SIZE      = 64*16; // Multiple RSA/ECC keys name;size // TODO  make it dynamic (any size)

constexpr static uint32_t MIN_KEY_SIZE      = 64;
constexpr static int16_t CHKSUM_SIZE        = 64;
constexpr static int16_t PADDING_LEN_ENCODESIZE = 2;
constexpr static uint32_t RSA_LEN_ENCODESIZE = 4;   // RSA/ECC
constexpr static uint32_t RSA_POS_ENCODESIZE = 4;   // RSA/ECC
constexpr static uint32_t RSA_PAD_ENCODESIZE = 4;   // RSA/ECC
constexpr static uint32_t CRYPTO_FLAGS_ENCODESIZE   = 4;
constexpr static uint32_t CRYPTO_SHUFFLE_ENCODESIZE = 4;

constexpr static uint32_t URLINFO_SIZE      =   URL_LEN_ENCODESIZE + URL_MAX_SIZE +
                                                MAGIC_SIZE +
                                                KEYPOS_ENCODESIZE  +
                                                CHKSUM_SIZE +	// key
												CHKSUM_SIZE +	// data
                                                MIN_KEY_SIZE +
                                                CRYPTO_ALGO_ENCODESIZE +
												RSA_LEN_ENCODESIZE +
												RSA_POS_ENCODESIZE +
												RSA_PAD_ENCODESIZE +
												CRYPTO_FLAGS_ENCODESIZE +
												CRYPTO_SHUFFLE_ENCODESIZE +
												PADDING_LEN_ENCODESIZE + 26; // padding 64

constexpr static int16_t PADDING_MULTIPLE       = 64; // data should be at least 64x with Salsa20 requirement
constexpr static int16_t PADDING_KEY_MULTIPLE   = 32; //  key should be at least 32x with Salsa20 requirement
constexpr static int16_t NITER_LIM              = 2048;
constexpr static uint32_t FILE_SIZE_LIM         = 256*1024*1024;

const std::string QA_TOKEN              = "QA";
const std::string REM_TOKEN             = "REM";
const std::string BLOCK_START_TOKEN     = "BLOCK_START";
const std::string BLOCK_END_TOKEN       = "BLOCK_END";
const std::string CHKSUM_TOKEN          = "CHKSUM";

constexpr static uint32_t CRYPTO_HEADER_SIZE = 64+64;
constexpr static int16_t HINT_SIZE           = 32+64-4;
struct CRYPTO_HEADER {
    char sig[6];                                // File Signature (CRYPTO)
    std::uint16_t version;                      // Format Version
    std::uint32_t enc_puzzle_size;              // Size of encrypted puzzle
    std::uint32_t enc_puzzle_padding_size;      // Size of encrypted puzzle before padding
    std::uint32_t enc_data_size;                // Size of encrypted data before padding
    std::uint32_t enc_data_padding_size;
    std::uint32_t crc_enc_data_hash;            // CRC32 hash of encrypted data before padding
    std::uint32_t crc_enc_puzzle_hash;
    std::uint32_t crc_enc_puzzle_key_hash = 0;  // 0 if no enc key for puzzle
    char enc_puzzle_key_hint[HINT_SIZE];        // Encrypted Puzzle Extract Key Hint
};
static_assert(sizeof(CRYPTO_HEADER) == CRYPTO_HEADER_SIZE);

}

#endif

