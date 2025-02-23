#ifndef _INCLUDES_crypto_test
#define _INCLUDES_crypto_test

#include "crypto_const.hpp"
#include "file_util.hpp"
#include "crypto_file.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "DES.h"
#include "AESa.h"
#include "twofish.h"
#include "Salsa20.h"
#include "IDEA.hpp"
#include "qa/aes-whitebox/aes_whitebox.h"

namespace cryptoAL
{

// ./crypto test -i manywebkey
void DOTESTCASE(std::string TEST, std::string folder, bool disable_netw = false, bool verb = false, std::string file_msg = "/msg.txt")
{
    std::string TESTCASE = "testcase";
    std::string FOLDER;

    if (folder.size()==0)
    {
#ifdef _WIN32
        FOLDER = "../../../../";
#else
        FOLDER = "./../../";
#endif
    }
    else
    {
        FOLDER = folder;
    }

    if(std::filesystem::is_directory(FOLDER)==false)
    {
        std::cerr << "ERROR test folder is not a directory " << FOLDER << std::endl;
        return;
    }

    std::string file_url            = "/urls.txt";
    std::string file_puzzle         = "/puzzle.txt";
    std::string file_msg_decrypted  = "/msg_decrypted.dat";
    std::string file_partial_puzzle = "/partial_puzzle.txt";
    std::string file_full_puzzle    = "/full_puzzle.txt";
    std::string file_msg_encrypted  = "/msg_encrypted.dat";

    std::cout << "TESTCASE " + TEST << std::endl;
    std::string BASE_FOLDER = FOLDER + TESTCASE + "/" + TEST;
    {
        std::string file = BASE_FOLDER + file_partial_puzzle;
        if (file_util::fileexists(file))
            std::remove(file.data());

		file = BASE_FOLDER + file_msg_encrypted;
		if (file_util::fileexists(file))
            std::remove(file.data());

        file = BASE_FOLDER+ file_puzzle;
        if (file_util::fileexists(file) == false)
        {
            std::cout << "ERROR missing puzzle file " << file <<  std::endl;
            return;
        }

        file = BASE_FOLDER + file_msg;
        if (file_util::fileexists(file) == false)
        {
            std::cout << "ERROR missing msg file " << file <<  std::endl;
            return;
        }

        encryptor encr( "",
                        BASE_FOLDER + file_url,
                        BASE_FOLDER + file_msg,
                        BASE_FOLDER + file_puzzle,
                        BASE_FOLDER + file_partial_puzzle,
                        BASE_FOLDER + file_full_puzzle,
                        BASE_FOLDER + file_msg_encrypted,
                        "",
                        "",
                         "", "","", "",
                        "", "","",
                        "",
                        verb);

        if (encr.encrypt(disable_netw) == true)
        {
            decryptor decr( "",
                            encr.filename_full_puzzle,
                            encr.filename_encrypted_data,
                            FOLDER + TESTCASE + "/" + TEST + file_msg_decrypted,
                            "",
                            "","", "",
                            "", "","","", "",
                            "",
                            verb
                          );

            if (decr.decrypt() == true)
            {
                if( file_util::is_file_same(encr.filename_msg_data, decr.filename_decrypted_data) == false)
                {
                    std::cout << TESTCASE + " " + TEST + " - ERROR encrypt- decrypt failed " << std::endl;
                }
                else
                {
                    std::cout << "SUCCESS " + TESTCASE + " " + TEST << std::endl;
                }
            }
            else
            {
                std::cout << TESTCASE + " " + TEST + " - ERROR decrypt " << std::endl;
            }
        }
        else
        {
            std::cout << TESTCASE + " " + TEST + " - ERROR encrypt " << std::endl;
        }
    }
    std::cout << std::endl;
}

void test_core(bool verbose = true)
{
    verbose = verbose;

   // TEST makehex() <=> hextobin()
    if (true)
    {
        std::cout << "\nTEST HEX"<< std::endl;
        std::cout << "bin 255 to hex2 " << makehex((char)255, 2) << std::endl;
        std::cout << "bin 128 to hex2 " << makehex((char)128, 2) << std::endl;
        std::cout << "bin 0 to hex2 "   << makehex((char)0  , 2) << std::endl;
        std::cout << "bin 256*10+5 to hex4 "   << makehex((uint32_t)2565  , 4) << std::endl;

        std::cout << "hex2 " << makehex((char)255, 2) << " to uint8_t " << (int)hextobin(makehex((char)255, 2), uint8_t(0)) << std::endl;
        std::cout << "hex4 " << makehex((uint32_t)2565  , 4) << " to uint32_t " << (int)hextobin(makehex((uint32_t)2565  , 4), uint32_t(0)) << std::endl;

        Buffer b(4);
        uint32_t n = 30*256*256*256 + 20*256*256 + 10*256 + 5;
        b.writeUInt32(n, 0);
        uint32_t nn = b.readUInt32(0);
        if (n != nn)
        {
            std::cout << "Error with writeUInt32 readUInt32"<<std::endl;
            std::cout << n << " " << nn << std::endl;
        }
        else
        {
            std::cout << "OK with writeUInt32 readUInt32"<<std::endl;
        }
    }


    if (true)
    {
        idea algo;

        uint8_t KEY[16]    = {0x12, 0x00, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};
        uint8_t DATA[8]    = {0x11, 0x12, 0x00, 0x78, 0x00, 0xbc, 0xde, 0xde};

        uint16_t copydata[4];
        uint16_t data[4];
        uint16_t key[8];
        uint16_t data2[4];

        for(int i=0;i<8;i++)
        {
            key[i] = 256*KEY[2*i] + KEY[2*i+1];
        }
        for(int i=0;i<4;i++)
        {
            data[i] = 256*DATA[2*i] + DATA[2*i+1];
            copydata[i] = data[i];
        }

        algo.IDEA(data, key, true);

        {

            for(int i=0;i<4;i++)
            {
                data2[i] = data[i];
            }

            algo.IDEA(data2, key, false);
        }

        // Print initial data
//        printf("Initial data:   %04X %04X %04X %04X\n", copydata[0], copydata[1], copydata[2], data[3]);
//        printf("Encrypted data: %04X %04X %04X %04X\n", data[0], data[1], data[2], data[3]);
//        printf("Decrypted data: %04X %04X %04X %04X\n", data2[0], data2[1], data2[2], data2[3]);

        bool ok = true;
        for(size_t i=0;i<4;i++)
        {
            if (copydata[i] != data2[i])
            {
                std::cout << "Error with IDEA "<< i <<std::endl;
                std::cout << (int)data[i]<<std::endl;
                std::cout << (int)data2[i]<<std::endl;
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::cout << "OK with IDEA encrypt decrypt " << std::endl;
        }
    }

        if (true)
    {
        idea algo;

        uint8_t KEY[16]    = {0x12, 0x00, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};
        uint8_t DATA[8]    = {0x11, 0x12, 0x00, 0x78, 0x00, 0xbc, 0xde, 0xde};
        uint8_t DATA1[8]   = {0x11, 0x12, 0x00, 0x78, 0x00, 0xbc, 0xde, 0xde};

        algo.IDEA(DATA1, KEY, true);
        algo.IDEA(DATA1, KEY, false);

        bool ok = true;
        for(size_t i=0;i<4;i++)
        {
            if (DATA[i] != DATA1[i])
            {
                std::cout << "Error with IDEA "<< i <<std::endl;
                std::cout << (int)DATA[i]<<std::endl;
                std::cout << (int)DATA1[i]<<std::endl;
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::cout << "OK with IDEA encrypt decrypt " << std::endl;
        }
    }

    if (true)
    {
        /**
         * \brief Constructs cypher with given key.
         * \param[in] key 256-bit key
         */
        uint8_t key[32]  = {0x12, 0x34, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                            0x12, 0x34, 0x00, 0x78, 0x9a, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde};

        ucstk::Salsa20 s20(key);

        /**
         * \brief Sets IV.
         * \param[in] iv 64-bit IV
         */
        uint8_t iv[8]  = {0x12, 0x01, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};
        s20.setIv(iv);

         /**
         * \brief Processes blocks.
         * \param[in] input input
         * \param[out] output output
         * \param[in] numBlocks number of blocks
         */
//        enum: size_t
//        {
//                VECTOR_SIZE = 16,
//                BLOCK_SIZE = 64,
//                KEY_SIZE = 32,
//                IV_SIZE = 8
//        };
        uint8_t data[64] = {0x11, 0x12, 0x13, 0x78, 0x00, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                            0x12, 0x34, 0x00, 0x78, 0x9a, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                            0x11, 0x12, 0x13, 0x78, 0x00, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                            0x12, 0x34, 0x00, 0x78, 0x9a, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde
                            };
        uint8_t enc[64]= {0};
        uint8_t dec[64]= {0};

        s20.processBlocks(data, enc, 1);

        {
            uint8_t sskey[32]  = {  0x12, 0x34, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                                    0x12, 0x34, 0x00, 0x78, 0x9a, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde};
            ucstk::Salsa20 ss20(sskey);
            ss20.setIv(iv);
            ss20.processBlocks(enc, dec, 1);
        }

        bool ok = true;
        for(size_t i=0;i<64;i++)
        {
            if (data[i] != dec[i])
            {
                std::cout << "Error with Salsa20 "<< i <<std::endl;
                std::cout << (int)data[i]<<std::endl;
                std::cout << (int)dec[i]<<std::endl;
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::cout << "OK with Salsa20 encrypt decrypt " << std::endl;
        }
    }

    if (true)
    {
        int  r = Twofish_initialise();
        if (r < 0)
        {
            std::cout << "Error with Twofish_initialise " <<r << std::endl;
        }
        else
        {
            std::cout << "OK with Twofish_initialise "<< std::endl;

            Twofish_Byte key[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,  0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde};
            Twofish_key xkey;
            r = Twofish_prepare_key( key, 16, &xkey );
            if (r < 0)
            {
                std::cout << "Error with Twofish Twofish_prepare_key " << r << std::endl;
            }
            else
            {
                std::cout << "OK with Twofish Twofish_prepare_key " << r << std::endl;

                Twofish_Byte p[16] = {0x12, 0x34, 0x56, 0x00, 0x9a, 0xbc, 0xde, 0x12, 0x34, 0x00, 0x78, 0x9a, 0xbc, 0xde, 0xbc, 0xde};
                Twofish_Byte c[16] = {0};
                Twofish_Byte d[16] = {0};
                Twofish_encrypt(&xkey, p, c);
                Twofish_decrypt(&xkey, c, d);

                bool ok = true;
                for(size_t i=0;i<16;i++)
                {
                    if (p[i] != d[i])
                    {
                        std::cout << "Error with Twofish_encrypt  Twofish_decrypt"<< i <<std::endl;
                        std::cout << (int)p[i]<<std::endl;
                        std::cout << (int)d[i]<<std::endl;
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    std::cout << "OK with Twofish_encrypt  Twofish_decrypt " << std::endl;
                }
            }
        }
    }

    // FAILED
    if (false)
    {
        //Unlike most Twofish implementations, this one allows any key size from * 0 to 32 byte
        int  r = Twofish_initialise();
        if (r < 0)
        {
            std::cout << "Error with Twofish_initialise 32 " <<r << std::endl;
        }
        else
        {
            std::cout << "OK with Twofish_initialise 32 "<< std::endl;

            Twofish_Byte key[] = {  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde};
            Twofish_key xkey;
            r = Twofish_prepare_key( key, 32, &xkey );
            if (r < 0)
            {
                std::cout << "Error with Twofish 32 Twofish_prepare_key " << r << std::endl;
            }
            else
            {
                std::cout << "OK with Twofish 32 Twofish_prepare_key " << r << std::endl;

                Twofish_Byte p[32] = {  0x11, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
                                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde};
                Twofish_Byte c[32] = {0};
                Twofish_Byte d[32] = {0};
                Twofish_encrypt(&xkey, p, c);
                Twofish_decrypt(&xkey, c, d);

                bool ok = true;
                for(size_t i=0;i<32;i++)
                {
                    if (p[i] != d[i])
                    {
                        std::cout << "Error with Twofish_encrypt  Twofish_decrypt 32 "<< i <<std::endl;
                        std::cout << (int)p[i]<<std::endl;
                        std::cout << (int)d[i]<<std::endl;
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    std::cout << "OK with Twofish_encrypt  Twofish_decrypt 32" << std::endl;
                }
            }
        }
    }


    if (true)
    {
        unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        unsigned char key[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

        binAES aes(AESKeyLength::AES_128);  //key length, can be 128, 192 or 256
        auto e = aes.EncryptECB(plain, plainLen, key);
        auto p = aes.DecryptECB(e, plainLen, key);
        //now variable c contains plainLen bytes - ciphertext

        for(size_t i=0;i<16;i++)
        {
            if (p[i] != plain[i])
            {
                std::cout << "Error with binary AES 128 algo "<< i <<std::endl;
                std::cout << (int)p[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with binary AES 128 algo "<<std::endl;
    }

    if (true)
    {
        unsigned char plain[] = { 	0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x30, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        unsigned char key[]   = { 	0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x40, 0x21, 0x22, 0x23, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        unsigned int plainLen = 32 * sizeof(unsigned char);  //bytes in plaintext

        binAES aes(AESKeyLength::AES_256);  //  key length, can be 128, 192 or 256
        auto e = aes.EncryptECB(plain, plainLen, key);
        auto p = aes.DecryptECB(e, plainLen, key);
        //now variable c contains plainLen bytes - ciphertext

        for(size_t i=0;i<32;i++)
        {
            if (p[i] != plain[i])
            {
                std::cout << "Error with binary AES 256 ECB algo "<< i <<std::endl;
                std::cout << (int)p[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with binary AES 256 ECB algo "<<std::endl;
    }
	if (true)
    {
        unsigned char plain[] = { 	0x81, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x80, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        unsigned char key[]   = { 	0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x80, 0x21, 0x22, 0x23, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        unsigned int plainLen = 32 * sizeof(unsigned char);  //bytes in plaintext
        const unsigned char iv[32] = {
                        0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x66, 0x77, 0x88, 0x93, 0x04, 0x99, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

        binAES aes(AESKeyLength::AES_256);  //  key length, can be 128, 192 or 256
        auto e = aes.EncryptCFB(plain, plainLen, key, iv);
        auto p = aes.DecryptCFB(e, plainLen, key, iv);
        //now variable c contains plainLen bytes - ciphertext

        for(size_t i=0;i<32;i++)
        {
            if (p[i] != plain[i])
            {
                std::cout << "Error with binary AES 256 CFB algo "<< i <<std::endl;
                std::cout << (int)p[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with binary AES 256 CFB algo "<<std::endl;
    }
	if (true)
    {
        unsigned char plain[] = { 	0x51, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x70, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        unsigned char key[]   = { 	0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x88, 0x21, 0x22, 0x23, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        unsigned int plainLen = 32 * sizeof(unsigned char);  //bytes in plaintext
        const unsigned char iv[32] = {
                        0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x66, 0x77, 0x88, 0x93, 0x04, 0x99, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

        binAES aes(AESKeyLength::AES_256);  //  key length, can be 128, 192 or 256
        auto e = aes.EncryptCBC(plain, plainLen, key, iv);
        auto p = aes.DecryptCBC(e, plainLen, key, iv);
        //now variable c contains plainLen bytes - ciphertext

        for(size_t i=0;i<32;i++)
        {
            if (p[i] != plain[i])
            {
                std::cout << "Error with binary AES 256 CBC algo "<< i <<std::endl;
                std::cout << (int)p[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with binary AES 256 CBC algo "<<std::endl;
    }
/*
	if (true)
    {
        unsigned char plain[] = { 	0x51, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x70, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
									0x51, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x70, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,}; //plaintext example
		unsigned char plaincopy[] = { 	0x51, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x70, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
									0x51, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf,
									0x70, 0x31, 0x32, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,}; //plaintext example
		unsigned char eout[64] = {0};
		unsigned char dout[64] = {0};

		//NO KEY!!!!!!!!!!!!!!!!!!
        unsigned char key[]   = { 	0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x88, 0x21, 0x22, 0x23, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
									0x88, 0x21, 0x22, 0x23, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,}; //key example

		unsigned int plainLen = 64 * sizeof(unsigned char);  //bytes in plaintext
        const unsigned char iv[16] = {
                        0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};


		//void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,size_t len, uint8_t* c);
		//void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,size_t len, uint8_t* m);

		// aes 512
		std::cout << "AES 512 message: ";
		for(size_t i=0;i<plainLen;i++) std::cout << (int)plain[i];
		std::cout <<std::endl;

		aes_whitebox_encrypt_cfb(iv, plaincopy, plainLen, eout);
		std::cout << "AES 512 encrypt: ";
		for(size_t i=0;i<plainLen;i++) std::cout << (int)eout[i];
		std::cout <<std::endl;

		aes_whitebox_decrypt_cfb(iv, eout, plainLen, dout);
		std::cout << "AES 512 decrypt: ";
		for(size_t i=0;i<plainLen;i++) std::cout << (int)dout[i];
		std::cout <<std::endl;

		for(size_t i=0;i<plainLen;i++)
        {
            if (dout[i] != plain[i])
            {
                std::cout << "Error with binary AES 512 cfb algo "<< i <<std::endl;
                std::cout << (int)dout[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with binary AES 512 cfb algo "<<std::endl;
    }
*/

    // TEST CLASSIC STRING DES
    if (false)
    {
        std::cout << "\nTEST CLASSIC STRING DES"<< std::endl;
        std::string KEY  = "EWTW;RLd"; // 8 bytes l peut exister 2e56 (soit 7.2*10e16) clés différentes !
        std::string data = "65431234"; // 8 bytes

        DES des(KEY);
        std::string data_encr = des.encrypt(data);
        std::string data_back = des.decrypt(data_encr);
        if (data != data_back)
        {
            std::cout << "Error with DES algo"
            << "\nkey " << KEY
            << "\ndata " << data
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
        else
        {
            std::cout << "OK with DES algo "
            << "\nkey " << KEY
            << "\ndata " << data
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }

    // TEST BINARYE DES
    if (false)
    {
        std::cout << "\nTEST BINARYE DES"<< std::endl;
        char bin[4] = {12, 0, 34, 0}; // bin 4 => string 8
        char dat[4] = {33, 5, 12, 0}; // bin 4 => string 8
        char out_dat[4];

        DES des(bin);
        std::string data_encr = des.encrypt_bin(dat, 4);
        des.decrypt_bin(data_encr, out_dat, 4);

        std::string data_back  = "{";
        for(size_t i=0;i<4;i++)
        {
            data_back+=std::to_string((int)out_dat[i]);
            data_back+=",";
        }
        data_back += "}";

        bool ok = true;
        for(size_t i=0;i<4;i++)
        {
            if (dat[i] != out_dat[i])
            {
                std::cout << "Error with DES binary algo"
                //<< "\nkey " << KEY
                << "\ndata {33, 5, 12, 0}"
                //<< "\ndata_encr " << data_encr
                << "\ndata_back " << data_back
                << std::endl;
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::cout << "OK with DES binary algo "
            //<< "\nkey " << KEY
            << "\ndata {33, 5, 12, 0}"
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }

    if (false)
    {
        std::cout << "\nTEST encode FTP user:pwd"<< std::endl;
        std::string user;
        std::string pwd;
        std::string key;

        std::cout << "ENTER a pwd to encode ftp user:pwd"<< std::endl;
        std::cin >> key;

        std::cout << "ENTER ftp user:";
        std::cin >> user;
        auto su = encrypt_simple_string(user, key);
        std::cout << "Your encrypted ftp user is : " << su << std::endl;

        std::cout << "ENTER ftp pwd:";
        std::cin >> pwd;
        auto sp = encrypt_simple_string(pwd, key);
        std::cout << "Your encrypted ftp pwd is : " << sp << std::endl;

        auto su2 = decrypt_simple_string(su, key);
        auto sp2 = decrypt_simple_string(sp, key);

        if (user != su2)
        {
            std::cout << "Error cannot decode the encrypted user " << std::endl;
        }
        if (pwd != sp2)
        {
            std::cout << "Error cannot decode the encrypted pwd " << std::endl;
        }
    }

    // TEST wget
    if (false)
    {
        std::cout << "\nTEST wget"<< std::endl;
        std::string url = "https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz";
        std::string filename  = "./staging_Python-3.8.1.tgz";
        if (file_util::fileexists(filename))
		    std::remove(filename.data());

        if ( key_file::wget(url.data(), filename.data()) != 0)
        {
            std::cout << "ERROR with wget " << std::endl;
        }
        else
        {
         if (file_util::filesize(filename) > 0)
                std::cout << "OK with wget" << std::endl;
            else
                std::cout << "ERROR with wget remote access, file empty " << url << std::endl;
        }
        if (file_util::fileexists(filename))
		    std::remove(filename.data());
    }

    // TEST wget - FAILED
    if (false)
    {
        std::cout << "\nTEST wget"<< std::endl;
        std::string url = "https://github.com/alanthie/Encryptions/raw/master/modes/CBC.cpp";
        std::string filename  = "./staging_CBC.cpp";
        if (file_util::fileexists(filename))
		    std::remove(filename.data());

        if ( key_file::wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            if (file_util::filesize(filename) > 0)
                std::cout << "OK with wget" << std::endl;
            else
                std::cout << "ERROR with wget remote access, file empty " << url << std::endl;
        }
        if (file_util::fileexists(filename))
		    std::remove(filename.data());
    }

    // VIDEO
    if (false)
    {
        std::cout << "\nTEST loading video with youtube-dl"<< std::endl;
#ifdef _WIN32
        std::string url = "https://www.bitchute.com/video/JjqRgjv5GJmW";
#else
        std::string url = "https://www.bitchute.com/video/JjqRgjv5GJmW";
#endif
        std::string filename  = "./staging_video_bitchute.mp4";
        std::string options   = "";

        if (file_util::fileexists(filename))
		    std::remove(filename.data());

        int r = key_file::getvideo(url, filename, options);
        if (r < 0)
        {
            std::cout << "OK with getvideo, code:" << r << std::endl;
        }
        else
        {
            if (file_util::filesize(filename) > 0)
                std::cout << "OK with getvideo" << std::endl;
            else
                std::cout << "ERROR with getvideo (bitchute) remote access, file empty " << url << std::endl;
        }

        if (file_util::fileexists(filename))
		    std::remove(filename.data());
    }

    // FTP
    if (false)
    {
        std::cout << "\nTEST loading with FTP user:pwd"<< std::endl;
        std::string user;
        std::string pwd;

        std::cout << "ENTER ftp user:";
        std::cin >> user;

        std::cout << "ENTER ftp pwd:";
        std::cin >> pwd;

        std::string filename  = "./staging_ftp_Buffer.hpp";
        if (file_util::fileexists(filename))
		    std::remove(filename.data());

        std::string cmd = "ftp://" + user + ":" + pwd + "@ftp.vastserve.com/htdocs/Buffer.hpp";
        if ( key_file::wget(cmd.data(), filename.data()) != 0)
        {
            std::cout << "ERROR with wget ftp://.." << std::endl;
        }
        else
        {
            if (file_util::filesize(filename) > 0)
                std::cout << "OK with wget ftp://.." << std::endl;
            else
                std::cout << "ERROR with wget ftp://... remote access, file empty " << "ftp.vastserve.com/htdocs/Buffer.hpp" << std::endl;
        }

        if (file_util::fileexists(filename))
		    std::remove(filename.data());
    }

    //https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6
    if (false)
    {
        //Sync public TerrePlane (Flat earth) img.pgn
        //std::string url = "https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6";
        // EXTRACT TEMPORARY BLOB

        //std::string url = "https://cp.sync.com/9a4886a8-b1b3-4a2c-a3c7-4b0c01d76486";
        //std::string url = "https://cp.sync.com/file/1342219113/view/image";
        std::string url = "https://u.pcloud.link/publink/show?code=XZH2QgVZC4KuzbwhtBmqrvCrpMQhTzAkOd2V";
        //"downloadlink": "https:\/\/vc577.pcloud.com\/dHZTgqwh1ZJ8HkagZZZC9s5o7Z2ZZLH4ZkZH2QgVZXgFPoVee7xjlQn2NAj6oUHSJKlPy\/Screenshot%20from%202021-06-16%2014-28-40.png",

        //"downloadlink": " // EXPIRED
        //std::string url = "https://c326.pcloud.com/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7/Screenshot%20from%202021-06-16%2014-28-40.png";
        //"https:\/\/c326.pcloud.com\/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7\/Screenshot%20from%202021-06-16%2014-28-40.png"
        std::string filename  = "./staging_img_header.txt";
        std::remove(filename.data());

        if ( key_file::wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << std::endl;
        }
//        if (file_util::fileexists(filename))
//		    std::remove(filename.data());
    }
}

}
#endif

