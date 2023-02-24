#ifndef _INCLUDES_crypto_test
#define _INCLUDES_crypto_test

#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "Encryptions/AES.h"
#include "Encryptions/DES.h"
#include "AESa.h"

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

    if(fs::is_directory(FOLDER)==false)
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

    {
        std::string file = FOLDER + TESTCASE+ "/" + TEST+file_partial_puzzle;
        if (fileexists(file))
            std::remove(file.data());

		file = FOLDER + TESTCASE+"/"+TEST+file_msg_encrypted;
		if (fileexists(file))
            std::remove(file.data());

        file = FOLDER + TESTCASE + "/" + TEST + file_puzzle;
        if (fileexists(file) == false)
        {
            std::cout << "ERROR missing puzzle file " << file <<  std::endl;
            return;
        }

        file = FOLDER + TESTCASE + "/" + TEST + file_msg;
        if (fileexists(file) == false)
        {
            std::cout << "ERROR missing msg file " << file <<  std::endl;
            return;
        }

        encryptor encr( FOLDER + TESTCASE + "/" + TEST + file_url,
                        FOLDER + TESTCASE + "/" + TEST + file_msg,
                        FOLDER + TESTCASE + "/" + TEST + file_puzzle,
                        FOLDER + TESTCASE + "/" + TEST + file_partial_puzzle,
                        FOLDER + TESTCASE + "/" + TEST + file_full_puzzle,
                        FOLDER + TESTCASE + "/" + TEST + file_msg_encrypted,
                        "",
                        "",
                        verb);

        if (encr.encrypt(disable_netw) == true)
        {
            decryptor decr( encr.filename_full_puzzle,
                            encr.filename_encrypted_data,
                            FOLDER + TESTCASE + "/" + TEST + file_msg_decrypted,
                            "",
                            "",
                            verb
                          );

            if (decr.decrypt() == true)
            {
                if( is_file_same(encr.filename_msg_data, decr.filename_decrypted_data) == false)
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
            std::cout << n << " " << nn << std::endl;
        }
    }

    if (true)
    {
        // parameters
        const std::string raw_data = "Hello, plusaes";
        const std::vector<unsigned char> key = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        };

        // encrypt
        const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
        std::vector<unsigned char> encrypted(encrypted_size);

        plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);
        // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

        // decrypt
        unsigned long padded_size = 0;
        std::vector<unsigned char> decrypted(encrypted_size);

        plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);
        // Hello, plusaes
        for(size_t i=0;i<16;i++)
        {
            if (decrypted[i] != raw_data[i])
            {
                std::cout << "Error with string AES algo "<< i <<std::endl;
                std::cout << (int)decrypted[i]<<std::endl;
                std::cout << (int)raw_data[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with string AES algo "<<std::endl;
    }

    if (true)
    {
//        const unsigned char iv[16] = {
//            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
//
//        //unsigned char KEY[16+1] = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00};
//        unsigned char KEY[16+1] = "1234567812345678";
//		//unsigned char DATA[16+1]= {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00};
//		unsigned char DATA[16+1]= "1234567812345678";
//        unsigned char encrypted[32+1];
//        unsigned char decrypted[32+1];
//		// encrypt
//        //const unsigned long encrypted_size = 16;//plusaes::get_padded_encrypted_size(raw_data.size());
//        //std::vector<unsigned char> encrypted(encrypted_size);
//        plusaes::encrypt_cbc(&DATA[0], 16, &KEY[0], 16, &iv, &encrypted[0], 16, false);
//
//        unsigned long padded_size = 0;
//        //std::vector<unsigned char> decrypted(16);
//        plusaes::decrypt_cbc(   &encrypted[0], 16, &KEY[0], 16, &iv,
//                                &decrypted[0], 16, &padded_size);

        unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        unsigned char key[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

        binAES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
        auto e = aes.EncryptECB(plain, plainLen, key);
        auto p = aes.DecryptECB(e, plainLen, key);
        //now variable c contains plainLen bytes - ciphertext

        for(size_t i=0;i<16;i++)
        {
            if (p[i] != plain[i])
            {
                std::cout << "Error with 2 bin AES algo "<< i <<std::endl;
                std::cout << (int)p[i]<<std::endl;
                std::cout << (int)plain[i]<<std::endl;
                break;
            }
        }
        std::cout << "OK with biary AES algo "<<std::endl;
    }


    // TEST CLASSIC STRING AES
    if (false)
    {
        std::cout << "\nTEST CLASSIC STRING AES"<< std::endl;
        std::string KEY  = std::string("EWTW;RLd")+std::string("hgjhfg88");   // 16 24 32 bytes
        std::string data = std::string("65431234")+std::string("3bhgfdfg");   // 16 bytes

        AES aes(KEY);
        std::string data_encr = aes.encrypt(data);
        std::string data_back = aes.decrypt(data_encr);
        if (data != data_back)
        {
            std::cout << "Error with AES algo"
            << "\nkey " << KEY
            << "\ndata " << data
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
        else
        {
            std::cout << "OK with AES algo "
            << "\nkey " << KEY
            << "\ndata " << data
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }

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
        if (fileexists(filename))
		    std::remove(filename.data());

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "ERROR with wget " << std::endl;
        }
        else
        {
         if (filesize(filename) > 0)
                std::cout << "OK with wget" << std::endl;
            else
                std::cout << "ERROR with wget remote access, file empty " << url << std::endl;
        }
        if (fileexists(filename))
		    std::remove(filename.data());
    }

    // TEST wget - FAILED
    if (false)
    {
        std::cout << "\nTEST wget"<< std::endl;
        std::string url = "https://github.com/alanthie/Encryptions/raw/master/modes/CBC.cpp";
        std::string filename  = "./staging_CBC.cpp";
        if (fileexists(filename))
		    std::remove(filename.data());

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            if (filesize(filename) > 0)
                std::cout << "OK with wget" << std::endl;
            else
                std::cout << "ERROR with wget remote access, file empty " << url << std::endl;
        }
        if (fileexists(filename))
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

        if (fileexists(filename))
		    std::remove(filename.data());

        int r = getvideo(url, filename, options);
        if (r < 0)
        {
            std::cout << "OK with getvideo, code:" << r << std::endl;
        }
        else
        {
            if (filesize(filename) > 0)
                std::cout << "OK with getvideo" << std::endl;
            else
                std::cout << "ERROR with getvideo (bitchute) remote access, file empty " << url << std::endl;
        }

        if (fileexists(filename))
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
        if (fileexists(filename))
		    std::remove(filename.data());

        std::string cmd = "ftp://" + user + ":" + pwd + "@ftp.vastserve.com/htdocs/Buffer.hpp";
        if ( wget(cmd.data(), filename.data()) != 0)
        {
            std::cout << "ERROR with wget ftp://.." << std::endl;
        }
        else
        {
            if (filesize(filename) > 0)
                std::cout << "OK with wget ftp://.." << std::endl;
            else
                std::cout << "ERROR with wget ftp://... remote access, file empty " << "ftp.vastserve.com/htdocs/Buffer.hpp" << std::endl;
        }

        if (fileexists(filename))
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

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << std::endl;
        }
//        if (fileexists(filename))
//		    std::remove(filename.data());
    }
}


#endif

