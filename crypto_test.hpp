#ifndef _INCLUDES_crypto_test
#define _INCLUDES_crypto_test

#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"

// ./crypto test -i manywebkey
void DOTESTCASE(std::string TEST, bool disable_netw = false, bool verb = false, std::string file_msg = "/msg.txt")
{
    std::string TESTCASE = "testcase";

#ifdef _WIN32
    std::string FOLDER = "../../../../";
#else
    std::string FOLDER = "./../../";
#endif

    std::string file_url            = "/urls.txt";
    std::string file_puzzle         = "/puzzle.txt";
    std::string file_msg_decrypted  = "/msg_decrypted.dat";
    std::string file_partial_puzzle = "/partial_puzzle.txt";
    std::string file_msg_encrypted  = "/msg_encrypted.dat";

    std::cout << "TESTCASE " + TEST << std::endl;

    {
        std::string file = FOLDER + TESTCASE+ "/" + TEST+file_partial_puzzle;
        if (fileexists(file))
            std::remove(file.data());

		file = FOLDER + TESTCASE+"/"+TEST+file_msg_encrypted;
		if (fileexists(file))
            std::remove(file.data());

        file = FOLDER + TESTCASE + "/" +TEST+file_puzzle;
        if (fileexists(file) == false)
        {
            std::cout << "ERROR missing puzzle file " << file <<  std::endl;
            return;
        }

        file = FOLDER +TESTCASE+"/"+TEST+file_msg;
        if (fileexists(file) == false)
        {
            std::cout << "ERROR missing msg file " << file <<  std::endl;
            return;
        }

        encryptor encr( FOLDER +TESTCASE+"/"+TEST+file_url,
                        FOLDER+TESTCASE+"/"+TEST+file_msg,
                        FOLDER+TESTCASE+"/"+TEST+file_puzzle,
                        FOLDER +TESTCASE+"/"+TEST+file_partial_puzzle,
                        FOLDER +TESTCASE+"/"+TEST+file_msg_encrypted,
                        verb);

        if (encr.encrypt(disable_netw) == true)
        {
            decryptor decr( encr.filename_full_puzzle,
                            encr.filename_encrypted_data,
                            FOLDER +TESTCASE+"/"+TEST+file_msg_decrypted,
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
        std::cout << "bin 255 to hex2 " << makehex((char)255, 2) << std::endl;
        std::cout << "bin 128 to hex2 " << makehex((char)128, 2) << std::endl;
        std::cout << "bin 0 to hex2 "   << makehex((char)0  , 2) << std::endl;
        std::cout << "bin 256*10+5 to hex4 "   << makehex((uint32_t)2565  , 4) << std::endl;

        std::cout << "hex2 " << makehex((char)255, 2) << " to uint8_t " << (int)hextobin(makehex((char)255, 2), uint8_t(0)) << std::endl;
        std::cout << "hex4 " << makehex((uint32_t)2565  , 4) << " to uint32_t " << (int)hextobin(makehex((uint32_t)2565  , 4), uint32_t(0)) << std::endl;
    }

    // TEST CLASSIC STRING DES
    if (true)
    {
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
    if (true)
    {
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

    // TEST wget
    if (true)
    {
        std::string url = "https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz";
        std::string filename  = "./staging_Python-3.8.1.tgz";
        std::remove(filename.data());

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << url << std::endl;
        }
        std::remove(filename.data());
    }

    // TEST wget
    if (true)
    {
        std::string url = "https://github.com/alanthie/Encryptions/raw/master/modes/CBC.cpp";
        std::string filename  = "./staging_CBC.cpp";
        std::remove(filename.data());

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << url << std::endl;
        }
        //std::remove(filename.data());
    }

    // VIDEO
    if (true)
    {
        std::string url = "https://www.bitchute.com/video/JjqRgjv5GJmW/";
        std::string filename  = "./staging_video.mp4";
        std::string options   = "";

        if (fileexists(filename))
		    std::remove(filename.data());

        int r = getvideo(url, filename, options);
        std::cout << "getvideo returned " << r << std::endl;
    }

    //https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6
    if (false)
    {
        //Sync public TerrePlane (Flat earth) img.pgn
        //std::string url = "https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6";
        //std::string url = "https://cp.sync.com/9a4886a8-b1b3-4a2c-a3c7-4b0c01d76486";
        //std::string url = "https://cp.sync.com/file/1342219113/view/image";
        //std::string url = "https://u.pcloud.link/publink/show?code=XZH2QgVZC4KuzbwhtBmqrvCrpMQhTzAkOd2V";
        //"downloadlink": " // EXPIRED
        std::string url = "https://c326.pcloud.com/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7/Screenshot%20from%202021-06-16%2014-28-40.png";
        //"https:\/\/c326.pcloud.com\/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7\/Screenshot%20from%202021-06-16%2014-28-40.png"
        std::string filename  = "./staging_img.png";
        std::remove(filename.data());

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << std::endl;
        }
        std::remove(filename.data());
    }
}


#endif

