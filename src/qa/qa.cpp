#include "mathcommon.h"

//#define USE_EMPTY 1
#ifdef USE_EMPTY
    #define qaclass qa_internal_empty
    #include "qa_internal_empty.hpp"
#else
    #define qaclass qa_internal
    #include "qa_internal.hpp" // NOT SHARED ON GITHUB
#endif


std::string VERSION = "v1";
std::string FULLVERSION = VERSION + "_" + get_current_date();

std::string tree_shape(long long k);

long long str_to_ll(const std::string& schoice)
{
    long long r = -1;
    try
    {
        r = std::stoll(schoice);
    }
    catch (...)
    {
        r = -1;
    }
    return r;
}


void  menu()
{
    long long choice = 1;
    long long last_choice = 1;
    long long n;

    std::string schoice;
    while(choice != 0)
    {
//#ifdef _WIN32
//        system("CLS");
//#else
//        system("clear");
//#endif

        std::cout << "====================================" << std::endl;
        std::cout << "Program version  : " << FULLVERSION   << std::endl;
        std::cout << "Select a function: " << std::endl;
        std::cout << "====================================" << std::endl;
        std::cout << "0. Quit" << std::endl;
        std::cout << "*. Last choice" << std::endl;
        std::cout << "1. F(n)" << std::endl;
        std::cout << "2. P(n)" << std::endl;
        std::cout << "3. HEX(file, position, keysize)" << std::endl;
        std::cout << "4. Book(title, page, para)" << std::endl;
        std::cout << "==> ";
        std::cin >> schoice;

        if (schoice == "*") choice = last_choice;
        else choice = str_to_ll(schoice);
        std::cout << std::endl;

        if (choice == -1) continue;
        last_choice = choice;

        if (choice == 0) return;
        else if (choice == 1)
        {
            std::cout << "F(n)" << std::endl;
            std::cout << "Enter a number: ";
            std::string snum;
            std::cin >> snum;
            n = str_to_ll(snum);
            if (n==-1) continue;

            qaclass qa;
            auto r = qa.F(n);
            std::cout << "F(" << n << ") = " << r << std::endl;
            std::cout << std::endl;
        }
        else if (choice == 2)
        {
            std::cout << "P(n)" << std::endl;
            std::cout << "Enter a number: ";
            std::string snum;
            std::cin >> snum;
            n = str_to_ll(snum);
            if (n==-1) continue;

            qaclass qa;
            auto r = qa.P(n);
            std::cout << "P(" << n << ") = " << r << std::endl;
            std::cout << std::endl;
        }
        else if (choice == 3)
        {
            std::cout << "HEX(file, position, keysize)" << std::endl;
            std::cout << "Enter filename: ";
            std::string sfile;
            std::cin >> sfile;

            std::cout << "Enter position: ";
            std::string spos;
            std::cin >> spos;
            long long pos = str_to_ll(spos);

            std::cout << "Enter keysize: ";
            std::string skeysize;
            std::cin >> skeysize;
            long long keysize = str_to_ll(skeysize);

            qaclass qa;
            auto r = qa.HEX(sfile, pos, keysize);
            std::cout << "HEX(" << sfile << "," << pos << "," << keysize << ") = " << r << std::endl;
            std::cout << std::endl;
        }
    }
    return;
}


int main()
{
    menu();
    return 0;
}
