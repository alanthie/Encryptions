#ifndef CRYPTO_PACKAGE_H
#define CRYPTO_PACKAGE_H

#include <map>
#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include "ini_parser.hpp"

class crypto_package
{
public:
    
    ini_parser cfg;
};

#endif