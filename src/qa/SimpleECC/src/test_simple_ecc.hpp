#include "boolean.hpp"
#include "helper.hpp"
#include "point.hpp"
#include "j_point.hpp"
#include "ecc.hpp"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#ifdef _WIN32
//...
#else
#include <dirent.h>
#endif
#include <ctype.h>
#include <string.h>
#include <gmpxx.h>
//#include <gmp.h>


namespace cryptoSimpleECC
{
    int test_simple_ecc();
}