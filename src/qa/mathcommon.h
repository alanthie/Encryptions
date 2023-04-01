#ifndef MATH_COMMON_H_INCLUDED
#define MATH_COMMON_H_INCLUDED

#ifdef _WIN32
//https://github.com/ckormanyos/wide-integer
#define WIDE_INTEGER_NAMESPACE WIDE_INTEGER_NS
#include <math\wide_integer\uintwide_t.h>
// TODO what size top use for RSA big prime [2x biggest prime = 2xMaxRSAbits/8] ==> using GMP and BigUnsigned lib
//Width2 must be 2^n times 1...63 (with n >= 3), while being 16, 24, 32 or larger, and exactly divisible by limb count'
using uint2048_t = WIDE_INTEGER_NS::math::wide_integer::uintwide_t<2048U, std::uint32_t>;
using uinteger_t = uint2048_t;
#else
// BUG in modulo for big number
// https://github.com/Kronuz/uinteger_t
#include "uinteger_t.hh"
#endif

#ifdef _WIN32
#include <bitset>
#else
#include <bits/stdc++.h>
#endif

//https://github.com/ckormanyos/wide-decimal
#include <math/wide_decimal/decwide_t.h>
using dec101_t = math::wide_decimal::decwide_t<INT32_C(100), std::uint32_t, void>;

#include <iostream>
#include <cmath>
#include <iomanip>
#include <atomic>
#include <vector>
#include <set>
#include <thread>
#include <mutex>
#include <algorithm>
#include <unordered_map>
#include <cstdint>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <future>
#include <chrono>
#include <cstdlib>
#include <stdlib.h>
#include <cstdio>
#include <type_traits>
#include <random>
#include <list>
#include <numeric>
#include <stdexcept>


#endif

