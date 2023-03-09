#ifndef qa_internal_INCLUDED
#define qa_internal_INCLUDED

#include "qa_internal_empty.hpp"
#include "../puzzle.hpp"
#include "../random_engine.hpp"


using namespace PRIME;

// NOT SHARED ON GITHUB
class qa_internal : public qa_internal_empty
{
    // ?
    const uinteger_t N  = 3214523324591919191;
    const long long MOD = 101*17*37*11*89;

public:
    uinteger_t F(long long n ) override
    {
        uinteger_t mod = upow(MOD, 10);
        auto r = ufact(n);
        if (r==0) r=1;
        return r - 1; // ( ((r-1) % mod) * (N % mod) ) % mod;
    }

    uinteger_t P(long long n ) override
    {
        uinteger_t mod = upow(MOD, 10);
        auto r = next_uprime(n, 0);
        if (r==0) r=1;
        return r - 1; //( ((r-1) % mod) * (N % mod) ) % mod;
    }

};
#endif
