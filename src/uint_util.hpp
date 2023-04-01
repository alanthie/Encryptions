#ifndef UINTEGER_UTIL_H_INCLUDED
#define UINTEGER_UTIL_H_INCLUDED

#include "qa/mathcommon.h"

#include "qa/RSA_generate/bigint/BigIntegerLibrary.hh"
using typeuinteger   = BigUnsigned;
using typebiginteger = BigInteger;

#include "crypto_const.hpp"

namespace uint_util
{
    [[maybe_unused]] static int pos64(char c)
    {
        for(size_t  i=0;i<cryptoAL::BASEDIGIT64.size();i++)
        {
            if (c == cryptoAL::BASEDIGIT64[i])
            {
                return (int)i;
            }
        }
        std::cerr << "ERROR pos64v invalid base 64 char " << (int)(unsigned char)c << std::endl;
        throw std::string("ERROR pos64() invalid base 64 char ");
        return 0;
    }

    [[maybe_unused]] static int pos10(char c)
    {
        for(size_t i=0;i<cryptoAL::BASEDIGIT10.size();i++)
        {
            if (c == cryptoAL::BASEDIGIT10[i])
            {
                return (int)i;
            }
        }
        std::cerr << "ERROR invalid base 10 char " << (int)c << std::endl;
        throw "ERROR invalid base 10 char ";
        return 0;
    }

    [[maybe_unused]] static typeuinteger val(const std::string& s)
    {
        typeuinteger r = 0;
        long long n = (long long)s.size();
        for(long long i=0;i<n;i++)
        {
            r *= 64;
            r += pos64(s[i]);
        }
        return r;
    }
    [[maybe_unused]] static typeuinteger val10(const std::string& s)
    {
        typeuinteger r = 0;
        long long n = (long long)s.size();
        for(long long i=0;i<n;i++)
        {
            r *= 10;
            r += pos10(s[i]);
        }
        return r;
    }

    [[maybe_unused]] static typeuinteger mod_pow(typeuinteger base, typeuinteger exp, const typeuinteger& mod)
    {
        typeuinteger resoult = 1;

        while (exp > 0)
        {
            if (typeuinteger(exp & 1) == 1)
                resoult = (base * resoult) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }

        return resoult;
    }

    [[maybe_unused]] static typeuinteger power_modulo(const typeuinteger& a, const typeuinteger& power, const typeuinteger& mod)
    {
        try
        {
            // windows stack overflow....
            // Visual Studio uses 4KB for the stack but reserved 1MB by default. You can change this in "Configuration Properties"->Linker->System->"Stack Reserve Size" to 10MB for example.
            // (a ⋅ b) mod m = [(a mod m) ⋅ (b mod m)] mod m
            if (power == 0) return 1;
            if (power % 2 == 1)
            {
                return ((a % mod) * power_modulo(a, power - 1, mod)) % mod;
            }

            typeuinteger b = power_modulo(a, power / 2, mod) % mod;
            return (b * b) % mod;
        }
        catch (const std::exception& e)
        {
            std::cerr << "ERROR exception thrown in power_modulo " << e.what() << std::endl;
            throw e;
        }
        catch (...)
        {
            std::cerr << "ERROR exception thrown in power_modulo " << std::endl;
            throw std::string("ERROR exception thrown in power_modulo ");
        }
    }

    [[maybe_unused]] static std::string to_base64(const typeuinteger& v)
    {
        typeuinteger r = v;
        typeuinteger b64 = 64;
        typeuinteger t;
        int digit;
        std::string s;
        while(r > 0)
        {
            t = (r % b64);
            digit = t.toInt();
            if (digit< 0) throw std::string("to base64 bad digit < 0");
            if (digit>63) throw std::string("to base64 bad digit > 63");
            s += cryptoAL::BASEDIGIT64[digit];
            r = r - digit;
            r = r / 64;
        }
        std::reverse(s.begin(), s.end());
        return s;
    }

    [[maybe_unused]] static std::string to_base10(const typeuinteger& v)
    {
        typeuinteger r = v;
        int digit;
        std::string s;
        typeuinteger t;
        typeuinteger b10 = 10;
        while(r > 0)
        {
            t = (r % b10);
            digit = t.toInt();
            if (digit<0) throw std::string("to base10 bad digit < 0");
            if (digit>9) throw std::string("to base10 bad digit > 9");
            s += cryptoAL::BASEDIGIT10[digit];
            r = r - digit;
            r = r / 10;
        }
        std::reverse(s.begin(), s.end());
        return s;
    }

    [[maybe_unused]] static std::string base10_to_base64(const std::string& s)
    {
        typeuinteger m = val10(s);
        return to_base64(m);
    }
    [[maybe_unused]] static std::string base64_to_base10(const std::string& s)
    {
        typeuinteger m = val(s);
        return to_base10(m);
    }
	

  	[[maybe_unused]] static typeuinteger hex_to_uinteger(std::string s)
	{
		typeuinteger r = 0;
		long long n = (long long)s.size();
		for(long long i=0;i<n;i++)
		{
			r *= 16;
			if ((s[i]>= '0') && (s[i]<= '9') )
				r += (s[i] - '0');
			else if ((s[i]>= 'a') && (s[i]<= 'f') )
				r += 10 + (s[i] - 'a');
			else if ((s[i]>= 'A') && (s[i]<= 'F') )
				r +=  10 + (s[i] - 'A');
			else
			   throw "invalid hex";
		}
		return r;
	}


}
#endif
