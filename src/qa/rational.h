#ifndef RATIONAL_H_INCLUDED
#define RATIONAL_H_INCLUDED

#include <iostream>
#include "mathcommon.h"
//using BigInteger = uinteger_t;
#include "BigInteger.h" // Allow negative number

namespace RationalNS
{
    const BigInteger BigIntegerZERO((int)0);
    const BigInteger BigIntegerONE((int)1);

    class RationalNumber
    {
        private:
            BigInteger m; // numerator
            BigInteger n; // denominator

        public:
            RationalNumber(BigInteger m = BigIntegerZERO, BigInteger n = BigIntegerONE );
            void set(BigInteger m = BigIntegerZERO, BigInteger n = BigIntegerONE);

            void Display(std::ostream& output = std::cout, bool line_return = false);

            BigInteger getM() const {return this->m;}
            BigInteger getN() const {return this->n;}

            friend std::ostream& operator<<(std::ostream& output,const RationalNumber& Number);
            const BigInteger GCDiv(BigInteger a, BigInteger b);
    };

    RationalNumber operator +(RationalNumber A,RationalNumber B);
    RationalNumber operator -(RationalNumber A,RationalNumber B);
    RationalNumber operator *(RationalNumber A,RationalNumber B);
    RationalNumber operator /(RationalNumber A,RationalNumber B);

    bool operator ==(RationalNumber A,RationalNumber B);
    bool operator !=(RationalNumber A,RationalNumber B);
    bool operator >(RationalNumber A,RationalNumber B);
    bool operator <(RationalNumber A,RationalNumber B);
    bool operator >=(RationalNumber A,RationalNumber B);
    bool operator <=(RationalNumber A,RationalNumber B);

    class RationalNumberTest
    {
        public:
            std::pair<int, bool> unit_tests();

        BigInteger fact(BigInteger r)
        {
            if (r <= 1) return 1;
            return r  * fact(r-1);
        };
    };

}
#endif

