#include "rational.h"

namespace RationalNS
{
    RationalNumber::RationalNumber(BigInteger m , BigInteger n )
    {
        set(m, n);
    }

    void RationalNumber::set(BigInteger m , BigInteger n)
    {
        if (n==BigIntegerZERO)
        {
            throw "Denominator can't be 0" ;
        }

        BigInteger gcd = GCDiv(m,n);
        this->n = n / gcd;
        this->m = m / gcd;
    }

    void RationalNumber::Display(std::ostream& output, bool line_return)
    {
        if (this->m==BigIntegerZERO)
        {
            output << "0";
        }
        else if (this->n == BigIntegerONE)
        {
           output << this->m.getFNumber() << "/" << "1";
           //output << this->getM().getNumber()<< "/" << "1";
        }
        else
        {
            auto a = this->m.getFNumber();
            auto b = this->n.getFNumber();
            output << a << "/" << b;
        }
        if (line_return)
            output << "\n";
    }

    std::ostream& operator<<(std::ostream& output,const RationalNumber& Number)
    {
        //output << Number.m.getFNumber() << "/" << Number.n.getFNumber();
        output << Number.getM() << "/" << Number.getN();
        return output;
    }

    RationalNumber operator +(RationalNumber A,RationalNumber B)
    {
        if (A.getM()==BigIntegerZERO)
        {
            return RationalNumber(B.getM(), B.getN());
        }
        else if (B.getM()==BigIntegerZERO)
        {
            return RationalNumber(A.getM(), A.getN());
        }

        return RationalNumber(A.getM() * B.getN() + A.getN() * B.getM(), A.getN() * B.getN());
    }

    RationalNumber operator -(RationalNumber A,RationalNumber B)
    {
        if(A.getM()==BigIntegerZERO)
        {
            return RationalNumber(-B.getM(), B.getN());
        }
        else if(B.getM()==BigIntegerZERO)
        {
            return RationalNumber(A.getM(), A.getN());
        }

        BigInteger z1 = A.getM() * B.getN();
        BigInteger z2 = B.getM() * A.getN();
        return RationalNumber(z1 - z2, A.getN() * B.getN());
    }

    RationalNumber operator *(RationalNumber A,RationalNumber B)
    {
        if (A.getM()==BigIntegerZERO)
        {
            return RationalNumber(0, B.getN());
        }
        else if (B.getM()==BigIntegerZERO)
        {
            return RationalNumber(0, A.getN());
        }

        return RationalNumber(A.getM()*B.getM(),A.getN()*B.getN());
    }

    RationalNumber operator /(RationalNumber A,RationalNumber B)
    {
        if (A.getM()==0)
        {
            return RationalNumber(0, B.getN());
        }
        else if (B.getM()==BigIntegerZERO)
        {
            return RationalNumber(0, A.getN());
        }

        return RationalNumber(A.getM()*B.getN(),A.getN()*B.getM());
    }

    bool operator ==(RationalNumber A,RationalNumber B)
    {
        if(A.getM()==B.getM() && A.getN() == B.getN())
            return true;
        else
            return false;
    }

    bool operator !=(RationalNumber A,RationalNumber B)
    {
        if(A==B)
            return false;
        else
            return true;
    }

    bool operator >(RationalNumber A,RationalNumber B)
    {
        BigInteger a = A.getM() * B.getN();
        BigInteger b = B.getM() * A.getN();
        return a > b;
    }

    bool operator <(RationalNumber A,RationalNumber B)
    {
        BigInteger a = A.getM() * B.getN();
        BigInteger b = B.getM() * A.getN();
        return a < b;
    }

    bool operator >=(RationalNumber A,RationalNumber B)
    {
        if(A==B)
            return true;
        else if(A>B)
            return true;
        else
            return false;
    }

    bool operator <=(RationalNumber A,RationalNumber B)
    {
        if(A==B)
            return true;
        else if(A<B)
            return true;
        else
            return false;
    }

    const BigInteger RationalNumber::GCDiv(BigInteger a,BigInteger b)
    {
        // GCD of two number
        if (a < BigIntegerZERO)
        {
            //if (a < 0) a = -1 * a;
            a = a.absolute();
        }
        if (b < BigIntegerZERO)
        {
            //if (b < 0) b = -1 * b;
            b = b.absolute();
        }

        if(a<b)
        {
            BigInteger t = a;
            a = b;
            b = t;
        }
        while(b != BigIntegerZERO)
        {
            BigInteger org_b = b;
            b = a % b;
            a = org_b;
        }
        return a;
    }


    std::pair<int, bool> RationalNumberTest::unit_tests()
    {
        RationalNumber a(-1,11);
        RationalNumber b( 2,11);

        if ( (a - b) != RationalNumber(-3, 11)) return std::pair<int, bool>(1, false);
        if ( (a + b) != RationalNumber( 1, 11)) return std::pair<int, bool>(2, false);
        if ( (a * b) != RationalNumber(-2, 121)) return std::pair<int, bool>(3, false);
        if ( (a / b) != RationalNumber(-1, 2)) return std::pair<int, bool>(4, false);

        a = RationalNumber(-25, 9);
        b = RationalNumber(-18, 15);
        if ( (a * b) != RationalNumber(10, 3)) return std::pair<int, bool>(5, false);

        {
            BigInteger b1 = BigInteger(2 * 3 * 2 * 3 * 5 * 7 * 11*13) ; // 180180"
            BigInteger b2 = BigInteger(2 * 3 * 11*13*17*19*23 * 11*13); // 911493726"
            if ( RationalNumber(BigInteger(2 * 3 * 5 * 7), BigInteger(11*13*17*19*23)) != RationalNumber(b1, b2) ) return std::pair<int, bool>(6, false);
            BigInteger mod = b1 % b2;
            if ( b1 % b2 != 180180) return std::pair<int, bool>(7, false);
            if ( b2 % b1 != 143286) return std::pair<int, bool>(8, false);
        }
        {
            BigInteger b1 = BigInteger("180180") * BigInteger("10000000000000");
            BigInteger b2 = BigInteger("911493726") * BigInteger("10000000000000");
            BigInteger mod = b1 % b2;
            if ( (b1 % b2) != 1801800000000000000) return std::pair<int, bool>(9, false);
            if ( (b2 % b1) != 1432860000000000000) return std::pair<int, bool>(10, false);
        }
        if ( BigInteger(5) % BigInteger(-3) != 2) return std::pair<int, bool>(11, false);
        if ( BigInteger(-5) % BigInteger(3) != -2) return std::pair<int, bool>(12, false);
        if ( BigInteger(-3) % BigInteger(-2) != -1) return std::pair<int, bool>(13, false);
        if ( BigInteger(3) % BigInteger(-2) != 1) return std::pair<int, bool>(14, false);
        if ( BigInteger(-3) % BigInteger(2) != -1) return std::pair<int, bool>(15, false);

        auto func = [](RationalNumber r) -> RationalNumber
        {
            // x / (x - 3)
            return r / (r - RationalNumber(3, 1) );
        };
        if ( func(RationalNumber(3001, 1000)) != RationalNumber(3001, 1) ) return std::pair<int, bool>(16, false);
        if ( func(RationalNumber(7, 2)) != RationalNumber(7, 1) ) return std::pair<int, bool>(17, false);
        if ( func(RationalNumber(100, 1)) != RationalNumber(100 , BigInteger(97) )  ) return std::pair<int, bool>(18, false);
        if ( fact(45) != BigInteger("119622220865480194561963161495657715064383733760000000000")) return std::pair<int, bool>(19, false);
        if ( RationalNumber(fact(100), fact(99)) != RationalNumber(100, 1) ) return std::pair<int, bool>(20, false);

        if ( (a < b) != true) return std::pair<int, bool>(21, false);
        if ( (a == b) != false) return std::pair<int, bool>(22, false);
        if ( (a > b) != false) return std::pair<int, bool>(23, false);

        // TODO more tests
        return std::pair<int, bool>(0, true);
    }
}

