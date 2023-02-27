
#include "BigInteger.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cmath>

using namespace std;

BigInteger::BigInteger()
{
	number = "0";
	sign = false;
}

BigInteger::BigInteger(const BigInteger& b )
{
    setNumber( b.getNumber() );
    setSign( b.getSign() );
}

//-------------------------------------------------------------
BigInteger::BigInteger(string s)
{
	if( isdigit(s[0]) )
	{
		setNumber(s);
		sign = false;
	}
	else
	{
		setNumber( s.substr(1) );
		sign = (s[0] == '-');
	}
}
//-------------------------------------------------------------
BigInteger::BigInteger(string s, bool sin)
{
	setNumber( s );
	setSign( sin );
}
//-------------------------------------------------------------
BigInteger::BigInteger(long long n)
{
	stringstream ss;
	string s;
	ss << n;
	ss >> s;

	if( isdigit(s[0]) ) // if not signed
	{
		setNumber( s );
		setSign( false ); // +ve
	}
	else
	{
		setNumber( s.substr(1) );
		setSign( s[0] == '-' );
	}
}
//-------------------------------------------------------------
void BigInteger::setNumber(string s)
{
	number = s;
}
//-------------------------------------------------------------
const string& BigInteger::getNumber() const
{
	return number;
}
//-------------------------------------------------------------
string BigInteger::getFNumber() const
{
    if (sign)
    {
        string s = string("-").append(number);
        return s;
    }
	return number;
}

//-------------------------------------------------------------
void BigInteger::setSign(bool s)
{
	sign = s;
}
//-------------------------------------------------------------
const bool& BigInteger::getSign() const
{
	return sign;
}
//-------------------------------------------------------------
BigInteger BigInteger::absolute()
{
	return BigInteger( getNumber() ); // +ve by default
}
//-------------------------------------------------------------
void BigInteger::operator = (BigInteger b)
{
	setNumber( b.getNumber() );
	setSign( b.getSign() );
}
//-------------------------------------------------------------
bool BigInteger::operator == (BigInteger b)
{
	return equals((*this) , b);
}
//-------------------------------------------------------------
bool BigInteger::operator != (BigInteger b)
{
	return ! equals((*this) , b);
}
//-------------------------------------------------------------
bool BigInteger::operator > (BigInteger b)
{
	return greater((*this) , b);
}
//-------------------------------------------------------------
bool BigInteger::operator < (BigInteger b)
{
	return less((*this) , b);
}
//bool BigInteger::operator < (const BigInteger& b)
//{
//    return less((*this) , b);
//}
//bool BigInteger::operator < (const BigInteger& b) const
//{
//    return less( (*this) , b);
//}
bool operator <(const BigInteger& n1, const BigInteger& n2)
{
    bool sign1 = n1.getSign();
	bool sign2 = n2.getSign();

	if(sign1 && ! sign2) // if n1 is -ve and n2 is +ve
		return true;

	else if(! sign1 && sign2)
		return false;

	else if(! sign1) // both +ve
	{
		if(n1.getNumber().length() < n2.getNumber().length() )
			return true;
		if(n1.getNumber().length() > n2.getNumber().length() )
			return false;
		return n1.getNumber() < n2.getNumber();
	}
	else // both -ve
	{
		if(n1.getNumber().length() > n2.getNumber().length())
			return true;
		if(n1.getNumber().length() < n2.getNumber().length())
			return false;
		return n1.getNumber().compare( n2.getNumber() ) > 0; // greater with -ve sign is LESS
	}
}
//-------------------------------------------------------------
bool BigInteger::operator >= (BigInteger b)
{
	return equals((*this) , b)
		|| greater((*this), b);
}
//-------------------------------------------------------------
bool BigInteger::operator <= (BigInteger b)
{
	return equals((*this) , b)
		|| less((*this) , b);
}
//-------------------------------------------------------------
// increments the value, then returns its value
BigInteger& BigInteger::operator ++() // prefix
{
	(*this) = (*this) + 1;
	return (*this);
}
//-------------------------------------------------------------
// returns the value, then increments its value
BigInteger BigInteger::operator ++(int) // postfix
{
	BigInteger before = (*this);

	(*this) = (*this) + 1;

	return before;
}
//-------------------------------------------------------------
// decrements the value, then return it
BigInteger& BigInteger::operator --() // prefix
{
	(*this) = (*this) - 1;
	return (*this);

}
//-------------------------------------------------------------
// return the value, then decrements it
BigInteger BigInteger::operator --(int) // postfix
{
	BigInteger before = (*this);

	(*this) = (*this) - 1;

	return before;
}
//-------------------------------------------------------------
BigInteger BigInteger::operator + (BigInteger b)
{
	BigInteger addition;
	if( getSign() == b.getSign() ) // both +ve or -ve
	{
		addition.setNumber( add(getNumber(), b.getNumber() ) );
		addition.setSign( getSign() );
	}
	else // sign different
	{
		if( absolute() > b.absolute() )
		{
			addition.setNumber( subtract(getNumber(), b.getNumber() ) );
			addition.setSign( getSign() );
		}
		else
		{
			addition.setNumber( subtract(b.getNumber(), getNumber() ) );
			addition.setSign( b.getSign() );
		}
	}
	if(addition.getNumber() == "0") // avoid (-0) problem
		addition.setSign(false);

	return addition;
}

//-------------------------------------------------------------
BigInteger BigInteger::operator - (BigInteger b)
{
	b.setSign( ! b.getSign() );
	return (*this) + b;
}

//-------------------------------------------------------------
BigInteger BigInteger::operator * (BigInteger b)
{
	BigInteger mul;

	mul.setNumber( multiply(getNumber(), b.getNumber() ) );
	mul.setSign( getSign() != b.getSign() );

	if(mul.getNumber() == "0") // avoid (-0) problem
		mul.setSign(false);

	return mul;
}

//-------------------------------------------------------------
BigInteger BigInteger::operator / (BigInteger b)
{
	// TODO
#ifdef _WIN32
	uinteger_t au(this->getNumber().data());
	uinteger_t bu(b.getNumber().data());
	uinteger_t ru = au / bu;
	std::stringstream ss; ss << ru;
	BigInteger r = BigInteger(ss.str());
#else
	uinteger_t au(this->getNumber(), 10);
	uinteger_t bu(b.getNumber(), 10);
	uinteger_t ru = au / bu;
	BigInteger r = BigInteger(ru.str());
#endif

    if ( this->getSign() != b.getSign() )
    {
        r.setSign(true);
    }
    return  r;

// Warning: Denomerator must be within "long long" size not "BigInteger"
//	long long den = toInt( b.getNumber() );
//	BigInteger div;
//
//	div.setNumber( divide(getNumber(), den).first );
//	div.setSign( getSign() != b.getSign() );
//
//	if(div.getNumber() == "0") // avoid (-0) problem
//		div.setSign(false);
//
//	return div;
}

//-------------------------------------------------------------
BigInteger BigInteger::operator % (BigInteger b)
{
	// TODO
#ifdef _WIN32
	uinteger_t au(this->getNumber().data());
	uinteger_t bu(b.getNumber().data());
	uinteger_t ru = au % bu;
	std::stringstream ss; ss << ru;
	BigInteger r = BigInteger(ss.str());
#else
	uinteger_t au(this->getNumber(), 10);
	uinteger_t bu(b.getNumber(), 10);
	uinteger_t ru = au % bu;
	BigInteger r = BigInteger(ru.str());
#endif

    if ( this->getSign() != b.getSign() )
    {
        if (this->getSign() == true)
            r.setSign(true);
    }
    else if ( this->getSign() == true)
    {
        r.setSign(true);
    }
    return  r;

//Warning: Denomerator must be within "long long" size not "BigInteger"
//	long long den = toInt( b.getNumber() );
//
//	BigInteger rem;
//	long long rem_int = divide(number, den).second;
//	rem.setNumber( toString(rem_int) );
//	rem.setSign( getSign() != b.getSign() );
//
//	if(rem.getNumber() == "0") // avoid (-0) problem
//		rem.setSign(false);
//
//	return rem;
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator += (BigInteger b)
{
	(*this) = (*this) + b;
	return (*this);
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator -= (BigInteger b)
{
	(*this) = (*this) - b;
	return (*this);
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator *= (BigInteger b)
{
	(*this) = (*this) * b;
	return (*this);
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator /= (BigInteger b)
{
	(*this) = (*this) / b;
	return (*this);
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator %= (BigInteger b)
{
	(*this) = (*this) % b;
	return (*this);
}
//-------------------------------------------------------------
BigInteger& BigInteger::operator [] (int n)
{
	return *(this + (n*sizeof(BigInteger)));
}
//-------------------------------------------------------------
BigInteger BigInteger::operator -() // unary minus sign
{
	return (*this) * -1;
}
//-------------------------------------------------------------
BigInteger::operator string() // for conversion from BigInteger to string
{
	string signedString = ( getSign() ) ? "-" : ""; // if +ve, don't print + sign
	signedString += number;
	return signedString;
}
//-------------------------------------------------------------

bool BigInteger::equals(BigInteger n1, BigInteger n2)
{
	return n1.getNumber() == n2.getNumber()
		&& n1.getSign() == n2.getSign();
}

//-------------------------------------------------------------
bool BigInteger::less(BigInteger n1, BigInteger n2)
{
	bool sign1 = n1.getSign();
	bool sign2 = n2.getSign();

	if(sign1 && ! sign2) // if n1 is -ve and n2 is +ve
		return true;

	else if(! sign1 && sign2)
		return false;

	else if(! sign1) // both +ve
	{
		if(n1.getNumber().length() < n2.getNumber().length() )
			return true;
		if(n1.getNumber().length() > n2.getNumber().length() )
			return false;
		return n1.getNumber() < n2.getNumber();
	}
	else // both -ve
	{
		if(n1.getNumber().length() > n2.getNumber().length())
			return true;
		if(n1.getNumber().length() < n2.getNumber().length())
			return false;
		return n1.getNumber().compare( n2.getNumber() ) > 0; // greater with -ve sign is LESS
	}
}
//bool BigInteger::less(BigInteger n1, BigInteger n2) const
//{
//    return less(n1, n2);
//}
//-------------------------------------------------------------
bool BigInteger::greater(BigInteger n1, BigInteger n2)
{
	return ! equals(n1, n2) && ! less(n1, n2);
}

//-------------------------------------------------------------
// adds two strings and returns their sum in as a string
string BigInteger::add(string number1, string number2)
{
	string add = (number1.length() > number2.length()) ?  number1 : number2;
	char carry = '0';
	int differenceInLength = abs( (int) (number1.size() - number2.size()) );

	if(number1.size() > number2.size())
		number2.insert(0, differenceInLength, '0'); // put zeros from left

	else// if(number1.size() < number2.size())
		number1.insert(0, differenceInLength, '0');

	for(int i=(int)number1.size()-1; i>=0; --i)
	{
		add[i] = ((carry-'0')+(number1[i]-'0')+(number2[i]-'0')) + '0';

		if(i != 0)
		{
			if(add[i] > '9')
			{
				add[i] -= 10;
				carry = '1';
			}
			else
				carry = '0';
		}
	}
	if(add[0] > '9')
	{
		add[0]-= 10;
		add.insert(0,1,'1');
	}
	return add;
}

//-------------------------------------------------------------
// subtracts two strings and returns their sum in as a string
string BigInteger::subtract(string number1, string number2)
{
	string sub = (number1.length()>number2.length())? number1 : number2;
	int differenceInLength = abs( (int)(number1.size() - number2.size()) );

	if(number1.size() > number2.size())
		number2.insert(0, differenceInLength, '0');

	else
		number1.insert(0, differenceInLength, '0');

	for(int i= (int)number1.length()-1; i>=0; --i)
	{
		if(number1[i] < number2[i])
		{
			number1[i] += 10;
			number1[i-1]--;
		}
		sub[i] = ((number1[i]-'0')-(number2[i]-'0')) + '0';
	}

	while(sub[0]=='0' && sub.length()!=1) // erase leading zeros
		sub.erase(0,1);

	return sub;
}

//-------------------------------------------------------------
// multiplies two strings and returns their sum in as a string
string BigInteger::multiply(string n1, string n2)
{
	if(n1.length() > n2.length())
		n1.swap(n2);

	string res = "0";
	for(int i= (int)n1.length()-1; i>=0; --i)
	{
		string temp = n2;
		int currentDigit = n1[i]-'0';
		int carry = 0;

		for(int j=(int)temp.length()-1; j>=0; --j)
		{
			temp[j] = ((temp[j]-'0') * currentDigit) + carry;

			if(temp[j] > 9)
			{
				carry = (temp[j]/10);
				temp[j] -= (carry*10);
			}
			else
				carry = 0;

			temp[j] += '0'; // back to string mood
		}

		if(carry > 0)
			temp.insert(0, 1, (carry+'0'));

		temp.append((n1.length()-i-1), '0'); // as like mult by 10, 100, 1000, 10000 and so on

		res = add(res, temp); // O(n)
	}

	while(res[0] == '0' && res.length()!=1) // erase leading zeros
		res.erase(0,1);

	return res;
}

//-------------------------------------------------------------
// divides string on long long, returns pair(qutiont, remainder)
pair<string, long long> BigInteger::divide(string n, long long den)
{
	long long rem = 0;
	string result;
	result.resize(2 * n.length()); // todo
	char rd;

	for(int indx=0, len = (int)n.length(); indx<len; ++indx)
	{
		rem = (rem * 10) + (n[indx] - '0');
		rd = (char) (rem / den); // TODO
		result[indx] = rd + '0';
		rem %= den;
	}
	result.resize( n.length() );

	while( result[0] == '0' && result.length() != 1)
		result.erase(0,1);

	if(result.length() == 0)
		result = "0";

	return make_pair(result, rem);
}

//-------------------------------------------------------------
// converts long long to string
string BigInteger::toString(long long n)
{
	stringstream ss;
	string temp;

	ss << n;
	ss >> temp;

	return temp;
}

//-------------------------------------------------------------
// converts string to long long
long long BigInteger::toInt(string s)
{
	long long sum = 0;

	for(size_t i=0; i<s.length(); i++)
		sum = (sum*10) + (s[i] - '0');

	return sum;
}

long long BigInteger::toLongLong()
{
	long long sum = 0;

	for(size_t i=0; i<number.length(); i++)
		sum = (sum*10) + (number[i] - '0');

    if (sign)
    {
        sum = -1*sum;
    }
	return sum;
}

