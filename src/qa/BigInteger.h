#ifndef BIGINTEGER_H
#define BIGINTEGER_H

#include <string>
#include "mathcommon.h"
//#include "uinteger_t.hh" // compute any size unsigned number

//-------------------------------------------------------------
class BigInteger
{
private:
	std::string number;
	bool sign;
public:
	BigInteger(); // empty constructor initializes zero
	BigInteger(const BigInteger& b );

	BigInteger(std::string s); // "string" constructor
	BigInteger(std::string s, bool sin); // "string" constructor
	BigInteger(long long n); // "int" constructor
	void setNumber(std::string s);
	const std::string& getNumber() const; // retrieves the number
	std::string getFNumber() const;
	void setSign(bool s);
	const bool& getSign() const;
	BigInteger absolute(); // returns the absolute value
	void operator = (BigInteger b);
	bool operator == (BigInteger b);
	bool operator != (BigInteger b);
	bool operator > (BigInteger b);
	bool operator < (BigInteger b);
//	bool operator < (const BigInteger& b);
//	bool operator < (const BigInteger& b) const;
	bool operator >= (BigInteger b);
	bool operator <= (BigInteger b);
	BigInteger& operator ++(); // prefix
	BigInteger  operator ++(int); // postfix
	BigInteger& operator --(); // prefix
	BigInteger  operator --(int); // postfix
	BigInteger operator + (BigInteger b);
	BigInteger operator - (BigInteger b);
	BigInteger operator * (BigInteger b);
	BigInteger operator / (BigInteger b);
	BigInteger operator % (BigInteger b);
	BigInteger& operator += (BigInteger b);
	BigInteger& operator -= (BigInteger b);
	BigInteger& operator *= (BigInteger b);
	BigInteger& operator /= (BigInteger b);
	BigInteger& operator %= (BigInteger b);
	BigInteger& operator [] (int n);
	BigInteger operator -(); // unary minus sign
	operator std::string(); // for conversion from BigInteger to string
	long long toLongLong();
private:
	bool equals(BigInteger n1, BigInteger n2);
	bool less(BigInteger n1, BigInteger n2);
	//bool less(BigInteger n1, BigInteger n2) const;
	bool greater(BigInteger n1, BigInteger n2);
	std::string add(std::string number1, std::string number2);
	std::string subtract(std::string number1, std::string number2);
	std::string multiply(std::string n1, std::string n2);
	std::pair<std::string, long long> divide(std::string n, long long den);
	std::string toString(long long n);
	public:
	long long toInt(std::string s);
};

bool operator <(const BigInteger& A, const BigInteger&  B);
#endif
