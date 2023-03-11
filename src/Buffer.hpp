#ifndef FDR_BUFFER_HPP
#define FDR_BUFFER_HPP

#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include "crypto_const.hpp"

class data;

namespace cryptoAL
{

constexpr static uint32_t BUFFER_SIZE_INIT  = 8*1024;
constexpr static uint32_t BUFFER_SIZE_LIM   = FILE_SIZE_LIM;

class bad_buffer_operation
{
public:
    bad_buffer_operation(uint32_t sz) :
        bsize(sz)
    {
    }
    uint32_t bsize;
};

class Buffer
{
public:
    explicit Buffer(uint32_t sz = BUFFER_SIZE_INIT)
    {
        data = new char[sz]{0};
        length = 0;
        alloc_size = sz;
    }

    ~Buffer()
    {
        erase();
    }

    void erase()
    {
        if(data != nullptr)
        {
            delete[] data;
            data = nullptr;
            length = 0;
            alloc_size = 0;
        }
    }

    void clear()
    {
        length = 0;
    }
    void seek_begin()
    {
        length = 0;
    }

    void remove_last_n_char(uint32_t n)
    {
        if (length >= n)
            length = length - n;
        else length = 0;
    }

    void init(char c)
    {
        for( size_t i = 0; i< alloc_size; i++)
            data[i] = c;
    }

    Buffer(Buffer&& bfr)
    {
        std::swap( data, bfr.data );
        std::swap( length, bfr.length);
        std::swap( alloc_size, bfr.alloc_size);
    }

    void swap_with(Buffer& r)
    {
        std::swap( data, r.data );
        std::swap( length, r.length);
        std::swap( alloc_size, r.alloc_size);
    }

    void replace_at(uint32_t n, char c)
    {
        if (n < length)
        {
            data[n] = c;
        }
        else{
            std::cerr << "ERROR replace_at " <<  n << " length " << length << std::endl;
        throw "ERROR replace_at " ;
        }
    }

    char get_at(uint32_t n)
    {
        if (n < length)
        {
            return data[n];
        }
        std::cerr << "ERROR get_at " <<  n << " length " << length << std::endl;
        throw "ERROR get_at " ;
    }

    void increase_size(uint32_t n) // bug
    {
        if(n==0)
        {
            return;
        }

        if (n > BUFFER_SIZE_LIM)
        {
			std::cerr << "ERROR buffer too big " <<  n << " BUFFER_SIZE_LIM " << BUFFER_SIZE_LIM << std::endl;
            throw bad_buffer_operation(alloc_size);
        }

        if (alloc_size > n)
            return;

        if (length == 0)
        {
            realloc(n);
            return;
        }

        if (data == nullptr)
        {
            realloc(n);
        }
        else
        {
            // save data    n>=alloc_size
            Buffer temp(length);
            temp.write(data, length, 0);

            realloc(n);

            // reload data
            if (temp.length <= n)
            {
                write(temp.getdata(), temp.length, 0);
            }
            else
            {
                write(temp.getdata(), n, 0);
            }
        }
    }

    int32_t read(std::ifstream& is, uint32_t sz, int32_t offset = -1)
    {
        if (is.bad()) return -1;

        uint32_t of = (uint32_t)(offset == -1 ? length : offset) + sz - 1;
        if (of >= alloc_size) increase_size(of + 1);

        // block read...
        is.read(data, sz);
        if (is.bad() == false)
        {
            length = sz;
            return sz;
        }
        return -1;
    }

    int32_t write(std::ofstream& os, uint32_t sz)
    {
        if (os.bad()) return -1;
        if (sz > size()) return -1;

        // block write...
        os.write(data, sz);
        if (os.bad() == false)
        {
            return sz;
        }
        return -1;
    }

    uint32_t byteToUInt4(char buff[])
    {
        return   ((uint32_t )(unsigned char)buff[3] << 24)
               | ((uint32_t )(unsigned char)buff[2] << 16)
               | ((uint32_t )(unsigned char)buff[1] << 8)
               |  (uint32_t )(unsigned char)buff[0];
    }
    uint16_t byteToUInt2(char buff[])
    {
        return   ((uint16_t)(unsigned char)buff[1] << 8)
               | (uint16_t)(unsigned char)buff[0];
    }

//    void uint8ToByte(uint64_t k, char buff[])
//    {
//        //memcpy(buff, &k, 8);
//        buff[0] = (char)(k & 0x00000000000000ff);
//        buff[1] = (char)(k & 0x000000000000ff00) >> 8;
//        buff[2] = (char)(k & 0x0000000000ff0000) >> 16;
//        buff[3] = (char)(k & 0x00000000ff000000) >> 24;
//        buff[4] = (char)(k & 0x000000ff00000000) >> 32;
//        buff[5] = (char)(k & 0x0000ff0000000000) >> 40;
//        buff[6] = (char)(k & 0x00ff000000000000) >> 48;
//        buff[7] = (char)(k & 0xff00000000000000) >> 56;
//    }

    void uint4ToByte(uint32_t k, char buff[])
    {
        //memcpy(buff, &k, 4);
        buff[0] = (char)(k & 0x000000ff);
        buff[1] = (char)(k & 0x0000ff00) >> 8;
        buff[2] = (char)(k & 0x00ff0000) >> 16;
        buff[3] = (char)(k & 0xff000000) >> 24;
    }
    void int2ToByte(unsigned long k,  char buff[])
    {
        buff[0] = (k & 0x000000ff);
        buff[1] = (k & 0x0000ff00) >> 8;
    }

    int32_t readInt32(uint32_t offset)
    {
        if (offset+4-1 >= alloc_size) throw bad_buffer_operation(alloc_size);
        return (int32_t)data[offset];
    }
    int16_t readInt16(uint32_t offset)
    {
        if (offset+2-1 >= alloc_size) throw bad_buffer_operation(alloc_size);
        return (int16_t)data[offset];
    }
    uint16_t readUInt16(uint32_t offset)
    {
        if (offset+2-1 >= alloc_size) throw bad_buffer_operation(alloc_size);
        return (int16_t) byteToUInt2(&data[offset]);
    }
    uint32_t readUInt32(uint32_t offset)
    {
        if (offset+4-1 >= alloc_size) throw bad_buffer_operation(alloc_size);
        return (uint32_t) byteToUInt4(&data[offset]);
    }
    int8_t readInt8(uint32_t offset)
    {
        if (offset+1-1 >= alloc_size) throw bad_buffer_operation(alloc_size);
        return (int8_t)data[offset];
    }

    void writeInt32(int32_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+4-1;
        if (of >= alloc_size) increase_size(of);

        int appendOffset = offset == -1 ? length : offset;

        memcpy(this->data + appendOffset, &number, sizeof(int32_t));

        if (appendOffset + sizeof(int32_t) > length)
            length = appendOffset + sizeof(int32_t);
    }


    void writeInt16(int16_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+2-1;
        if (of >= alloc_size) increase_size(of);

        int appendOffset = offset == -1 ? length : offset;

        memcpy(this->data + appendOffset, &number, sizeof(int16_t));

        if (appendOffset + sizeof(int16_t) > length)
            length = appendOffset + sizeof(int16_t);
    }

    void writeUInt16(uint16_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+2-1;
        if (of >= alloc_size) increase_size(of);

        uint32_t appendOffset = (offset == -1) ? length : (uint32_t)offset;

//        char buff[2];
//        int2ToByte(number, buff);
//        memcpy(this->data + appendOffset, buff, 2);
        memcpy(this->data + appendOffset, &number, 2);
        if (appendOffset + 2 > length) length = appendOffset + 2;
    }

    void writeUInt32(uint32_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+4-1;
        if (of >= alloc_size) increase_size(of);

        uint32_t appendOffset = (offset == -1) ? length : (uint32_t)offset;

//        char buff[4];
//        uint4ToByte(number, buff);
//        memcpy(this->data + appendOffset, buff, 4);

        memcpy(this->data + appendOffset, &number, 4);
        if (appendOffset + 4 > length) length = appendOffset + 4;
    }

    void writeUInt64(uint64_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+8-1;
        if (of >= alloc_size) increase_size(of);

        uint32_t appendOffset = (offset == -1) ? length : (uint32_t)offset;

//        char buff[8];
//        uint8ToByte(number, buff);
//        memcpy(this->data + appendOffset, buff, 8);

        memcpy(this->data + appendOffset, &number, 8);
        if (appendOffset + 8 > length) length = appendOffset + 8;
    }

    void writeInt8(int8_t number, int32_t offset = -1)
    {
        uint32_t of = (uint32_t)(offset == -1 ? length : offset)+1-1;
        if (of >= alloc_size) increase_size(of);

        int appendOffset = offset == -1 ? length : offset;

        memcpy(data + appendOffset, &number, sizeof(int8_t));

        if (appendOffset + sizeof(int8_t) > this->length)
            length = appendOffset + sizeof(int8_t);
    }
    void write(const char* buffer, uint32_t len, int32_t offset = -1)
    {
        if (len==0) return;
        uint32_t last_of = (uint32_t)(offset == -1 ? length : offset)+len-1;
        if (last_of >= alloc_size)
            increase_size(last_of+1);

        int appendOffset = ((offset == -1) ? length : offset);

        memcpy(data + appendOffset, buffer, len);

        if (appendOffset + len > length)
            length = appendOffset + len;
    }

    void realloc(uint32_t sz)
    {
        erase();
        this->data = new char[sz]{0};
        length = 0;
        alloc_size = sz;
    }

    friend void swap(Buffer&& l, Buffer&& r);

    uint32_t size()         { return length; }
    uint32_t allocsize()    { return alloc_size; }
    const char* getdata()   { return data; }

protected:
    char* data = nullptr;
    uint32_t length = 0;
    uint32_t alloc_size = 0;
};

void swap(Buffer&& l, Buffer&& r)
{
    std::swap( l.data, r.data );
    std::swap( l.length, r.length);
    std::swap( l.alloc_size, r.alloc_size);
}

}

#endif
