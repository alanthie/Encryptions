#ifndef FDR_BUFFER_HPP
#define FDR_BUFFER_HPP

#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <stdio.h>

class data;

constexpr static uint32_t BUFFER_SIZE_INIT  = 10*1000;
constexpr static uint32_t BUFFER_SIZE_LIM   = 10*1000*1000;

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
//friend class data;

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
    }

    void swap_with(Buffer& r)
    {
        std::swap( data, r.data );
        std::swap( length, r.length);
    }

    void increase_size(uint32_t n)
    {
        if(n==0)
        {
            return;
        }

        if (n > BUFFER_SIZE_LIM)
        {
            throw bad_buffer_operation(alloc_size);
        }

        if (length == 0)
        {
            realloc(n);
            return;
        }

        Buffer temp(length);
        temp.write(data, length, 0);

        realloc(n);
        write(temp.getdata(), temp.length, 0);
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

    unsigned long byteToInt4(char buff[])
    {
        return   ((unsigned long)(unsigned char)buff[3] << 24)
               | ((unsigned long)(unsigned char)buff[2] << 16)
               | ((unsigned long)(unsigned char)buff[1] << 8)
               |  (unsigned long)(unsigned char)buff[0];
    }
    unsigned long byteToInt2(char buff[])
    {
        return   ((unsigned long)(unsigned char)buff[1] << 8)
               | (unsigned long)(unsigned char)buff[0];
    }

    void int4ToByte(unsigned long k,  char buff[])
    {
        buff[0] = (k & 0x000000ff);
        buff[1] = (k & 0x0000ff00) >> 8;
        buff[2] = (k & 0x00ff0000) >> 16;
        buff[3] = (k & 0xff000000) >> 24;
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
        //return (uint16_t)data[offset];
        return (int16_t) byteToInt2(&data[offset]);
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

        //memcpy(this->data + appendOffset, &number, sizeof(uint16_t));
        char buff[2];
        int2ToByte(number, buff);
        memcpy(this->data + appendOffset, &number, 2);

        //if (appendOffset + sizeof(uint16_t) > length) length = appendOffset + sizeof(uint16_t);
        if (appendOffset + 2 > length) length = appendOffset + 2;
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

        int appendOffset = offset == -1 ? length : offset;

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

#endif
