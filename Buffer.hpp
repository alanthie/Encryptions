#ifndef FDR_BUFFER_HPP
#define FDR_BUFFER_HPP

#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <stdio.h>

class data;

class bad_buffer_operation
{
public:
    bad_buffer_operation(uint32_t sz) : bsize(sz)
    {
        int a=1;
    }
    uint32_t bsize;
};

class Buffer
{
//friend class data;

public:
    explicit Buffer(uint32_t sz = 1*1000*1000)
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
        if (n > 100*1000*1000) // 100MB
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