#ifndef _INCLUDES_random_engine
#define _INCLUDES_random_engine

#include <random>
#include "data.hpp"
#include "rng.h"

namespace cryptoAL
{


class random_engine
{
  public:
    std::random_device                    rd;
    std::mt19937                          mt;
    std::uniform_real_distribution<double>  dist;

    random_engine() : rd{}, mt{rd()}, dist{0.0, 1.0}
    {
        seed();
    }

#ifdef _WIN32
    static uint64_t getTickCount()
    {
        return GetTickCount();
    }
#else
    static uint64_t getTickCount() // ms
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)(ts.tv_nsec / 1000000) + ((uint64_t)ts.tv_sec * 1000ull);
    }
#endif

    double get_rand()
    {
      return dist(mt);
    }

    void seed()
    {
        srand ((unsigned int)getTickCount());
        int n = rand() % 100;
        for (int i=0;i<n;i++) get_rand(); // random seed
    }

};

bool generate_random_file(std::string filename, long long Nk, long num_files = 1)
{
    std::string s;
    std::string si;
    std::string sn;
    const double LIM = 1000*1000*1000;
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    long long n;
    long long t;
    bool r = true;
    random_engine rd;
    long long N = Nk*1024;
    size_t sz=0;

    std::string filename_full;
    for(long long k=0;k<num_files;k++)
    {
        sz=0;
        cryptodata data;
        data.realloc((uint32_t)(Nk*1024));

        for(long long i=0;i<N;i++)
        {
            n = (long long)(rd.get_rand() * LIM);
            si = std::to_string(i);
            sn = std::to_string(n);
            if (i%10 == 0) s = si + ":" + sn + " \n";
            else s = si + ":" + sn + " ";
            sz += s.size();
            data.buffer.write(s.data(), (uint32_t)s.size(), -1);

            if (sz >= (size_t)N)
                break;

            t = (long long)(rd.get_rand() * 10);
            for(long long j=0;j<t;j++)
                rd.get_rand();
        }
        s = "\n";
        data.buffer.write(s.data(), (uint32_t) s.size(), -1);

        std::cerr << "data size " << data.buffer.size() << std::endl;

        if (num_files > 0)
            filename_full = filename + "." + std::to_string(k+1);
        else
            filename_full = filename;

        r = data.save_to_file(filename_full);
        if (r==false)
        {
            std::cerr << "ERROR writing to " << filename_full << std::endl;
            break;
        }
     }
     return r;
}

void serializeUInt32(char (&buf)[4], uint32_t val)
{
  memcpy(buf, &val, 4);
}

uint32_t parseUInt32(const char (&buf)[4])
{
  uint32_t val;
  memcpy(&val, buf, 4);
  return val;
}

bool generate_binary_random_file(std::string filename, long long Nk, long num_files = 1)
{
    //UINT_MAX   = 4294967295
    //ULONG_MAX  = 18446744073709551615
    //ULLONG_MAX = 18446744073709551615
#ifdef _WIN32
    uint32_t LIM = UINT_MAX;
#else
    uint32_t LIM = std::numeric_limits<uint32_t>::max();
#endif

    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    uint32_t n;
    char buf[4];
    bool r = true;
    random_engine rd;
    long long N = Nk*1024/4;
    long long t;

    rng::tsc_seed seed;
    rng::rng128 gen(seed());

    std::cerr << "LIM  " << LIM << std::endl;

    std::string filename_full;
    for(long long k=0;k<num_files;k++)
    {
        cryptodata data;
        data.realloc((uint32_t)(Nk*1024));
        for(long long i=0;i<N;i++)
        {
            if (i%2 == 0)
                n = (uint32_t)(rd.get_rand() * LIM);
            else
                n = gen() % LIM;

            serializeUInt32(buf, n);;
            data.buffer.write(buf, 4, -1);

            t = (long long)(rd.get_rand() * 3);
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
            if (i%20 == 0)
                srand ((unsigned int)time(NULL));
            t = rand() % 3;
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
        }

        if (num_files > 0)
            filename_full = filename + "." + std::to_string(k+1);
        else
            filename_full = filename;

        r = data.save_to_file(filename_full);
        if (r==false)
        {
            std::cerr << "ERROR writing to " << filename_full << std::endl;
            break;
        }
        else
        {
            std::cerr << "saving " << filename_full << std::endl;
        }
    }
    return r;
}



std::string generate_base10_random_string(long long N)
{
    std::string r;
    int digit;

#ifdef _WIN32
    uint32_t LIM = UINT_MAX;
#else
    uint32_t LIM = std::numeric_limits<uint32_t>::max();
#endif

    srand ((unsigned int)random_engine::getTickCount());
    uint32_t n;
    random_engine rd;
    long long t;

    rng::tsc_seed seed;
    rng::rng128 gen(seed());

    {
        for(long long i=0;i<N;i++)
        {
            if (i%2 == 0)
                n = (uint32_t)(rd.get_rand() * LIM);
            else
                n = gen() % LIM;

            digit = (int)(n % 10);
            if ((i==0) && (digit==0)) digit = 1;
            r += (digit +'0');

            t = (long long)(rd.get_rand() * 3);
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
            if (i%20 == 0)
                srand ((unsigned int)random_engine::getTickCount());

            t = rand() % 5;
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
       }
    }
    return r;
}


std::string generate_base64_random_string(long long N)
{
    std::string r;
    int digit;

#ifdef _WIN32
    uint32_t LIM = UINT_MAX;
#else
    uint32_t LIM = std::numeric_limits<uint32_t>::max();
#endif

    srand ((unsigned int)time(NULL));
    srand ((unsigned int)random_engine::getTickCount());
    uint32_t n;
    random_engine rd;
    long long t;

    rng::tsc_seed seed;
    rng::rng128 gen(seed());

    {
        for(long long i=0;i<N;i++)
        {
            if (i%2 == 0)
                n = (uint32_t)(rd.get_rand() * LIM);
            else
                n = gen() % LIM;

            digit = (int)(n % 64);
            if ((i==0) && (BASEDIGIT64[i]=='0')) digit = 1;
            r += BASEDIGIT64[digit];

            t = (long long)(rd.get_rand() * 3);
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
            if (i%20 == 0)
               srand ((unsigned int)random_engine::getTickCount());

            t = rand() % 5;
           for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
        }
    }
    return r;
}

std::string generate_base16_random_string(long long N)
{
    std::string r;
    int digit;

#ifdef _WIN32
    uint32_t LIM = UINT_MAX;
#else
    uint32_t LIM = std::numeric_limits<uint32_t>::max();
#endif

    srand ((unsigned int)time(NULL));
    srand ((unsigned int)random_engine::getTickCount());
    uint32_t n;
    random_engine rd;
    long long t;

    rng::tsc_seed seed;
    rng::rng128 gen(seed());

    {
        for(long long i=0;i<N;i++)
        {
            if (i%2 == 0)
                n = (uint32_t)(rd.get_rand() * LIM);
            else
                n = gen() % LIM;

            digit = (int)(n % 16);
            if ((i==0) && (BASEDIGIT16[i]=='0')) digit = 1;
            r += BASEDIGIT16[digit];

            t = (long long)(rd.get_rand() * 3);
            for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
            if (i%20 == 0)
               srand ((unsigned int)random_engine::getTickCount());

            t = rand() % 5;
           	for(long long j=0;j<t;j++)
            {
                rd.get_rand();
                gen();
            }
        }
    }
    return r;
}

}
#endif

