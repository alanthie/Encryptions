#ifndef _INCLUDES_random_engine
#define _INCLUDES_random_engine

#include <random>
#include "data.hpp"

class random_engine
{
  public:
    std::random_device                      rd;
    std::mt19937                            mt;
    std::uniform_real_distribution<double>  dist;

    random_engine() : rd{}, mt{rd()}, dist{0.0, 1.0}
    {
        seed();
    }

    double get_rand()
    {
      return dist(mt);
    }

    void seed()
    {
        srand ((unsigned int)time(NULL));
        int n = rand() % 100;
        for (int i=0;i<n;i++) get_rand(); // random seed
    }
};

bool generate_random_file(std::string filename, long long N=1000)
{
    cryptodata data;
    std::string s;
    std::string si;
    std::string sn;
    const double LIM = 1000*1000*1000;
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    long long n;
    long long t;
    random_engine rd;

    for(long long i=0;i<N;i++)
    {
        n = (long long)(rd.get_rand() * LIM);
        si = std::to_string(i);
        sn = std::to_string(n);
        if (i%10 == 0) s = si + ":" + sn + " \n";
        else s = si + ":" + sn + " ";
        data.buffer.write(s.data(), s.size(), -1);

        t = (long long)(rd.get_rand() * 100);
        for(long long j=0;j<t;j++)
            rd.get_rand();
    }
    s = "\n";
    data.buffer.write(s.data(), s.size(), -1);

    return data.save_to_file(filename);
}

bool generate_binary_random_file(std::string filename, long long N=10000)
{
    cryptodata data;
    const double LIM = 256*256;
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    uint16_t n;
    long long t;
    random_engine rd;

    for(long long i=0;i<N;i++)
    {
        n = (uint16_t)(rd.get_rand() * LIM);
        data.buffer.writeUInt16(n, -1);

        t = (long long)(rd.get_rand() * 100);
        for(long long j=0;j<t;j++)
            rd.get_rand();
    }
    return data.save_to_file(filename);
}

#endif

