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

bool generate_random_file(std::string filename, long Nk, long num_files = 1)
{
    std::string s;
    std::string si;
    std::string sn;
    const double LIM = 1000*1000*1000;
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    long long n;
    long t;
    bool r = true;
    random_engine rd;
    long N = Nk*1000;
    long sz=0;

    std::string filename_full;
    for(long long k=0;k<num_files;k++)
    {
        sz=0;
        cryptodata data;
        for(long long i=0;i<N;i++)
        {
            n = (long long)(rd.get_rand() * LIM);
            si = std::to_string(i);
            sn = std::to_string(n);
            if (i%10 == 0) s = si + ":" + sn + " \n";
            else s = si + ":" + sn + " ";
            sz += s.size();
            data.buffer.write(s.data(), s.size(), -1);

            if (sz >= N)
                break;

            t = (long long)(rd.get_rand() * 10);
            for(long long j=0;j<t;j++)
                rd.get_rand();
        }
        s = "\n";
        data.buffer.write(s.data(), s.size(), -1);

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

bool generate_binary_random_file(std::string filename, long long Nk, long num_files = 1)
{
    uint32_t LIM = (uint32_t) ( ((uint64_t)(256ull*256ull*256ull*256ull)) - 1);
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    uint32_t n;
    long t;
    bool r = true;
    random_engine rd;
    long long N = Nk*1000/4;

    std::string filename_full;
    for(long long k=0;k<num_files;k++)
    {
        cryptodata data;
        for(long long i=0;i<N;i++)
        {
            n = (uint32_t)(rd.get_rand() * LIM);
            data.buffer.writeUInt32(n, -1);

            t = (long long)(rd.get_rand() * 2);
            for(long long j=0;j<t;j++)
                rd.get_rand();
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

#endif

