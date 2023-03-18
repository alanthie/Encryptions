#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ecc_curve.hpp"

int random_in_range (unsigned int min, unsigned int max)
{
    int base_random = rand(); /* in [0, RAND_MAX] */
    if (RAND_MAX == base_random) return random_in_range(min, max);

    int range       = max - min,
    remainder   = RAND_MAX % range,
    bucket      = RAND_MAX / range;
    if (base_random < RAND_MAX - remainder)
    {
        return min + base_random/bucket;
    }
    else
    {
        return random_in_range (min, max);
    }
}

// inital msg = x = 0x00 ---- 0x00 "FFzaa234fsdf" 0x00
bool ecc_curve::format_msg_for_ecc(const std::string& msg, cryptoAL::Buffer& out_message)
{
    if (msg.size() > MSG_BYTES_MAX)
    {
        std::cerr << "ERROR msg.size() > MSG_BYTES_MAX" << msg.size() << " " <<MSG_BYTES_MAX<< std::endl;
        return false;
    }

    char c[1];
    out_message.clear();
    out_message.increase_size(MSG_BYTES_MAX+MSG_BYTES_PAD);
    out_message.init(0);
    out_message.seek_begin();

    size_t NBefore = MSG_BYTES_MAX + MSG_BYTES_PAD - (msg.size() + MSG_BYTES_PAD);
    c[0]=0;
   	for(int i=0;i<NBefore;i++)
   	{
        out_message.write(&c[0], 1);
   	}
   	out_message.write(msg.data(), msg.size());
   	out_message.write(&c[0], 1);

   	if (verbose)
    for(int i=0;i<out_message.size();i++)
   	{
        std::cout << i << " message[i] " << (unsigned int) (unsigned char)out_message.getdata()[i]<< std::endl;
   	}
   	return true;
}

// msg = x = 0x00 ---- 0x00 "FFzaa234fsdf" 0x00
message_point ecc_curve::getECCPointFromMessage(cryptoAL::Buffer& message_buffer)
{
    message_point rm;
    if (message_buffer.size() < MSG_BYTES_PAD)
    {
        rm.p.is_valid = false;
        std::cerr << "Invalid message size() in getECCPointFromMessage (message_buffer.size() < MSG_BYTES_PAD)" << message_buffer.size() <<std::endl;
        return rm;
    }

    mpz_t x;
	mpz_init(x);
    ecc_point r;

    size_t NBefore = 0;
    for(int i=0;i<message_buffer.size();i++)
   	{
        if (message_buffer.getdata()[i] == 0)
        {
            NBefore++;
        }
        else
        {
            break;
        }
   	}
   	size_t NAfter = message_buffer.size() - NBefore;

	unsigned int n;
    const char* message = &message_buffer.getdata()[NBefore];
	for (int i = NAfter-1;i>=0;i--)
    {
		mpz_t temp;
		mpz_init_set_str(temp,pow256string(i).data(),BASE_16);
		n = (unsigned int)(unsigned char)(*message);
		mpz_addmul_ui(x,temp,n);
		++message;
		if (verbose) gmp_printf("x=%Zd\n",x);
	}

    // check x, x+1, ... x+255 50%, 75%, ...99.9999...%
	int i=0;
	do{
		if (verbose) printf("i-> %d",i);
		if (verbose) gmp_printf(" x=%Zd\n",x);

		r = existPoint(x);
		i++;
		mpz_add_ui(x,x,1); // x++;
	}
    while( (r.is_valid==false) && i<255);

    if (r.is_valid==false)
    {
        rm.p.is_valid = false;
        std::cerr << std::string("Unable to encode message after 255 rounds in getECCPointFromMessage") << std::endl;
        return rm;
    }

    if (verbose) gmp_printf("r.x=%Zd\n",r.x);
	mpz_mod(r.x,r.x,prime); // TOO BIG..........
	if (verbose) gmp_printf("r.x mod prime = %Zd\n",r.x);

	if (r.is_valid)
    {
		rm.p = r;
		rm.qtd_adicoes = i-1;
		return rm;
	}
    else
    {
        rm.p.is_valid = false;
		return rm;
    }
}

void ecc_curve::getMessageFromPoint(message_point& msg, cryptoAL::Buffer& final_message)
{
    cryptoAL::Buffer out_message;
    out_message.clear();
    out_message.increase_size(MSG_BYTES_MAX+MSG_BYTES_PAD);
    out_message.init(0);

   	char* message = (char*)out_message.getdata();

    message_point rm;

	mpz_init_set(rm.p.x, msg.p.x);
	mpz_init_set(rm.p.y, msg.p.y);

   // msg = x = 0x00 ---- 0x00 "FFzaa234fsdf" 0x03
	unsigned int c;
	char cc;
    unsigned int K = MSG_BYTES_PAD;
    unsigned int cnt = 0;
	for (unsigned int i=0;i<MSG_BYTES_MAX+K;i++)
    {
		mpz_t pot;
		mpz_init_set_str(pot,pow256string(MSG_BYTES_MAX+K-i).data(),BASE_16);

		mpz_sub_ui(pot,pot,1);
		mpz_and(rm.p.x,rm.p.x,pot);
		mpz_t aux;
		mpz_init(aux);

		mpz_set_str(pot,pow256string(MSG_BYTES_MAX+K-1-i).data(),BASE_16);
		mpz_fdiv_q(aux,rm.p.x,pot); // digit extract

        c = mpz_get_ui(aux);
        cc = (char)c;
        message[i] = cc; // digit
        cnt++;
        if (verbose)
            std::cout << i << " digit[i] " << c << std::endl;
	}

	for (unsigned int i=cnt;i<MSG_BYTES_MAX+K;i++)
	{
        message[i] = 0;
        if (verbose) std::cout << i << " *digit[i] " << 0 << std::endl;
	}

    size_t NBefore = 0;
    for(int i=0;i<MSG_BYTES_MAX+K;i++)
   	{
        if (out_message.getdata()[i] == 0)
        {
            NBefore++;
        }
        else
        {
            break;
        }
   	}
   	size_t NAfter = MSG_BYTES_MAX+K - NBefore;

    final_message.clear();
    final_message.increase_size(NAfter - 1);
    final_message.init(0);

    for(int i=NBefore; i< MSG_BYTES_MAX+K - 1; i++) // skip last digit counter
   	{
        final_message.write(&out_message.getdata()[i], 1);
   	}

   	//char vc[1] = {0};
   	//final_message.write(&vc[0], 1); // 0 for string end ????
}

bool ecc_curve::test_encode_decode(const std::string& msg)
{
    std::string ia;
    std::string ib;
    std::string iprime;
    std::string iorder;
    int icofactor = 1;
    std::string igx;
    std::string igy;

	iprime  = "fc8f88931241dd05ccc11db66ff45a1bcf7a3c4cfaba61c9";
	ia      = "33d0ace1e83c560c67f108f774cd338b301fd1586769a7b8";
	ib      = "eecebf658d539d28aed5c99606a1485d8ccdd69eda09c6aa";
	iorder  = "fc8f88931241dd05ccc11db60b661236ad9b6ebfe3a3a75f";
	igx     = "3832fd8db6564763402cebd28bdbe680b7df161e7653242e";
	igy     = "32b5a51cd858a78ff9f685d6e3ec236b7a29fdacaa0d84cf";

	int ir = init_curve(192, ia, ib, iprime, iorder, icofactor, igx, igy);
    if (ir < 0) return false;

	ecc_point out_Cm;
	ecc_point out_rG;

    mpz_t privateKey_decoder;
	mpz_t privateKey_encoder;
	ecc_point publicKey_decoder;

	mpz_t random;
	mpz_init(random);
	gmp_randstate_t st;
	gmp_randinit_default(st);
	gmp_randseed_ui(st,random_in_range(1000,2000));

	int nr = random_in_range(1000,2000);
	for(int j=0;j<nr;j++)
	{
        mpz_urandomm(random, st, order);
	}
	mpz_urandomm(random, st, order);
	mpz_init_set(privateKey_decoder, random);
	//gmp_printf("privateKey_decoder=%Zd\n",privateKey_decoder);

    nr = random_in_range(1000,2000);
	for(int j=0;j<nr;j++)
	{
        mpz_urandomm(random, st, order);
	}
	mpz_urandomm(random, st, order);
	mpz_init_set(privateKey_encoder, random);
	//gmp_printf("privateKey_encoder=%Zd\n",privateKey_encoder);

	publicKey_decoder = mult(generator_point, privateKey_decoder);

	std::string out_msg;
    bool r = encode(out_Cm, out_rG, msg, publicKey_decoder, privateKey_encoder);
    if (r)
    {
        r = decode(out_Cm,  out_rG, out_msg, privateKey_decoder);
        if (r)
        {
            if (strcmp(msg.data(), out_msg.data()) !=0)
            {
                std::cerr << "MSG IN :[" << msg     << "]" << std::endl;
                std::cerr << "MSG out:[" << out_msg << "]" << std::endl;
                r = false;
            }
        }
        else
        {
        }
    }
    return r;
}

int ecc_curve::test_msg(const std::string& smsg)
{
	cryptoAL::Buffer buffer_message;

    message_point   rm;
    ecc_point       rp;
    ecc_point       rgenerator;

	clock_t starttime, endtime;
	starttime = clock();

    std::string ia;
    std::string ib;
    std::string iprime;
    std::string iorder;
    std::string igx;
    std::string igy;

	iprime  = "fc8f88931241dd05ccc11db66ff45a1bcf7a3c4cfaba61c9";
	ia      = "33d0ace1e83c560c67f108f774cd338b301fd1586769a7b8";
	ib      = "eecebf658d539d28aed5c99606a1485d8ccdd69eda09c6aa";
	iorder  = "fc8f88931241dd05ccc11db60b661236ad9b6ebfe3a3a75f";
	igx     = "3832fd8db6564763402cebd28bdbe680b7df161e7653242e";
	igy     = "32b5a51cd858a78ff9f685d6e3ec236b7a29fdacaa0d84cf";

	int ir = init_curve(192, ia, ib, iprime, iorder, 1, igx, igy);
	if (ir < 0) return ir;

//./ecgen --fp -u -p -r 192
//	    "field": {
//        "p": "0xfc8f88931241dd05ccc11db66ff45a1bcf7a3c4cfaba61c9"
//    },
//    "a": "0x33d0ace1e83c560c67f108f774cd338b301fd1586769a7b8",
//    "b": "0xeecebf658d539d28aed5c99606a1485d8ccdd69eda09c6aa",
//    "order": "0xfc8f88931241dd05ccc11db60b661236ad9b6ebfe3a3a75f",
//    "subgroups": [
//        {
//            "x": "0x3832fd8db6564763402cebd28bdbe680b7df161e7653242e",
//            "y": "0x32b5a51cd858a78ff9f685d6e3ec236b7a29fdacaa0d84cf",
//            "order": "0xfc8f88931241dd05ccc11db60b661236ad9b6ebfe3a3a75f",
//            "cofactor": "0x1",
//            "points": [
//                {
//                    "x": "0x3832fd8db6564763402cebd28bdbe680b7df161e7653242e",
//                    "y": "0x32b5a51cd858a78ff9f685d6e3ec236b7a29fdacaa0d84cf",
//                    "order": "0xfc8f88931241dd05ccc11db60b661236ad9b6ebfe3a3a75f"
//                }
//            ]
//

	if (verbose) gmp_printf("ORDER=%Zd\n",order);
	if (verbose) gmp_printf("PRIME=%Zd\n",prime);
	if (verbose) gmp_printf("Gxy=%Zd %Zd\n",generator_point.x,generator_point.y);

	bool r = format_msg_for_ecc(smsg, buffer_message);
	if (r==false) return -1;

    // const char* message = buffer_message.getdata();
    if (verbose) std::cout << "message: " << smsg << std::endl;

	// key generation
    mpz_t privateKey_decoder;
	mpz_t privateKey_encoder;

	mpz_t random;
	mpz_init(random);
	gmp_randstate_t st;
	gmp_randinit_default(st);
	//gmp_randseed_ui(st,time(NULL)); // NOT GOOD
	gmp_randseed_ui(st,random_in_range(1000,2000));

	int nr = random_in_range(1000,2000);
	for(int j=0;j<nr;j++)
	{
        mpz_urandomm(random, st, order);
	}
	mpz_urandomm(random, st, order);
	mpz_init_set(privateKey_decoder, random);
	if (verbose) gmp_printf("privateKey_decoder=%Zd\n",privateKey_decoder);

	nr = random_in_range(1000,2000);
	for(int j=0;j<nr;j++)
	{
        mpz_urandomm(random, st, order);
	}
	mpz_urandomm(random, st, order);
	mpz_init_set(privateKey_encoder, random);
	if (verbose) gmp_printf("privateKey_encoder=%Zd\n",privateKey_encoder);

	ecc_point publicKey_decoder = mult(generator_point, privateKey_decoder);

	rm = getECCPointFromMessage(buffer_message);
	if (rm.p.is_valid == false)
    {
		printf("ERROR \n");
		return -1;
	}
    if (verbose) gmp_printf("msg point x,y, msg add:  %Zd %Zd %d \n",rm.p.x,rm.p.y,rm.qtd_adicoes);

    // Encryption encoder
	ecc_point rG    = mult(generator_point, privateKey_encoder);
	ecc_point rPub  = mult(publicKey_decoder, privateKey_encoder);
	if (verbose) gmp_printf("Encryption publicKey_decoder(Pub=r'G).xy=%Zd %Zd\n",publicKey_decoder.x, publicKey_decoder.y);
	if (verbose) gmp_printf("Encryption privateKey_encoder(r)=%Zd\n",privateKey_encoder);
	if (verbose) gmp_printf("Encryption rPub.x %Zd rPub.y %Zd Mp.x %Zd\n",rPub.x,rPub.y,rm.p.x);
	if (verbose) gmp_printf("Encryption rG.x %Zd rG.y %Zd\n",rG.x,rG.y);

	ecc_point Cm = sum(rm.p, rPub);
	if (verbose) gmp_printf("Encryption [Cm=Pm+rGPub].x %Zd [Cm=Pm+rGPub].y %Zd\n",Cm.x,Cm.y);

	// Decryption decoder
	ecc_point rGPriv = mult(rG, privateKey_decoder);
	if (verbose) gmp_printf("Decryption privateKey_decoder(r')=%Zd rG.x=%Zd rGPriv.x=%Zd rGPriv.y=%Zd\n",privateKey_decoder,rG.x,rGPriv.x,rGPriv.y);
	mpz_neg(rGPriv.y,rGPriv.y); //-rGPriv.y

    message_point rm1;

	rm1.p = sum(Cm, rGPriv); // Cm-rGPriv
	if (verbose) gmp_printf("Decryption [Cm-rGPriv].x: %Zd [Cm-rGPriv].y: %Zd\n", rm1.p.x, rm1.p.y);
	cryptoAL::Buffer out_message;
	getMessageFromPoint(rm1, out_message);
	if (verbose) printf("Message final from [Cm-rGPriv] point: %s\n", out_message.getdata());

	endtime= clock();
	if (verbose) printf("Execution time was %lu miliseconds\n", (endtime - starttime)/(CLOCKS_PER_SEC/1000));

	return 0;
}

