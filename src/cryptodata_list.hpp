#ifndef _INCLUDES_cryptodata_list
#define _INCLUDES_cryptodata_list

#include <iostream>
#include "data.hpp"
#include <fstream>
#include <stdio.h>

namespace cryptoAL
{

struct cryptodata_list_header_item
{
	CRYPTO_FILE_TYPE    data_type = CRYPTO_FILE_TYPE::Unknown; // raw data, rsadb, eccdb, hhdb, ...
	uint32_t            data_size = 0;
	std::string         filename;       // only for reading not saved in header
	std::string         public_other_short_filename;

	cryptodata_list_header_item(const std::string& file, const std::string& publicothershortfilename, uint32_t datasize, CRYPTO_FILE_TYPE datatype)
	{
		filename = file;
		public_other_short_filename = publicothershortfilename;
		data_size = datasize;
		data_type = datatype;
	}
};

struct cryptodata_list_header
{
	char magic_number[8] = {'c', 'r', 'y', 'p', 't', 'o', 'e', 'n'};
	uint32_t version = 1000;
	std::vector<cryptodata_list_header_item> vitem;

	void add_item(const std::string& filename, const std::string& publicothershortfilename, uint32_t datasize, CRYPTO_FILE_TYPE datatype, bool verbose=false)
	{
        if (verbose) std::cout << "header add item: " << filename << " datasize: " << datasize << " datatype: " << (uint32_t)datatype << " shortfilename: " << publicothershortfilename  << std::endl;

		cryptodata_list_header_item hitem(filename, publicothershortfilename, datasize, datatype);
		vitem.push_back(hitem);
	}

	uint32_t get_total_size()
	{
		uint32_t r = 0;
		r+=8;	// magic_number
		r+=4;	// version
		r+=4; 	// size vitem
		for(size_t i=0;i<vitem.size();i++)
		{
			r+=4; // data_type
			r+=4; // data_size
			r+=4; // public_other_short_filename.size()
			r+=vitem[i].public_other_short_filename.size();
		}
		return r;
	}

	void show()
	{
		std::cout << "------------------------------------------------- "  << std::endl;
		std::cout << "HEADER get_total_size: "  << get_total_size()<< std::endl;
        std::string m(magic_number, 8);
        std::cout << "magic: " 		<< m << std::endl;
		std::cout << "version: " 	<< version << std::endl;
		std::cout << "vitem size: " 	<< vitem.size() << std::endl;
		for(size_t i=0;i<vitem.size();i++)
		{
			std::cout   << "data_type: "<< (uint32_t)vitem[i].data_type
                        << " data_size: "<< vitem[i].data_size
                        << " short_filename: " << vitem[i].public_other_short_filename
                        << " filename: " << vitem[i].filename
                        << std::endl;
		}
		std::cout << "------------------------------------------------- "  << std::endl<< std::endl;
	}

	bool fill_into_buffer(Buffer& bout)
	{
		bool r = true;
		bout.increase_size(get_total_size());
		bout.seek_begin();

		bout.write(&magic_number[0], 8, 0);
		bout.writeUInt32(version, -1);
		bout.writeUInt32(vitem.size(), -1);
		for(size_t i=0;i<vitem.size();i++)
		{
			bout.writeUInt32((uint32_t)vitem[i].data_type, -1);
			bout.writeUInt32(vitem[i].data_size, -1);
			bout.writeUInt32(vitem[i].public_other_short_filename.size(), -1);
			bout.write(vitem[i].public_other_short_filename.data(),vitem[i].public_other_short_filename.size(), -1);
		}
		return r;
	}

	void error(int n)
	{
        if      (n==1) std::cerr << "ERROR invalid file header" << std::endl;
        else if (n==2) std::cerr << "ERROR invalid file size, unable to read file header" << std::endl;
	}

	bool read_from_buffer(  Buffer& in_data,
                            const std::string&  folder_other_public_rsa,
                            const std::string&  folder_other_public_ecc,
                            const std::string&  folder_other_public_hh,
                            bool verbose = false)
	{
		bool r = true;
		uint32_t pos=0;
		uint32_t sz_in = in_data.size();

		if (sz_in < 8+8) {error(2); return false;}

		in_data.write(&magic_number[0], 8, pos);
		if (magic_number[0] != 'c') {error(1);return false;}
		if (magic_number[1] != 'r') {error(1);return false;}
		if (magic_number[2] != 'y') {error(1);return false;}
		if (magic_number[3] != 'p') {error(1);return false;}
		if (magic_number[4] != 't') {error(1);return false;}
		if (magic_number[5] != 'o') {error(1);return false;}
		if (magic_number[6] != 'e') {error(1);return false;}
		if (magic_number[7] != 'n') {error(1);return false;}
		pos+=8;

		version = in_data.readUInt32(pos);pos+=4;
		uint32_t sz = in_data.readUInt32(pos);pos+=4;

		for(size_t i=0;i<sz;i++)
		{
			if (sz_in < pos+12) {error(2);return false;}

			auto t = in_data.readUInt32(pos);pos+=4;
			CRYPTO_FILE_TYPE data_type = to_enum<CRYPTO_FILE_TYPE>(t);

			uint32_t data_size = in_data.readUInt32(pos);pos+=4;
			uint32_t filename_size = in_data.readUInt32(pos);pos+=4;

			int8_t c;
			std::string shortfilename;

			if (sz_in < pos+filename_size) {error(2);return false;}
			for(size_t j=0;j<filename_size;j++)
			{
				c = in_data.readInt8(pos);
				shortfilename += (char)c;
				pos+=1;
			}

            std::string filename;
			if      (data_type == CRYPTO_FILE_TYPE::RSA_PUBLIC) filename = folder_other_public_rsa + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::ECC_PUBLIC) filename = folder_other_public_ecc + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::HH_PUBLIC)  filename = folder_other_public_hh  + shortfilename;
			else filename = shortfilename;

			add_item(filename, shortfilename, data_size, data_type);
		}

		if (verbose) show();
		return r;
	}
};


struct cryptodata_item
{
    cryptodata_item(const std::string& file, const std::string& publicothershortfilename, cryptodata* buff, CRYPTO_FILE_TYPE datatype)
    {
		data_type = datatype;
        filename = file;
        public_other_short_filename = publicothershortfilename;
        b = buff;
    }

	CRYPTO_FILE_TYPE 	data_type = CRYPTO_FILE_TYPE::Unknown;
    std::string 		filename;
    std::string         public_other_short_filename;
    cryptodata* 		b = nullptr;
};

class cryptodata_list
{
public:
    cryptodata_list(bool verb = false) {verbose = verb;}

    ~cryptodata_list()
	{
		for(size_t i=0;i<vitem.size();i++)
		{
			if (vitem[i].b != nullptr)
			{
				delete vitem[i].b;;
				vitem[i].b = nullptr;
			}
		}
	}

	void error(int n, const std::string& s = "")
	{
        if      (n==1) std::cerr << "ERROR unable to read header" << std::endl;
        else if (n==2) std::cerr << "ERROR unable to read internal file: " << s <<std::endl;
        else if (n==3) std::cerr << "ERROR unable to write header" <<std::endl;
	}

	// post decode
	bool read_write_from(   cryptodata& in_data, const std::string& filename_decrypted_data,
                            const std::string&  folder_other_public_rsa,
                            const std::string&  folder_other_public_ecc,
                            const std::string&  folder_other_public_hh,
							bool verbose = false)
	{
		bool r = true;
		r = header.read_from_buffer(in_data.buffer,
                                    folder_other_public_rsa,
                                    folder_other_public_ecc,
                                    folder_other_public_hh, verbose);
		if (r)
		{
			for(size_t i=0;i<header.vitem.size();i++)
			{
				cryptodata* p = new cryptodata();
				cryptodata_item item(header.vitem[i].filename, header.vitem[i].public_other_short_filename, p, header.vitem[i].data_type);
				vitem.push_back(item);
			}

            int cntRAW = 0;
			uint32_t posdata = header.get_total_size();

			for(size_t i=0;i<vitem.size();i++)
			{
                if ( (cntRAW==0) && (header.vitem[i].data_type == CRYPTO_FILE_TYPE::RAW))
                {
                    cntRAW++;
                    vitem[i].filename = filename_decrypted_data;
                }
				vitem[i].b->buffer.increase_size(header.vitem[i].data_size);
				vitem[i].b->buffer.write(&in_data.buffer.getdata()[posdata], header.vitem[i].data_size, 0);

				// bck...

				vitem[i].b->save_to_file(vitem[i].filename);

				posdata += header.vitem[i].data_size;
			}
		}
		else
		{
            error(1);
		}

		return r;
	}

    void add_data(cryptodata* b, const std::string& filename, const std::string& public_other_short_filename, CRYPTO_FILE_TYPE datatype)
    {
		cryptodata_item item(filename, public_other_short_filename, b, datatype);
		vitem.push_back(item);

		if (b != nullptr)
			header.add_item(filename, public_other_short_filename, b->buffer.size(), datatype, verbose);
		else
			header.add_item(filename, public_other_short_filename, 0, datatype, verbose);
    }

 	void update_data_size_in_header()
	{
		for(size_t i=0;i<vitem.size();i++)
		{
			if (vitem[i].b != nullptr)
				header.vitem[i].data_size = vitem[i].b->buffer.size();
			else
				header.vitem[i].data_size = 0;
		}
	}

	bool read_data_fromfile()
	{
	 	bool r = true;
		for(size_t i=0;i<vitem.size();i++)
		{
			if (vitem[i].b == nullptr)
				vitem[i].b = new cryptodata();

			vitem[i].b->buffer.seek_begin();
			if (verbose) std::cout << "reading : "<< vitem[i].filename << std::endl;
			r = vitem[i].b->read_from_file(vitem[i].filename);
			if (r == false)
            {
                error(2, vitem[i].filename);
                break;
            }
		}
		return r;
	}

 	bool create_header_trailer_buffer(cryptodata& bout)
	{
		bool r = true;

		r = read_data_fromfile();
		if (r==false) return r;

		update_data_size_in_header();

		uint32_t sz = header.get_total_size();
		if (verbose) header.show();

		Buffer temp_header(sz);
		Buffer temp_footer;

		r = header.fill_into_buffer(temp_header);
		if (r)
		{
			for(size_t i=0;i<vitem.size();i++)
			{
				if (vitem[i].b != nullptr)
				{
                    if (vitem[i].b->buffer.size() > 0)
                    {
                        temp_footer.write(&vitem[i].b->buffer.getdata()[0], vitem[i].b->buffer.size());
					}
				}
			}

			bout.buffer.increase_size(temp_header.size() + temp_footer.size());

			// REDO write by block size....
        	bout.buffer.write(temp_header.getdata(), temp_header.size(), 0);
			bout.buffer.write(temp_footer.getdata(), temp_footer.size(), -1);
		}
		else
		{
            error(3);
		}
		return r;
	}

	cryptodata_list_header 			header;
    std::vector<cryptodata_item> 	vitem;
    bool verbose = false;
};


} //namespace
#endif
