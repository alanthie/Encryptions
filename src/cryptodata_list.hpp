#ifndef _INCLUDES_cryptodata_list
#define _INCLUDES_cryptodata_list

#include "crypto_const.hpp"
#include "crypto_png.hpp"
#include <iostream>
#include "data.hpp"
#include <fstream>
#include <stdio.h>

namespace cryptoAL
{

struct cryptodata_list_header_item
{
	CRYPTO_FILE_TYPE    data_type = CRYPTO_FILE_TYPE::Unknown; // raw data, rsa, ecc, hh, KEY_STATUS, ...
	uint32_t            data_size = 0;
	std::string         filename;       // only for reading not saved in header
	std::string         recipient_short_filename;

	cryptodata_list_header_item(const std::string& file, const std::string& recipientshortfilename, uint32_t datasize, CRYPTO_FILE_TYPE datatype)
	{
		filename = file;
		recipient_short_filename = recipientshortfilename;
		data_size = datasize;
		data_type = datatype;
	}
};

struct cryptodata_list_header
{
	char magic_number[8] = {'c', 'r', 'y', 'p', 't', 'o', 'e', 'n'};
	uint32_t version = 1000;
	uint32_t padding = 0;
	uint32_t converter = 0; // 1 = png
	std::vector<cryptodata_list_header_item> vitem;

	void add_item(const std::string& filename, const std::string& recipientshortfilename, uint32_t datasize, CRYPTO_FILE_TYPE datatype, bool verbose=false)
	{
        verbose=verbose;
        //if (verbose) std::cout << "header add item: " << filename << " datasize: " << datasize << " datatype: " << (uint32_t)datatype << " shortfilename: " << recipientshortfilename  << std::endl;

		cryptodata_list_header_item hitem(filename, recipientshortfilename, datasize, datatype);
		vitem.push_back(hitem);
	}

	uint32_t get_total_size()
	{
		uint32_t r = 0;
		r+=8;	// magic_number
		r+=4;	// version
		r+=4;	// padding
		r+=4;	// converter
		r+=4; 	// size vitem
		for(size_t i=0;i<vitem.size();i++)
		{
			r+=4; // data_type
			r+=4; // data_size
			r+=4; // recipient_short_filename.size()
			r+=vitem[i].recipient_short_filename.size();
		}
		return r;
	}

	void set_converter(uint32_t t)
	{
		// 1 == png padding
		converter = t;
		if (t > 0)
		{
			//if (verbose)
			//	std::cout << "CONVERTER : " << t << std::endl;
		}
	}

	void update_padding(uint32_t file_size_before_padding)
	{
		if (converter == 1)
		{
            padding = converter::pgn_converter::get_require_padding(file_size_before_padding);
			//std::cout << "PGN PADDING is : " << padding << std::endl;
		}
		else
		{
			padding = 0;
		}
	}

	void show()
	{
		std::cout << "------------------------------------------------- "  << std::endl;
		std::cout << "HEADER : " << std::endl;
		std::cout << "------------------------------------------------- "  << std::endl;
		std::cout << "size:        "  << get_total_size()<< std::endl;
        std::string m(magic_number, 8);
        std::cout << "magic:       " 		<< m << std::endl;
		std::cout << "version:     " 	<< version << std::endl;
		std::cout << "padding:     " 	<< padding << std::endl;
		std::cout << "converter:   " 	<< converter << std::endl;
		std::cout << "files count: " 	<< vitem.size() << std::endl;
		for(size_t i=0;i<vitem.size();i++)
		{
			std::cout   << "data type: "<< (uint32_t)vitem[i].data_type
                        << ", data size: "<< vitem[i].data_size
                        << ", remote short filename: " << vitem[i].recipient_short_filename
                        << ", local filename: " << vitem[i].filename
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
		bout.writeUInt32(padding, -1);
		bout.writeUInt32(converter, -1);
		bout.writeUInt32(vitem.size(), -1);
		for(size_t i=0;i<vitem.size();i++)
		{
			bout.writeUInt32((uint32_t)vitem[i].data_type, -1);
			bout.writeUInt32(vitem[i].data_size, -1);
			bout.writeUInt32(vitem[i].recipient_short_filename.size(), -1);
			bout.write(vitem[i].recipient_short_filename.data(),vitem[i].recipient_short_filename.size(), -1);
		}
		return r;
	}

	void error(int n, uint32_t sz = 0, uint32_t pos = 0)
	{
        if      (n==1) std::cerr << "ERROR invalid file header" << std::endl;
        else if (n==2) std::cerr << "ERROR invalid file size, unable to read file header " << sz << " " << pos << std::endl;
	}

	bool read_from_buffer(  Buffer& in_data,
                            const std::string&  folder_other_public_rsa,
                            const std::string&  folder_other_public_ecc,
                            const std::string&  folder_other_public_hh,
							const std::string&  folder_my_private_rsa,
                            const std::string&  folder_my_private_ecc,
                            const std::string&  folder_my_private_hh,
                            bool verbose = false)
	{
		bool r = true;
		uint32_t pos=0;
		uint32_t sz_in = in_data.size();

		if (verbose)
			std::cout << "read_from_buffer " << in_data.size() << std::endl;

		if (sz_in < 8+8) {error(2, sz_in, 8+8); return false;}

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

		if (verbose)
			std::cout << "read_from_buffer magic_number OK" << std::endl;

		version = in_data.readUInt32(pos);pos+=4;
		padding = in_data.readUInt32(pos);pos+=4;
		converter = in_data.readUInt32(pos);pos+=4;

		if (verbose) std::cout << "version   " << version << std::endl;
		if (verbose) std::cout << "padding   " << padding << std::endl;
		if (verbose) std::cout << "converter " << converter << std::endl;

		uint32_t sz = in_data.readUInt32(pos);pos+=4;
		if (verbose) std::cout << "file count " << sz << std::endl;

		for(size_t i=0;i<sz;i++)
		{
			if (sz_in < pos+12) {error(2, sz_in, pos+12);return false;}

			auto t = in_data.readUInt32(pos);pos+=4;
			CRYPTO_FILE_TYPE data_type = to_enum<CRYPTO_FILE_TYPE>(t);

			if (verbose) std::cout << "data_type " << (int)data_type << std::endl;

			uint32_t data_size = in_data.readUInt32(pos);pos+=4;
			uint32_t filename_size = in_data.readUInt32(pos);pos+=4;

			if (verbose) std::cout << "data_size " << data_size << std::endl;
			if (verbose) std::cout << "filename_size " << filename_size << std::endl;

			int8_t c;
			std::string shortfilename;

			if (sz_in < pos+filename_size) {error(2, sz_in, pos+filename_size);return false;}
			for(size_t j=0;j<filename_size;j++)
			{
				c = in_data.readInt8(pos);
				shortfilename += (char)c;
				pos+=1;
			}

			if (verbose)
				std::cout << "read_from_buffer shortfilename " << shortfilename <<  std::endl;

            std::string filename;
			if      (data_type == CRYPTO_FILE_TYPE::RSA_PUBLIC) filename = folder_other_public_rsa + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::ECC_PUBLIC) filename = folder_other_public_ecc + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::ECC_DOMAIN) filename = folder_other_public_ecc + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::HH_PUBLIC)  filename = folder_other_public_hh  + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)  	filename = folder_my_private_rsa + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::ECC_KEY_STATUS) 	filename = folder_my_private_ecc + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::ECC_DOM_STATUS) 	filename = folder_my_private_ecc + shortfilename;
			else if (data_type == CRYPTO_FILE_TYPE::HH_KEY_STATUS)  	filename = folder_my_private_hh  + shortfilename;
			else filename = shortfilename;

			add_item(filename, shortfilename, data_size, data_type);
		}

		if (verbose) show();
		return r;
	}
};


struct cryptodata_item
{
    cryptodata_item(const std::string& file, const std::string& recipientshortfilename, cryptodata* buff, CRYPTO_FILE_TYPE datatype)
    {
		data_type 	= datatype;
        filename 	= file;
        recipient_short_filename = recipientshortfilename;
        b = buff;
		if (buff != nullptr)
		{
			own_buffer = false;
		}
    }

	CRYPTO_FILE_TYPE 	data_type = CRYPTO_FILE_TYPE::Unknown;
    std::string 		filename;
    std::string         recipient_short_filename;
    cryptodata* 		b = nullptr;
	bool				own_buffer = true;
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
				if (vitem[i].own_buffer)
				{
					delete vitem[i].b;;
					vitem[i].b = nullptr;
				}
			}
		}
	}

	void set_converter(uint32_t t)
	{
		// 1 == png padding
		header.set_converter(t);
	}

	void error(int n, const std::string& s = "")
	{
        if      (n==1) std::cerr << "ERROR unable to read header" << std::endl;
        else if (n==2) std::cerr << "ERROR unable to read internal file: " << s <<std::endl;
        else if (n==3) std::cerr << "ERROR unable to write header" <<std::endl;
	}

	// pre post decode
	bool read_write_from(   cryptodata& in_data, const std::string& filename_raw_data, // make vector raw
                            const std::string&  folder_other_public_rsa,
                            const std::string&  folder_other_public_ecc,
                            const std::string&  folder_other_public_hh,
							const std::string&  folder_my_private_rsa,
                            const std::string&  folder_my_private_ecc,
                            const std::string&  folder_my_private_hh,
							bool verbose = false)
	{
		bool r = true;
		r = header.read_from_buffer(in_data.buffer,
                                    folder_other_public_rsa,
                                    folder_other_public_ecc,
                                    folder_other_public_hh,
									folder_my_private_rsa,
                           			folder_my_private_ecc,
                             		folder_my_private_hh,
									verbose);
		if (r)
		{
			for(size_t i=0;i<header.vitem.size();i++)
			{
				cryptodata* p = new cryptodata();
				cryptodata_item item(header.vitem[i].filename, header.vitem[i].recipient_short_filename, p, header.vitem[i].data_type);
				vitem.push_back(item);
			}

            int cntRAW = 0;
			uint32_t posdata = header.get_total_size();

			if (verbose) std::cout << "------------------------------------ " <<  std:: endl;
			if (verbose) std::cout << " Saving files: " << std:: endl;
			if (verbose) std::cout << "------------------------------------ " <<  std:: endl;
			for(size_t i=0;i<vitem.size();i++)
			{
                if ( (cntRAW==0) && (header.vitem[i].data_type == CRYPTO_FILE_TYPE::RAW))
                {
                    cntRAW++;
                    vitem[i].filename = filename_raw_data;
                }
				vitem[i].b->buffer.increase_size(header.vitem[i].data_size);

				// This is a copy of all public valid key - not incremental.....
				vitem[i].b->buffer.write(&in_data.buffer.getdata()[posdata], header.vitem[i].data_size, 0);

				// bck...

				if (verbose)
				{
					std::cout << "saving... " << vitem[i].filename << std:: endl;
				}
				vitem[i].b->save_to_file(vitem[i].filename);

				posdata += header.vitem[i].data_size;
			}
			if (verbose) std::cout << "------------------------------------ "  << std:: endl<< std:: endl;
		}
		else
		{
            error(1);
		}

		return r;
	}

    void add_data(cryptodata* b, const std::string& filename, const std::string& recipient_short_filename, CRYPTO_FILE_TYPE datatype)
    {
		cryptodata_item item(filename, recipient_short_filename, b, datatype);
		vitem.push_back(item);

		if (b != nullptr)
			header.add_item(filename, recipient_short_filename, b->buffer.size(), datatype, verbose);
		else
			header.add_item(filename, recipient_short_filename, 0, datatype, verbose);
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

	bool read_data_from_file_or_buffer()
	{
		if (verbose) std::cout << "-------------------------------------- "<< std::endl;
		if (verbose) std::cout << "Reading files: "<< std::endl;
		if (verbose) std::cout << "-------------------------------------- "<< std::endl;
	 	bool r = true;
		for(size_t i=0;i<vitem.size();i++)
		{
			bool read_from_file = true;
			if (vitem[i].b == nullptr)
				vitem[i].b = new cryptodata();
			else
				read_from_file = false;

			if (read_from_file)
			{
				if (verbose) std::cout << "reading from file: "<< vitem[i].filename << std::endl;
				vitem[i].b->buffer.seek_begin();
				r = vitem[i].b->read_from_file(vitem[i].filename);
				if (r == false)
				{
					error(2, vitem[i].filename);
					break;
				}
			}
			else
			{
				if (verbose) std::cout << "reading from memory buffer: " << vitem[i].filename << std::endl;
			}
		}
		if (verbose) std::cout << "-------------------------------------- "<< std::endl << std::endl;
		return r;
	}

 	bool create_header_trailer_buffer(cryptodata& bout)
	{
		bool r = true;

		r = read_data_from_file_or_buffer();
		if (r==false) return r;

		update_data_size_in_header();

		uint32_t sz = header.get_total_size(); // header size
		if (verbose) header.show();

		Buffer temp_header(sz);
		Buffer temp_footer;

		uint32_t sz_data = 0;
		for(size_t i=0;i<vitem.size();i++)
		{
			if (vitem[i].b != nullptr)
			{
				if (vitem[i].b->buffer.size() > 0)
				{
					sz_data += vitem[i].b->buffer.size();
				}
			}
		}

		// padding
		header.update_padding(sz + sz_data);
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
			// padding
			if (r)
			{
				if (header.padding > 0)
				{
					if (verbose)
						std::cout << "Data padding... : " << header.padding << std::endl;
					char c[1] = {0};
					for(size_t i=0;i<header.padding;i++)
					{
						temp_footer.write(&c[0], 1);
					}
				}
			}

			bout.buffer.increase_size(temp_header.size() + temp_footer.size());
			if (verbose)
			{
				if (header.padding > 0)
				{
					std::cout << "size before padding... : " << sz + sz_data << std::endl;
					std::cout << "size after  padding... : " << sz + sz_data + header.padding << std::endl;
				}
			}

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
