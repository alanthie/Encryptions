#ifndef _INCLUDES_crypto_png_HPP
#define _INCLUDES_crypto_png_HPP

#include "crypto_const.hpp"
#include "qa/Bin2PNG/lodepng.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <filesystem>

namespace cryptoAL
{
namespace converter
{

// https://github.com/leeroybrun/Bin2PNG
//
// Convert a binary file to a PNG image and then decrypt it back to binary.
//
// Binary to PNG :
//     Each bytes of the binary file are converted to numbers (0-255), which will then define a pixel color.
//     For each bytes will be a grayscale pixel in the final PNG image.
//     The PNG image can have more pixels than the number of bytes of the binary file.
//     The excess pixels will have a RGB(255, 0, 0) color (red) and will be ignored when decrypting the file.
//
// PNG to Binary :
//     When decrypting the PNG file to create the corresponding binary file, we take each pixels of the image and get their color.
//     If the R & G color are different, we skip this pixel. It is not at grayscale, and so is an excess pixel.
//     It it is grayscale, we take the color number for R and then convert it to it's binary representation.
//     We construct an unsigned char array with all decrypted binary data of pixels and then save it back to a binary file.
//

class pgn_converter
{
public:
    bool 			verbose 	= false;
    unsigned char*  fileBuff 	= nullptr;
	unsigned char*  pngData  	= nullptr;
	unsigned char*	binaryBuff  = nullptr;
	unsigned int    imageSize 	= 0; // 4,294,967,295 imageSize = (int)ceil(sqrt((double) fileSize))   fileSize = imageSize*imageSize

    pgn_converter(bool verb=false) : verbose(verb) {}

    ~pgn_converter()
    {
    	// Free memory
        if (pngData != nullptr)
        {
		    free(pngData);
            pngData = nullptr;
        }
        if (fileBuff != nullptr)
        {
		    free(fileBuff);
            fileBuff = nullptr;
        }
		if (binaryBuff != nullptr)
        {
		    free(binaryBuff);
            binaryBuff = nullptr;
        }
    }

    static bool is_file_ext_png(const std::string& f)
    {
        std::filesystem::path filepath = f;
        if (filepath.extension() == ".png")
        {
            return true;
        }
        return false;
    }

	static std::string remove_ext_png(const std::string& filename)
    {
		std::string::size_type idx;
		idx = filename.rfind(".png");
		if(idx != std::string::npos)
		{
			//std::string extension = filename.substr(idx+1);
			return filename.substr(0, idx);
		}
		return filename;
	}

	static uint32_t get_require_padding(uint32_t input_size)
	{
		uint32_t sz = (uint64_t)ceil(sqrt((double) input_size));
		uint64_t t = sz*sz;
		if (t >= input_size)
			return (uint32_t) (t - input_size);
		return 0; // ?
	}

	// square value imageSize*imageSize
	uint64_t decrypt_size_of_inputfile(const::std::string& BIN_IN_FILE)
	{
	    FILE* binaryFile = fopen(BIN_IN_FILE.data(), "rb");
        if(binaryFile == NULL)
        {
			if (verbose)
            	std::cerr << "Error opening file: " << BIN_IN_FILE << std:: endl;
            return 0;
        }
        else
        {
            // Get file length
            fseek(binaryFile, 0, SEEK_END);
            unsigned long sz = ftell(binaryFile);
			fclose(binaryFile);

			imageSize = (unsigned int)ceil(sqrt((double) sz));
			return (uint64_t)imageSize*imageSize;
		}
	}

    // Convert a binary file to PNG
    int binaryToPng(const::std::string& BIN_IN_FILE, const::std::string& PNG_FILE)
    {
        FILE*           binaryFile;
        unsigned long   fileSize;
        char            pixelColorStr[4];
        int             pixelColor;
        unsigned int    i, x, y, error;

        // Open binary file
        binaryFile = fopen(BIN_IN_FILE.data(), "rb");
        if(binaryFile == NULL)
        {
           	std::cerr << "Error reading file: " << BIN_IN_FILE << std:: endl;
            return -1;
        }
        else
        {
            // Get file length
            fseek(binaryFile, 0, SEEK_END);
            fileSize = ftell(binaryFile);
            fseek(binaryFile, 0, SEEK_SET);

            // Allocate memory for the file buffer
            fileBuff = (unsigned char *)malloc(fileSize);

            // Get final image size
            imageSize = (int)ceil(sqrt((double) fileSize));

            // Print various informations
            if (verbose)
            {
                printf("Size of file : %ld bytes\n", fileSize);
                printf("Size of final image : %d x %d px\n", imageSize, imageSize);
                puts("\n");
            }

            // Allocate memory for the PNG data array
            pngData = (unsigned char *) malloc(imageSize * imageSize * 4);

            // Read binary file to buffer
            size_t sz =fread(fileBuff, fileSize, 1, binaryFile);

            if (sz == 0)
            {
                puts("WARNING PNG file empty...");
            }
            if (verbose)
                puts("Starting conversion to PNG file...");

            x = 0;
            y = 0;
            // Process each bytes, add pixel to pngData array
            for(i = 0; i < fileSize; i++)
			{
                // Get decimal value for this byte, will be the pixel color (convert byte to int)
                sprintf(pixelColorStr, "%d", fileBuff[i]);
                sscanf(pixelColorStr, "%d", &pixelColor);

                // Set pixel data
                pngData[4 * imageSize * y + 4 * x + 0] = pixelColor; // R
                pngData[4 * imageSize * y + 4 * x + 1] = pixelColor; // G
                pngData[4 * imageSize * y + 4 * x + 2] = pixelColor; // B
                pngData[4 * imageSize * y + 4 * x + 3] = 255;		 // A

                x += 1;

                // When reached end of pixels line, go to next one
                if(x == imageSize) {
                    x = 0;
                    y += 1;
                }
            }

            // Complete the image with red pixels
            while( x < imageSize && y < imageSize || y < imageSize )
            {
                pngData[4 * imageSize * y + 4 * x + 0] = 255; // R
                pngData[4 * imageSize * y + 4 * x + 1] = 0;   // G
                pngData[4 * imageSize * y + 4 * x + 2] = 0;   // B
                pngData[4 * imageSize * y + 4 * x + 3] = 255; // A

                x += 1;

                // When reached end of pixels line, go to next one
                if(x == imageSize) {
                    x = 0;
                    y += 1;
                }
            }

            if (verbose)
                printf("Writing PNG file to : %s\n", PNG_FILE.data());

            // Write PNG file
            error = lodepng_encode32_file(PNG_FILE.data(), pngData, imageSize, imageSize);

            // Free memory
            free(pngData);
            free(fileBuff);
			fileBuff = nullptr;
			pngData  = nullptr;

            fclose(binaryFile);

            if(error)
            {
                printf("ERROR %u: %s\n", error, lodepng_error_text(error));
                return -1;
            }
            else
            {
                if (verbose)
                    puts("Success !");
                return 0;
            }
        }
    }

    // Convert a PNG file to binary
    int pngToBinary(const::std::string& PNG_FILE, const::std::string& BIN_OUT_FILE)
    {
        FILE* binaryFile;
        unsigned int i, x, y;
        unsigned int error;

        // Decode PNG file to pngData array
        error = lodepng_decode32_file(&pngData, &imageSize, &imageSize, PNG_FILE.data());
        if(error)
        {
            printf("error %u: %s\n", error, lodepng_error_text(error));
            return -1;
        }

        if (verbose)
            printf("Image size : %d\n", imageSize);

        // Allocate memory for the binary file buffer
        binaryBuff = (unsigned char *)malloc(imageSize*imageSize*sizeof(unsigned char));

        if (verbose)
            puts("Starting conversion to binary file...");

        // Process each pixels, get color number, convert to byte and add to binary array
        i = 0;
        for(y = 0; y < imageSize; y++)
		{
            // Process pixel only if it is grayscale (R & B have same color)
            for(x = 0; x < imageSize && pngData[4 * imageSize * y + 4 * x + 0] == pngData[4 * imageSize * y + 4 * x + 1]; x++) {
                //printf("RGBA(%d, %d, %d, %d)\n", pngData[4 * imageSize * y + 4 * x + 0], pngData[4 * imageSize * y + 4 * x + 1], pngData[4 * imageSize * y + 4 * x + 2], pngData[4 * imageSize * y + 4 * x + 3]);
                binaryBuff[i] = (int)((pngData[4 * imageSize * y + 4 * x + 0] & 0XFF)); // Convert to binary

                i += 1;
            }
        }

        if (verbose)
            printf("Writing binary file to : %s\n", BIN_OUT_FILE.data());

        // Write data to binary file
        binaryFile = fopen(BIN_OUT_FILE.data(), "wb");
        if(binaryFile == NULL)
        {
            printf("Error reading '%s' file.", BIN_OUT_FILE.data());
            return -1;
        }
        else
        {
            fwrite(binaryBuff, (imageSize*imageSize*sizeof(unsigned char)), 1, binaryFile);

            if (verbose)
                puts("Success !");

            free(pngData);
            free(binaryBuff);
			binaryBuff  = nullptr;
			pngData     = nullptr;

            fclose(binaryFile);

            return 0;
        }
    }
};

}
}
#endif // _INCLUDES_crypto_png_HPP

