# SIMPLE-ECC

By: Iskandar Setiadi (freedomofkeima)

## Development Environment

- Linux/UNIX based Operating System

- C Language (C11) with GNU GMP 6.0 support (https://gmplib.org/)

## Requirements

** Install GNU GMP 6.0 **

1. Install GNU GMP 6.0 in your system (read the details in: https://gmplib.org/)

## How to Run

Use the following syntax for compilation process:

    make

Use the following syntax to run the application:

    make run
    
Also, you can define parts that you're interested in at main.c (as the following):

    // Define your TEST here
    
    #define TEST_MODULAR_OPERATION true
    
    #define TEST_SCALAR_OPERATION true
    
    #define TEST_SCALAR_ALGORITHM true
    
    #define TEST_ENCRYPT_DECRYPT true
    
    #define TEST_SIMPLIFIED_ECIES true


## Additional Information

This project is using RDTSC & RDTSCP for measuring average running time. ( Reference: https://idea.popcount.org/2013-01-28-counting-cycles---rdtsc/ )

Make sure to "warm up" the code before benchmarking. (avoid cache effects in the first iteration)

The report of this project can be accessed at https://www.researchgate.net/publication/268688957_Elliptic_Curve_Cryptography_Algorithms_and_Implementation_Analysis_over_Coordinate_Systems

---
#### MIT License

Copyright (c) 2014 Iskandar Setiadi <iskandarsetiadi@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Last Updated: November 19, 2014