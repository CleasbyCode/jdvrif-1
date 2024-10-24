void displayInfo() {
	std::cout << R"(

JPG Data Vehicle (jdvout v1.7). 
Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023.

jdvout is a steganography-like CLI tool for extracting hidden data from a (jdvin) "file-embedded" JPG image. 

Compile & run jdvout (Linux):
		
$ g++ main.cpp -O2 -lz -s -o jdvout
$ sudo cp jdvout /usr/bin
$ jdvout

Usage: jdvout <file-embedded-image>
       jdvout --info

)";
}