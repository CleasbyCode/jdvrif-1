int jdvOut(const std::string& IMAGE_FILENAME) {
	constexpr uint32_t 
		MAX_FILE_SIZE 	= 3U * 1024U * 1024U * 1024U, 	// 3GB.
		LARGE_FILE_SIZE = 400 * 1024 * 1024;  		// 400MB.

	const size_t IMAGE_FILE_SIZE = std::filesystem::file_size(IMAGE_FILENAME);
	
	std::ifstream image_file_ifs(IMAGE_FILENAME, std::ios::binary);

	if (!image_file_ifs || IMAGE_FILE_SIZE > MAX_FILE_SIZE) {
		std::cerr << (!image_file_ifs 
			? "\nOpen File Error: Unable to read image file"
			: "\nImage File Error: Size of file exceeds the maximum limit for this program")
		<< ".\n\n";
		return 1;
	}

	std::vector<uint8_t> Image_Vec;
	Image_Vec.resize(IMAGE_FILE_SIZE);

	image_file_ifs.read(reinterpret_cast<char*>(Image_Vec.data()), IMAGE_FILE_SIZE);
	
	constexpr uint8_t
		JDV_SIG[]	{ 0xB4, 0x6A, 0x3E, 0xEA, 0x5E, 0x9D, 0xF9 },
		PROFILE_SIG[] 	{ 0x6D, 0x6E, 0x74, 0x72, 0x52, 0x47, 0x42 },
		INDEX_DIFF = 8;
				
	const uint32_t 
		JDV_SIG_INDEX 	= searchFunc(Image_Vec, 0, 0, JDV_SIG),
		PROFILE_SIG_INDEX = searchFunc(Image_Vec, 0, 0, PROFILE_SIG);
		
	if (JDV_SIG_INDEX == Image_Vec.size()) {
		std::cerr << "\nImage File Error: Signature check failure. This is not a valid jdvrif file-embedded image.\n\n";
		return 1;
	}
	
	// Remove JPG header and the APP2 ICC Profile/segment header,
	// also, any other segments that could be added by hosting sites (e.g. Mastodon), such as EXIF. 
	// Vector now contains color profile data, encrypted/compressed data file and cover image data.
	Image_Vec.erase(Image_Vec.begin(), Image_Vec.begin() + (PROFILE_SIG_INDEX - INDEX_DIFF));

	std::vector<uint8_t>Decrypted_File_Vec;
	Decrypted_File_Vec.reserve(IMAGE_FILE_SIZE);

	if (IMAGE_FILE_SIZE > LARGE_FILE_SIZE) {
		std::cout << "\nPlease wait. Larger files will take longer to complete this process.\n";
	}

	const std::string DECRYPTED_FILENAME = decryptFile(Image_Vec, Decrypted_File_Vec);	
	
	const uint32_t INFLATED_FILE_SIZE = inflateFile(Decrypted_File_Vec);
	
	if (Decrypted_File_Vec.empty()) {
		std::cerr << "\nFile Error: Invalid recovery PIN or file is corrupt.\n\n";
		return 1;
	}
	
	std::reverse(Decrypted_File_Vec.begin(), Decrypted_File_Vec.end());

	std::ofstream file_ofs(DECRYPTED_FILENAME, std::ios::binary);

	if (!file_ofs) {
		std::cerr << "\nWrite Error: Unable to write to file.\n\n";
		return 1;
	}

	file_ofs.write(reinterpret_cast<const char*>(Decrypted_File_Vec.data()), INFLATED_FILE_SIZE);

	std::vector<uint8_t>().swap(Decrypted_File_Vec);

	std::cout << "\nExtracted hidden file: " << DECRYPTED_FILENAME << " (" << INFLATED_FILE_SIZE << " bytes).\n\nComplete! Please check your file.\n\n";
	return 0;
}
