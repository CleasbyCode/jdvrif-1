int jdvOut(const std::string& IMAGE_FILENAME) {
	const uintmax_t IMAGE_FILE_SIZE = std::filesystem::file_size(IMAGE_FILENAME);
	
	std::ifstream image_file_ifs(IMAGE_FILENAME, std::ios::binary);

	if (!image_file_ifs) {
		std::cerr << "\nOpen File Error: Unable to read image file.\n\n";
		return 1;
    	} 

	std::vector<uint8_t> image_vec;
	image_vec.resize(IMAGE_FILE_SIZE);

	image_file_ifs.read(reinterpret_cast<char*>(image_vec.data()), IMAGE_FILE_SIZE);
	image_file_ifs.close();
	
	constexpr std::array<uint8_t, 7>
		JDVRIF_SIG		{ 0xB4, 0x6A, 0x3E, 0xEA, 0x5E, 0x9D, 0xF9 },
		COLOR_PROFILE_SIG	{ 0x6D, 0x6E, 0x74, 0x72, 0x52, 0x47, 0x42 };

	const uint8_t INDEX_DIFF = 8;
				
	const uint32_t 
		JDVRIF_SIG_INDEX	= searchFunc(image_vec, 0, 0, JDVRIF_SIG),
		COLOR_PROFILE_SIG_INDEX = searchFunc(image_vec, 0, 0, COLOR_PROFILE_SIG);

	if (JDVRIF_SIG_INDEX == image_vec.size()) {
		std::cerr << "\nImage File Error: Signature check failure. This is not a valid jdvrif \"file-embedded\" image.\n\n";
		return 1;
	}
	
	uint8_t extract_success_byte_val = image_vec[JDVRIF_SIG_INDEX + INDEX_DIFF - 1];

	bool hasBlueskyOption = true;
		
	if (COLOR_PROFILE_SIG_INDEX != image_vec.size()) {
		image_vec.erase(image_vec.begin(), image_vec.begin() + (COLOR_PROFILE_SIG_INDEX - INDEX_DIFF));
		hasBlueskyOption = false;
	}

	if (hasBlueskyOption) { // EXIF segment (FFE1) is being used. Check for the second (XMP) segment.
		constexpr std::array<uint8_t, 7> XMP_SIG { 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F };
		const uint32_t XMP_SIG_INDEX = searchFunc(image_vec, 0, 0, XMP_SIG);

		if (XMP_SIG_INDEX != image_vec.size()) { // Found XMP segment...
			constexpr std::array<uint8_t, 6> XMP_CREATOR_SIG { 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69 };
			const uint32_t XMP_CREATOR_SIG_INDEX = searchFunc(image_vec, XMP_SIG_INDEX, 0, XMP_CREATOR_SIG);

			uint32_t xmp_creator_data_index = XMP_CREATOR_SIG_INDEX + 7;

			constexpr uint8_t END_OF_BASE64_DATA_ID = 0x3C;

			std::vector<uint8_t> base64_data_vec;
			base64_data_vec.reserve(XMP_SIG_INDEX);		

			// Read in and store the Base64 data found within the xmp_creator tag segment.
			while (image_vec[xmp_creator_data_index] != END_OF_BASE64_DATA_ID) {
				base64_data_vec.emplace_back(image_vec[xmp_creator_data_index++]);
			}
		
			// Convert back to binary...
			convertFromBase64(base64_data_vec);

			const uint32_t END_OF_EXIF_DATA_INDEX = XMP_SIG_INDEX - 0x32;

			// Now append the XMP binary data to the EXIF binary segment data, so that we have the complete data file.
			image_vec.insert(image_vec.begin() + END_OF_EXIF_DATA_INDEX, base64_data_vec.begin(), base64_data_vec.end());
		}
	}

	constexpr uint32_t LARGE_FILE_SIZE = 400 * 1024 * 1024;

	if (IMAGE_FILE_SIZE > LARGE_FILE_SIZE) {
		std::cout << "\nPlease wait. Larger files will take longer to complete this process.\n";
	}

	const std::string DECRYPTED_FILENAME = decryptFile(image_vec, hasBlueskyOption);	
	
	const uint32_t INFLATED_FILE_SIZE = inflateFile(image_vec);

	bool hasInflateFailed = !INFLATED_FILE_SIZE;
				 
	if (hasInflateFailed) {	
		std::fstream file(IMAGE_FILENAME, std::ios::in | std::ios::out | std::ios::binary);
		std::streampos failure_index = JDVRIF_SIG_INDEX + INDEX_DIFF - 1;

		file.seekg(failure_index);

		uint8_t byte;
		file.read(reinterpret_cast<char*>(&byte), sizeof(byte));

		if (byte == 0x90) {
			byte = 0;
		} else {
    			byte++;
		}
		
		if (byte > 2) {
			file.close();
			std::ofstream file(IMAGE_FILENAME, std::ios::out | std::ios::trunc | std::ios::binary);
		} else {
			file.seekp(failure_index);
			file.write(reinterpret_cast<char*>(&byte), sizeof(byte));
		}

		file.close();

		std::cerr << "\nFile Recovery Error: Invalid PIN or file is corrupt.\n\n";
		return 1;
	}

	if (extract_success_byte_val != 0x90) {
		std::fstream file(IMAGE_FILENAME, std::ios::in | std::ios::out | std::ios::binary);
		std::streampos success_index = JDVRIF_SIG_INDEX + INDEX_DIFF - 1;
	
		uint8_t byte = 0x90;

		file.seekp(success_index);
		file.write(reinterpret_cast<char*>(&byte), sizeof(byte));

		file.close();
	}

	std::reverse(image_vec.begin(), image_vec.end());

	std::ofstream file_ofs(DECRYPTED_FILENAME, std::ios::binary);

	if (!file_ofs) {
		std::cerr << "\nWrite Error: Unable to write to file.\n\n";
		return 1;
	}

	file_ofs.write(reinterpret_cast<const char*>(image_vec.data()), INFLATED_FILE_SIZE);

	std::vector<uint8_t>().swap(image_vec);

	std::cout << "\nExtracted hidden file: " << DECRYPTED_FILENAME << " (" << INFLATED_FILE_SIZE << " bytes).\n\nComplete! Please check your file.\n\n";
	return 0;
}