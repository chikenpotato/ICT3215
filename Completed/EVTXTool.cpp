#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <cstring>
#include <string>
#include <algorithm>
#include <sstream>

// File Header Structure
struct EVTXFileHeader {
    char signature[8];          // Offset 0: "ElfFile\x00" signature
    uint64_t firstChunkNumber;  // Offset 8: First chunk number
    uint64_t lastChunkNumber;   // Offset 16: Last chunk number
    uint64_t nextRecordId;      // Offset 24: Next record identifier
    uint32_t headerSize;        // Offset 32: Header size (128)
    uint16_t minorFormatVersion;// Offset 36: Minor format version
    uint16_t majorFormatVersion;// Offset 38: Major format version
    uint16_t headerBlockSize;   // Offset 40: Header block size (4096)
    uint16_t numberOfChunks;    // Offset 42: Number of chunks
    uint8_t unknown1[76];       // Offset 44: Unknown (Empty values)
    uint32_t fileFlags;         // Offset 120: File flags
    uint32_t checksum;          // Offset 124: Checksum (CRC32 of first 120 bytes)
    uint8_t unknown2[3968];     // Offset 128: Unknown (Empty values)
};

// Chunk Header Structure
struct EVTXChunkHeader {
    char signature[8];             // Offset 0: "ElfChnk\x00" signature
    uint64_t firstEventRecordNum;  // Offset 8: First event record number
    uint64_t lastEventRecordNum;   // Offset 16: Last event record number
    uint64_t firstEventRecordId;   // Offset 24: First event record identifier
    uint64_t lastEventRecordId;    // Offset 32: Last event record identifier
    uint32_t headerSize;           // Offset 40: Header size (128)
    uint32_t lastEventRecordOffset;// Offset 44: Offset to the data of the last event record
    uint32_t freeSpaceOffset;      // Offset 48: Offset to free space in the chunk
    uint32_t eventRecordsChecksum; // Offset 52: CRC32 of the event records data
    uint8_t unknown1[64];          // Offset 56: Unknown (Empty values)
    uint32_t unknownFlags;         // Offset 120: Unknown (flags?)
    uint32_t headerChecksum;       // Offset 124: CRC32 of the header
    uint32_t commonStringOffsets[64]; // Offset 128: Array of common string offsets (relative to chunk start)
    uint32_t templatePointers[32]; // Offset 384: Array of 32 template pointers
};

// CRC32 Calculation Function
uint32_t calculateCRC32(const uint8_t* data, size_t length) {
    const uint32_t polynomial = 0xEDB88320;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < length; ++i) {
        uint32_t byte = data[i];
        crc ^= byte;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            }
            else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// Helper Function: Calculate maximum modifiable space
size_t calculateMaxModifiableSpace(const std::string& inputPath, const std::vector<uint16_t>& skipChunks) {
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open the input file: " << inputPath << std::endl;
        return 0;
    }

    EVTXFileHeader fileHeader;
    inputFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    size_t modifiableSpace = sizeof(fileHeader.unknown2); // File header's unknown2 field

    // Per chunk modifiable fields
    size_t chunkModifiableSpace = sizeof(EVTXChunkHeader::unknown1) +
        sizeof(EVTXChunkHeader::commonStringOffsets) +
        sizeof(EVTXChunkHeader::templatePointers);

    for (uint16_t chunkIndex = 0; chunkIndex < fileHeader.numberOfChunks; ++chunkIndex) {
        if (std::find(skipChunks.begin(), skipChunks.end(), chunkIndex) == skipChunks.end()) {
            modifiableSpace += chunkModifiableSpace;
        }
    }

    inputFile.close();
    return modifiableSpace;
}

// Helper Function: Write message to a field
size_t writeMessage(uint8_t* field, size_t fieldSize, const std::vector<uint8_t>& content, size_t contentOffset) {
    size_t bytesToWrite = std::min(fieldSize, content.size() - contentOffset);
    std::memcpy(field, content.data() + contentOffset, bytesToWrite);
    return bytesToWrite;
}

// Function to encode a secret message or file content
static void encodeContent(const std::string& inputPath, const std::string& outputPath, const std::vector<uint8_t>& content, const std::vector<uint16_t>& skipChunks) {
    const uint8_t terminationPattern[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const uint16_t startMarker = 0xFEED;

    // Open the input file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open the input file: " << inputPath << std::endl;
        return;
    }

    // Open the output file
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Error: Could not create the output file: " << outputPath << std::endl;
        inputFile.close();
        return;
    }

    // Read the file header
    EVTXFileHeader fileHeader;
    inputFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Prepare the content with skipped chunks, start marker, and termination pattern
    std::vector<uint8_t> contentToEncode;

    // Add skipped chunks as 2-byte entries
    for (uint16_t chunk : skipChunks) {
        contentToEncode.push_back(static_cast<uint8_t>(chunk & 0xFF));
        contentToEncode.push_back(static_cast<uint8_t>((chunk >> 8) & 0xFF));
    }
    contentToEncode.push_back(0xFF); // End of skipped chunks marker
    contentToEncode.push_back(0xFF);

    // Add the start marker
    contentToEncode.push_back(static_cast<uint8_t>(startMarker & 0xFF));
    contentToEncode.push_back(static_cast<uint8_t>((startMarker >> 8) & 0xFF));

    // Add the actual content
    contentToEncode.insert(contentToEncode.end(), content.begin(), content.end());

    // Add the termination pattern
    contentToEncode.insert(contentToEncode.end(), std::begin(terminationPattern), std::end(terminationPattern));

    size_t contentOffset = 0;

    // Encode into the file header unknown2
    contentOffset += writeMessage(fileHeader.unknown2, sizeof(fileHeader.unknown2), contentToEncode, contentOffset);

    // Write the modified file header to the output file
    outputFile.write(reinterpret_cast<const char*>(&fileHeader), sizeof(fileHeader));

    // Get the total number of chunks from the file header
    uint16_t totalChunks = fileHeader.numberOfChunks;

    for (uint16_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
        uint64_t chunkOffset = 4096 + chunkIndex * 65536;
        inputFile.seekg(chunkOffset, std::ios::beg);

        EVTXChunkHeader chunkHeader;
        inputFile.read(reinterpret_cast<char*>(&chunkHeader), sizeof(chunkHeader));

        // Skip specified chunks
        if (std::find(skipChunks.begin(), skipChunks.end(), chunkIndex) != skipChunks.end()) {
            outputFile.write(reinterpret_cast<const char*>(&chunkHeader), sizeof(chunkHeader));

            // Copy the remaining chunk data
            const size_t chunkDataSize = 65536 - sizeof(chunkHeader); // Chunk size - header size
            std::vector<char> chunkData(chunkDataSize);
            inputFile.read(chunkData.data(), chunkDataSize);
            outputFile.write(chunkData.data(), chunkDataSize);
            continue;
        }

        // Encode into chunk header fields if there is still content left to encode
        if (contentOffset < contentToEncode.size()) {
            contentOffset += writeMessage(chunkHeader.unknown1, sizeof(chunkHeader.unknown1), contentToEncode, contentOffset);
        }
        if (contentOffset < contentToEncode.size()) {
            contentOffset += writeMessage(reinterpret_cast<uint8_t*>(chunkHeader.commonStringOffsets), sizeof(chunkHeader.commonStringOffsets), contentToEncode, contentOffset);
        }
        if (contentOffset < contentToEncode.size()) {
            contentOffset += writeMessage(reinterpret_cast<uint8_t*>(chunkHeader.templatePointers), sizeof(chunkHeader.templatePointers), contentToEncode, contentOffset);
        }

        // Only recalculate the checksum and write the header if changes were made
        if (contentOffset > 0) {
            std::vector<uint8_t> headerData(512);
            std::memcpy(headerData.data(), &chunkHeader, 124); // Bytes from 0 to 123
            std::memcpy(headerData.data() + 124, reinterpret_cast<uint8_t*>(&chunkHeader) + 128, 384); // Bytes from 128 to 511
            chunkHeader.headerChecksum = calculateCRC32(headerData.data(), 512);

            outputFile.seekp(chunkOffset, std::ios::beg);
            outputFile.write(reinterpret_cast<const char*>(&chunkHeader), sizeof(chunkHeader));
        }

        // Copy the remaining chunk data (event records and other fields)
        const size_t chunkDataSize = 65536 - sizeof(chunkHeader); // Chunk size - header size
        std::vector<char> chunkData(chunkDataSize);
        inputFile.read(chunkData.data(), chunkDataSize);
        outputFile.write(chunkData.data(), chunkDataSize);
    }

    // Copy the remaining file content (after the last chunk)
    uint64_t remainingOffset = 4096 + totalChunks * 65536;
    inputFile.seekg(remainingOffset, std::ios::beg);
    outputFile << inputFile.rdbuf();

    inputFile.close();
    outputFile.close();

    std::cout << "The content has been successfully encoded and saved to: " << outputPath << std::endl;
}


void decodeContent(const std::string& inputPath, bool toFile, const std::string& outputFilePath = "") {
    const uint8_t terminationPattern[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const uint16_t startMarker = 0xFEED;

    // Open the input file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open the input file: " << inputPath << std::endl;
        return;
    }

    // Read the file header
    EVTXFileHeader fileHeader;
    inputFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Container for extracted content
    std::vector<uint8_t> extractedContent;

    // Extract skipped chunks from the file header unknown2
    std::vector<uint16_t> skipChunks;
    size_t i = 0;
    while (i < sizeof(fileHeader.unknown2)) {
        uint16_t chunk = fileHeader.unknown2[i] | (fileHeader.unknown2[i + 1] << 8);
        if (chunk == 0xFFFF) {
            i += 2; // Skip the end marker
            break;
        }
        skipChunks.push_back(chunk);
        i += 2;
    }

    // Ensure the start marker is present
    uint16_t marker = fileHeader.unknown2[i] | (fileHeader.unknown2[i + 1] << 8);
    if (marker != startMarker) {
        std::cerr << "Error: Start marker not found in file header." << std::endl;
        return;
    }
    i += 2;

    // Get the total number of chunks from the file header
    uint16_t totalChunks = fileHeader.numberOfChunks;

    // Extract actual content from the remaining file header
    for (size_t j = i; j < sizeof(fileHeader.unknown2); ++j) {
        extractedContent.push_back(fileHeader.unknown2[j]);
        if (extractedContent.size() >= 16 &&
            std::equal(terminationPattern, terminationPattern + 16, extractedContent.end() - 16)) {
            extractedContent.resize(extractedContent.size() - 16); // Remove termination pattern
            goto OUTPUT;
        }
    }

    for (uint16_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
        uint64_t chunkOffset = 4096 + chunkIndex * 65536;
        inputFile.seekg(chunkOffset, std::ios::beg);

        EVTXChunkHeader chunkHeader;
        inputFile.read(reinterpret_cast<char*>(&chunkHeader), sizeof(chunkHeader));

        // Skip chunks specified in skipChunks
        if (std::find(skipChunks.begin(), skipChunks.end(), chunkIndex) != skipChunks.end()) {
            inputFile.seekg(65536 - sizeof(chunkHeader), std::ios::cur); // Skip the rest of the chunk
            continue;
        }

        // Extract from chunk header unknown1
        for (size_t j = 0; j < sizeof(chunkHeader.unknown1); ++j) {
            extractedContent.push_back(chunkHeader.unknown1[j]);
            if (extractedContent.size() >= 16 &&
                std::equal(terminationPattern, terminationPattern + 16, extractedContent.end() - 16)) {
                extractedContent.resize(extractedContent.size() - 16); // Remove termination pattern
                goto OUTPUT;
            }
        }

        // Extract from chunk header commonStringOffsets
        for (size_t j = 0; j < sizeof(chunkHeader.commonStringOffsets); ++j) {
            extractedContent.push_back(reinterpret_cast<uint8_t*>(chunkHeader.commonStringOffsets)[j]);
            if (extractedContent.size() >= 16 &&
                std::equal(terminationPattern, terminationPattern + 16, extractedContent.end() - 16)) {
                extractedContent.resize(extractedContent.size() - 16); // Remove termination pattern
                goto OUTPUT;
            }
        }

        // Extract from chunk header templatePointers
        for (size_t j = 0; j < sizeof(chunkHeader.templatePointers); ++j) {
            extractedContent.push_back(reinterpret_cast<uint8_t*>(chunkHeader.templatePointers)[j]);
            if (extractedContent.size() >= 16 &&
                std::equal(terminationPattern, terminationPattern + 16, extractedContent.end() - 16)) {
                extractedContent.resize(extractedContent.size() - 16); // Remove termination pattern
                goto OUTPUT;
            }
        }
    }

OUTPUT:
    // Output content
    if (toFile && !outputFilePath.empty()) {
        std::ofstream outputFile(outputFilePath, std::ios::binary);
        if (!outputFile) {
            std::cerr << "Error: Could not create the output file: " << outputFilePath << std::endl;
            return;
        }
        outputFile.write(reinterpret_cast<const char*>(extractedContent.data()), extractedContent.size());
        outputFile.close();
        std::cout << "Decoded content has been saved to: " << outputFilePath << std::endl;
    }
    else {
        // Print decoded content to the console
        std::cout << "" << std::string(extractedContent.begin(), extractedContent.end()) << std::endl;
    }

    inputFile.close();
}

size_t calculateFreeSpace(const std::string& inputPath) {
    // Open the input file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open the input file: " << inputPath << std::endl;
        return 0;
    }

    // Read the file header
    EVTXFileHeader fileHeader;
    inputFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Calculate modifiable space in the file header
    size_t modifiableSpace = sizeof(fileHeader.unknown2);

    // Get the number of chunks from the file header
    uint16_t totalChunks = fileHeader.numberOfChunks;

    // Calculate modifiable space in each chunk
    for (uint16_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
        uint64_t chunkOffset = 4096 + chunkIndex * 65536; // Chunk offset
        inputFile.seekg(chunkOffset, std::ios::beg);

        EVTXChunkHeader chunkHeader;
        inputFile.read(reinterpret_cast<char*>(&chunkHeader), sizeof(chunkHeader));

        // Verify the chunk signature
        const char expectedSignature[8] = { 'E', 'l', 'f', 'C', 'h', 'n', 'k', '\x00' };
        if (std::memcmp(chunkHeader.signature, expectedSignature, sizeof(expectedSignature)) != 0) {
            std::cerr << "Error: Invalid chunk signature at chunk " << chunkIndex + 1 << ".\n";
            inputFile.close();
            return 0;
        }

        // Add modifiable fields in the chunk
        modifiableSpace += sizeof(chunkHeader.unknown1);
        modifiableSpace += sizeof(chunkHeader.commonStringOffsets);
        modifiableSpace += sizeof(chunkHeader.templatePointers);
    }

    inputFile.close();
    return modifiableSpace;
}

std::vector<uint16_t> parseSkipChunks(int argc, char* argv[], int& i) {
    std::vector<uint16_t> skipChunks;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--skip-chunks" || arg == "-s") {
            if (i + 1 < argc) {
                std::string chunkSpec = argv[++i];
                std::istringstream ss(chunkSpec);
                uint16_t chunk;
                while (ss >> chunk) {
                    skipChunks.push_back(chunk);
                }
            }
            else {
                std::cerr << "Error: Missing chunk values after --skip-chunks/-s.\n";
                exit(1);
            }
        }
        else if (arg.find_first_not_of("0123456789") == std::string::npos) {
            skipChunks.push_back(static_cast<uint16_t>(std::stoi(arg)));
        }
        else {
            break; // Exit if it's not a number or another -s flag
        }
        i++;
    }
    return skipChunks;
}

void printUsage(const char* programName) {
    std::cout << "Usage:\n"
        << "  " << programName << " --encode|-e --input|-i <input.evtx> --output|-o <output.evtx> [--file|-f <file>] [--message|-m <message>] [--skip-chunks|-s <chunks>]\n"
        << "  " << programName << " --decode|-d --input|-i <input.evtx> [--output|-o <output file>]\n"
        << "  " << programName << " --space|-S --input|-i <input.evtx>\n\n"
        << "Options:\n"
        << "  --help, -h                 Show this help message and exit.\n"
        << "  --encode, -e               Encode a secret message or file into the specified event log.\n"
        << "  --decode, -d               Decode a secret message or file from the specified event log.\n"
        << "  --space, -S                Calculate total modifiable space in the specified event log.\n\n"
        << "Required Arguments:\n"
        << "  --input, -i <input.evtx>   Specify the input event log file to process.\n"
        << "  --output, -o <output.evtx> Specify the output event log file (for encoding) or output file (for decoding). Optional for decoding.\n\n"
        << "Optional Arguments for Encoding:\n"
        << "  --file, -f <file>          Encode the contents of the specified file into the event log.\n"
        << "  --message, -m <message>    Encode the provided secret message into the event log.\n"
        << "                             If neither --file nor --message is specified, the program will prompt for a message interactively.\n"
        << "  --skip-chunks, -s <chunks> Specify chunks to skip during encoding. Provide as a space-separated string or multiple -s options.\n"
        << "                             Example: -s \"10 12 31\" or -s 10 -s 12 -s 31.\n\n"
        << "Examples:\n"
        << "  Calculate free space:\n"
        << "    " << programName << " --space --input input.evtx\n\n"
        << "  Encode a message into an event log:\n"
        << "    " << programName << " --encode --input input.evtx --output encoded.evtx --message \"Secret Message\"\n\n"
        << "  Decode a message from an event log and print to console:\n"
        << "    " << programName << " --decode --input encoded.evtx\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) { // Minimum arguments for any operation
        printUsage(argv[0]);
        return 1;
    }

    std::string mode, inputPath, outputPath, filePath, message;
    std::vector<uint16_t> skipChunks;
    bool isEncode = false, isDecode = false, isSpace = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--encode" || arg == "-e") {
            isEncode = true;
        }
        else if (arg == "--decode" || arg == "-d") {
            isDecode = true;
        }
        else if (arg == "--space" || arg == "-S") {
            isSpace = true;
        }
        else if ((arg == "--input" || arg == "-i") && i + 1 < argc) {
            inputPath = argv[++i];
        }
        else if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            outputPath = argv[++i];
        }
        else if ((arg == "--file" || arg == "-f") && i + 1 < argc) {
            filePath = argv[++i];
        }
        else if ((arg == "--message" || arg == "-m") && i + 1 < argc) {
            message = argv[++i];
        }
        else if (arg == "--skip-chunks" || arg == "-s") {
            skipChunks = parseSkipChunks(argc, argv, i);
        }
        else {
            printUsage(argv[0]);
            return 1;
        }
    }

    // Validate mode
    if ((isEncode + isDecode + isSpace) != 1) {
        std::cerr << "Error: Specify exactly one mode: --encode, --decode, or --space.\n";
        return 1;
    }

    if (isSpace) {
        if (inputPath.empty()) {
            std::cerr << "Error: --input must be specified with --space.\n";
            return 1;
        }

        size_t freeSpace = calculateFreeSpace(inputPath);
        std::cout << "Total modifiable space in the file: " << freeSpace << " bytes\n";
        return 0;
    }

    if (isEncode) {
        if (inputPath.empty() || outputPath.empty()) {
            std::cerr << "Error: Both --input and --output must be specified for encoding.\n";
            return 1;
        }

        size_t maxModifiableSpace = calculateMaxModifiableSpace(inputPath, skipChunks);

        std::vector<uint8_t> content;

        if (!filePath.empty() && !message.empty()) {
            std::cerr << "Error: --file and --message cannot be used together.\n";
            return 1;
        }

        if (!filePath.empty()) {
            // Read the file to encode
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                std::cerr << "Error: Could not open file: " << filePath << std::endl;
                return 1;
            }
            content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
            file.close();

            if (content.size() > maxModifiableSpace) {
                std::cerr << "Error: File content is too large! Maximum allowed size is " << maxModifiableSpace << " bytes.\n";
                return 1;
            }
        }
        else if (!message.empty()) {
            // Use the provided message
            content.assign(message.begin(), message.end());

            if (content.size() > maxModifiableSpace) {
                std::cerr << "Error: Message is too large! Maximum allowed size is " << maxModifiableSpace << " bytes.\n";
                return 1;
            }
        }
        else {
            // Ask the user for the message interactively
            std::cout << "Enter the secret message to encode (max " << maxModifiableSpace << " characters): ";
            std::getline(std::cin, message);
            content.assign(message.begin(), message.end());

            if (content.size() > maxModifiableSpace) {
                std::cerr << "Error: Message is too large! Maximum allowed size is " << maxModifiableSpace << " bytes.\n";
                return 1;
            }
        }

        encodeContent(inputPath, outputPath, content, skipChunks);

    }
    else if (isDecode) {
        if (inputPath.empty()) {
            std::cerr << "Error: --input must be specified for decoding.\n";
            return 1;
        }

        // Output path is optional for decoding
        bool toFile = !outputPath.empty();
        decodeContent(inputPath, toFile, outputPath);

    }
    else {
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}

