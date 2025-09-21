#include <string>
#include <NTL/mat_ZZ.h>
using namespace std;
using namespace NTL;

class appliedCryptography {
public:
    // Shift Cipher
    string shiftEncrypt(string text, int key);
    string shiftDecrypt(string text, int key);

    // Vigenere Cipher
    string vigenereEncrypt(string text, string key);
    string vigenereDecrypt(string text, string key);

    // Hill Cipher 
    string hillEncrypt(string text, mat_ZZ key);
    string hillDecrypt(const string& ciphertext, const mat_ZZ& key);
};
