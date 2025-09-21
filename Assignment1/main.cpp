#include <iostream>
#include "assign.hpp"
using namespace std;
using namespace NTL;

int main() {
    appliedCryptography crypto;

    // Shift Cipher Example
    string shiftPlain = "HELLO";
    int shiftKey = 3;
    string shiftEnc = crypto.shiftEncrypt(shiftPlain, shiftKey);
    string shiftDec = crypto.shiftDecrypt(shiftEnc, shiftKey);

    cout << "Shift Cipher" << endl;
    cout << "Plaintext: " << shiftPlain << endl;
    cout << "Encrypted : " << shiftEnc << endl;
    cout << "Decrypted : " << shiftDec << endl << endl;

    // Vigenere Cipher Example
    string vigPlain = "HELLO";
    string vigKey = "KEY";
    string vigEnc = crypto.vigenereEncrypt(vigPlain, vigKey);
    string vigDec = crypto.vigenereDecrypt(vigEnc, vigKey);

    cout << "Vigenere Cipher" << endl;
    cout << "Plaintext: " << vigPlain << endl;
    cout << "Encrypted : " << vigEnc << endl;
    cout << "Decrypted : " << vigDec << endl << endl;

    // Hill Cipher  3x3 key matrix
    mat_ZZ key;
    key.SetDims(3,3);
    key[0][0]=6;  key[0][1]=24; key[0][2]=1;
    key[1][0]=13; key[1][1]=16; key[1][2]=10;
    key[2][0]=20; key[2][1]=17; key[2][2]=15;

    string hillPlain = "satyam";
    string hillEnc = crypto.hillEncrypt(hillPlain, key);
    string hillDec = crypto.hillDecrypt(hillEnc, key);

    cout << "Hill Cipher:" << endl;
    cout << "Plaintext: " << hillPlain << endl;
    cout << "Encrypted : " << hillEnc << endl;
    cout << "Decrypted : " << hillDec << endl;

    return 0;
}
