#include <string>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_ZZ_p.h>
using namespace std;
using namespace NTL;


struct ECPoint {
    ZZ_p x, y;
    bool isInfinity;
    ECPoint() : isInfinity(true) {}
    ECPoint(ZZ_p _x, ZZ_p _y) : x(_x), y(_y), isInfinity(false) {}
};


class appliedCryptography {
public:
    // Shift Cipher
    string shiftEncrypt(string text, int key);
    string shiftDecrypt(string text, int key);


    // Vigenere Cipher
    string vigenereEncrypt(string text, string key);
    string vigenereDecrypt(string text, string key);


    // Hill Cipher 
    string hillEncrypt(string text, mat_ZZ_p key);
    string hillDecrypt(const string& ciphertext, const mat_ZZ_p& key);

    
    //OTP
    string generateRandomKey(int length);
    string otpEncrypt(string plaintext, string key);
    string otpDecrypt(string ciphertext, string key);


  
    //Diffie Helman key exchange protocol
    ZZ_p diffiePublicKeyNTL(ZZ_p privateKey, ZZ_p g);
    ZZ_p diffieSharedKeyNTL(ZZ_p receivedKey, ZZ_p privateKey);

    
    // ElGamal Encryption / Decryption
    ZZ_p generateRandomY();
    void elGamalEncrypt(const ZZ_p& g, const ZZ_p& h, const ZZ_p& m, ZZ_p& c1, ZZ_p& c2);
    ZZ_p elGamalDecrypt(const ZZ_p& x, const ZZ_p& c1, const ZZ_p& c2);
   

    // ElGamal Digital Signature
    void elGamalSign(const ZZ& p, const ZZ& g, const ZZ& x, const ZZ& m, ZZ& gamma, ZZ& delta);
    bool elGamalVerify(const ZZ& p, const ZZ& g, const ZZ& h, const ZZ& m, const ZZ& gamma, const ZZ& delta);

    // point addition
    ECPoint pointAdd(const ECPoint& P, const ECPoint& Q, const ZZ_p& a);
    
    //point doubling
    ECPoint pointDouble(const ECPoint& P, const ZZ_p& a);

    //scalar multiplication
    ECPoint scalarMultiply(const ECPoint& P, const ZZ& k, const ZZ_p& a);
};
