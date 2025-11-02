#include <iostream>
#include <bitset>
#include "assign.hpp"
#include <NTL/mat_ZZ_p.h>
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
    ZZ_p::init(ZZ(31)); // prime modulus

    mat_ZZ_p key;
    key.SetDims(3,3);
    key[0][0]=6; key[0][1]=24; key[0][2]=1;
    key[1][0]=13; key[1][1]=16; key[1][2]=10;
    key[2][0]=20; key[2][1]=17; key[2][2]=15;

    string hillPlain = "HELLO";
    string hillEnc = crypto.hillEncrypt(hillPlain, key);
    string hillDec = crypto.hillDecrypt(hillEnc, key);

    cout << "Hill Cipher\n";
    cout << "Plaintext : " << hillPlain << "\n";
    cout << "Encrypted : " << hillEnc << "\n";
    cout << "Decrypted : " << hillDec << "\n";
    cout << endl;

    

    // OTP 

    string plaintext = "A";
    cout << "Plaintext: " << plaintext << endl;

    // Binary of plaintext
    bitset<8> plainBin(plaintext[0]);
    cout << "Plaintext Binary : " << plainBin << endl;

    // Generate OTP key
    string otpKey = crypto.generateRandomKey(plaintext.size());
    bitset<8> keyBin(otpKey[0]);
    cout << "Key Binary       : " << keyBin << endl;

    // Encrypt
    string cipher = crypto.otpEncrypt(plaintext, otpKey);
    bitset<8> cipherBin(cipher[0]);
    cout << "Cipher Binary    : " << cipherBin << endl;

    // Decrypt
    string decrypted = crypto.otpDecrypt(cipher, otpKey);
    bitset<8> decryptedBin(decrypted[0]);
    cout << "Decrypted Binary : " << decryptedBin << endl;
    cout << "Decrypted Text   : " << decrypted << endl;

    cout << endl;



    // Diffie-Hellman Key exchange protocol
    cout << "Diffie–Hellman :" << endl;

    ZZ p = conv<ZZ>(23);
    ZZ_p::init(p); // set global modulus

    ZZ_p g = conv<ZZ_p>(5);
    ZZ_p a_diff = conv<ZZ_p>(6);   // Alice private key
    ZZ_p b_diff = conv<ZZ_p>(15);  // Bob private key

    // Public keys
    ZZ_p A = crypto.diffiePublicKeyNTL(a_diff, g);  // A = g^a_diff mod p
    ZZ_p B = crypto.diffiePublicKeyNTL(b_diff, g);  // B = g^b_diff mod p

    // Shared keys
    ZZ_p s1 = crypto.diffieSharedKeyNTL(B, a_diff); // s1 = B^a_diff mod p
    ZZ_p s2 = crypto.diffieSharedKeyNTL(A, b_diff); // s2 = A^b_diff mod p

    cout << "Alice Public Key: " << rep(A) << endl;
    cout << "Bob Public Key  : " << rep(B) << endl;
    cout << "Alice Shared Key: " << rep(s1) << endl;
    cout << "Bob Shared Key  : " << rep(s2) << endl;
    cout << endl;
    

    // ElGamal Encryption / Decryption
    cout << "ElGamal Encryption / Decryption :" << endl;

    ZZ p2 = conv<ZZ>(467);
    ZZ_p::init(p2);  // set modulus

    ZZ_p g2 = conv<ZZ_p>(2);
    ZZ_p x  = conv<ZZ_p>(127);   // private key
    ZZ_p h  = power(g2, rep(x)); // public key

    ZZ_p m = conv<ZZ_p>(123);    // plaintext
    ZZ_p c1, c2;

    // Encrypt
    crypto.elGamalEncrypt(g2, h, m, c1, c2);
    cout << "Ciphertext (c1, c2): (" << rep(c1) << ", " << rep(c2) << ")\n";

    // Decrypt
    ZZ_p decryptedELGamal = crypto.elGamalDecrypt(x, c1, c2);
    cout << "Decrypted message: " << rep(decryptedELGamal) << "\n";
    cout << endl;   
 
    // ElGamal Digital Signature
    cout<<"ElGamal Digital Signature\n";
    ZZ p_sig = conv<ZZ>(467);
    ZZ g_sig = conv<ZZ>(2);
    ZZ x_sig = conv<ZZ>(127);
    ZZ h_sig;

    //h = g^x % p 
    PowerMod(h_sig, g_sig, x_sig, p_sig);

    ZZ m_sig = conv<ZZ>(100);
    ZZ gamma, delta;
    crypto.elGamalSign(p_sig, g_sig, x_sig, m_sig, gamma, delta);
    
    cout<< "Signature: "<< gamma << "," << delta  <<endl;

    bool valid = crypto.elGamalVerify(p_sig, g_sig, h_sig, m_sig, gamma, delta);
   
    cout<<"Signature verification: "<<(valid ? "Valid":"Invalid")<<endl;
    cout << endl;


    
   /* // Eleptic curve
    //point addition
    ZZ_p::init(ZZ(11)); // Modulus p = 11
    ZZ_p a = conv<ZZ_p>(1); // Curve coefficient 'a'
    ZZ_p b = conv<ZZ_p>(6); // Curve coefficient 'b'

    ECPoint P(conv<ZZ_p>(5), conv<ZZ_p>(2));
    ECPoint Q(conv<ZZ_p>(2), conv<ZZ_p>(7));

    ECPoint R = crypto.pointAdd(P, Q, a);

    cout << "P + Q = (" << rep(R.x) << ", " << rep(R.y) << ")" << endl;
    cout << endl;
   


    //point doubling
    ZZ_p::init(ZZ(11));
    ZZ_p pd_a = conv<ZZ_p>(1);
    ZZ_p pd_b = conv<ZZ_p>(6);

    ECPoint pd_P(conv<ZZ_p>(2), conv<ZZ_p>(7));

    ECPoint pd_R = crypto.pointDouble(pd_P, pd_a);

    cout << "2P = (" << rep(pd_R.x) << ", " << rep(pd_R.y) << ")" << endl;
*/
 


    ZZ_p::init(ZZ(11)); // Modulus p = 11
    ZZ_p a = conv<ZZ_p>(1); // Curve coefficient 'a'
    ZZ_p b = conv<ZZ_p>(6); // Curve coefficient 'b'

    ECPoint P(conv<ZZ_p>(2), conv<ZZ_p>(7));
    ECPoint Q(conv<ZZ_p>(5), conv<ZZ_p>(2));

    // Point Addition
    ECPoint R1 = crypto.pointAdd(P, Q, a);
    cout << "P + Q = (" << rep(R1.x) << ", " << rep(R1.y) << ")" << endl;

    // Point Doubling
    ECPoint R2 = crypto.pointDouble(P, a);
    cout << "2P = (" << rep(R2.x) << ", " << rep(R2.y) << ")" << endl;

    // Scalar Multiplication (example: 3 * P)
    ZZ k = conv<ZZ>(5);
    ECPoint R3 = crypto.scalarMultiply(P, k, a);    
    cout << "7P = (" << rep(R3.x) << ", " << rep(R3.y) << ")" << endl;


   return 0;
}