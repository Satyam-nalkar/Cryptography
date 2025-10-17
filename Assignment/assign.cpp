#include "assign.hpp"
#include <cstdlib>
#include <ctime>
#include <bitset>
#include <cctype>
#include <stdexcept>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>

long mod26(long x) {
    return (x % 26 + 26) % 26;
}


// Shift Cipher 
string appliedCryptography::shiftEncrypt(string text, int key) {
    string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char((c - base + key) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

string appliedCryptography::shiftDecrypt(string text, int key) {
    string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char((c - base - key + 26) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

// Vigenere Cipher 
string appliedCryptography::vigenereEncrypt(string text, string key) {
    string result = "";
    int j = 0;
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int k = tolower(key[j % key.size()]) - 'a';
            result += char((c - base + k) % 26 + base);
            j++;
        } else {
            result += c;
        }
    }
    return result;
}

string appliedCryptography::vigenereDecrypt(string text, string key) {
    string result = "";
    int j = 0;
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int k = tolower(key[j % key.size()]) - 'a';
            result += char((c - base - k + 26) % 26 + base);
            j++;
        } else {
            result += c;
        }
    }
    return result;
}

// Hill Cipher 
string appliedCryptography::hillEncrypt(string text, mat_ZZ_p key) {
    long n = key.NumRows();
    string result = "";

    ZZ_p::init(ZZ(31)); // prime modulus

    // Convert text to uppercase
    for(auto &c : text) c = toupper(c);

    // Padding
    while(text.size() % n != 0) text += 'X';

    for(size_t i = 0; i < text.size(); i += n) {
        vec_ZZ_p P;
        P.SetLength(n);
        for(long j = 0; j < n; j++) {
            P[j] = ZZ_p(text[i+j] - 'A');
        }

        vec_ZZ_p C = key * P; // automatically mod 31
        for(long j = 0; j < n; j++) {
            result += char(conv<long>(rep(C[j])) + 'A');
        }
    }

    return result;
}

// Hill Decrypt
string appliedCryptography::hillDecrypt(const string& ciphertext, const mat_ZZ_p& key) {
    long n = key.NumRows();
    string result = "";

    ZZ_p::init(ZZ(31)); // same prime modulus

    // Determinant and inverse
    ZZ_p det;
    determinant(det, key);
    ZZ_p detInv = inv(det); // inverse modulo 31

    // Compute adjugate
    mat_ZZ_p adj;
    adj.SetDims(n,n);
    for(long i = 0; i < n; i++) {
        for(long j = 0; j < n; j++) {
            mat_ZZ_p minor;
            minor.SetDims(n-1,n-1);
            long r = 0;
            for(long ii = 0; ii < n; ii++) {
                if(ii == i) continue;
                long c = 0;
                for(long jj = 0; jj < n; jj++) {
                    if(jj == j) continue;
                    minor[r][c] = key[ii][jj];
                    c++;
                }
                r++;
            }
            ZZ_p minorDet;
            determinant(minorDet, minor);
            if((i+j)%2 != 0) minorDet = -minorDet;
            adj[j][i] = minorDet; // transpose for adjugate
        }
    }

    mat_ZZ_p invKey = detInv * adj;

    // Decrypt
    for(size_t k = 0; k < ciphertext.size(); k += n) {
        vec_ZZ_p C;
        C.SetLength(n);
        for(long j = 0; j < n; j++) {
            C[j] = ZZ_p(ciphertext[k+j] - 'A');
        }
        vec_ZZ_p P = invKey * C;
        for(long j = 0; j < n; j++) {
            result += char(conv<long>(rep(P[j])) + 'A');
        }
    }

    return result;
}



// OTP

string appliedCryptography::generateRandomKey(int length) {
    srand(time(0));
    string key = "";
    for (int i = 0; i < length; i++) {
        key += char(rand() % 256); 
    }
    return key;
}

// Encryption (plaintext XOR key)
string appliedCryptography::otpEncrypt(string plaintext, string key) {
    if (key.size() < plaintext.size()) {
        throw runtime_error("Key must be at least as long as plaintext");
    }

    string ciphertext = "";
    for (size_t i = 0; i < plaintext.size(); i++) {
        char c = plaintext[i] ^ key[i];
        ciphertext += c;
    }
    return ciphertext;
}

// Decryption (ciphertext XOR key)
string appliedCryptography::otpDecrypt(string ciphertext, string key) {
    if (key.size() < ciphertext.size()) {
        throw runtime_error("Key must be at least as long as ciphertext");
    }

    string decrypted = "";
    for (size_t i = 0; i < ciphertext.size(); i++) {
        char c = ciphertext[i] ^ key[i];
        decrypted += c;
    }
    return decrypted;
}



// Diffie Helman Key Exchange
ZZ_p appliedCryptography::diffiePublicKeyNTL(ZZ_p privateKey, ZZ_p g) {
    ZZ_p result = power(g, conv<long>(rep(privateKey))); 
    return result;
}

ZZ_p appliedCryptography::diffieSharedKeyNTL(ZZ_p receivedKey, ZZ_p privateKey) {
    ZZ_p result = power(receivedKey, conv<long>(rep(privateKey)));
    return result;
}



// random y generate (1 < y < p-2)
ZZ_p appliedCryptography::generateRandomY() {
    long y = RandomBnd(conv<long>(ZZ_p::modulus()-2)) + 1;
    return ZZ_p(y);
}

// Encrypt
void appliedCryptography::elGamalEncrypt(const ZZ_p& g, const ZZ_p& h, const ZZ_p& m, ZZ_p& c1, ZZ_p& c2) {
    ZZ_p y = generateRandomY();      // random y
    c1 = power(g, rep(y));           // c1 = g^y mod p
    ZZ_p s = power(h, rep(y));       // s = h^y mod p
    c2 = m * s;                      // c2 = m * s mod p
}

// Decrypt
ZZ_p appliedCryptography::elGamalDecrypt(const ZZ_p& x, const ZZ_p& c1, const ZZ_p& c2) {
    ZZ_p s = power(c1, rep(x));      // s = c1^x mod p
    ZZ_p s_inv = inv(s);              // s^-1 mod p
    ZZ_p m = c2 * s_inv;              // m = c2 * s^-1 mod p
    return m;
}


 // ElGamal Digital Signature
void appliedCryptography::elGamalSign(const ZZ& p, const ZZ& g, const ZZ& x, const ZZ& m, ZZ& gamma, ZZ& delta) {
    ZZ p1 = p-1;
    ZZ y;
    do {
        y = conv<ZZ>(rand() % conv<long>(p1) + 1);
    } while(GCD(y,p1)!=1);

    PowerMod(gamma, g, y, p);
    ZZ y_inv = InvMod(y, p1);
    delta = ((m - x*gamma)*y_inv) % p1;
    if(delta<0) delta += p1;
    }

bool appliedCryptography::elGamalVerify(const ZZ& p, const ZZ& g, const ZZ& h, const ZZ& m, const ZZ& gamma, const ZZ& delta) {
    ZZ left, right;
    left = (PowerMod(h, gamma, p)*PowerMod(gamma, delta, p)) % p;
    PowerMod(right, g, m, p);
    return (left==right);
    }



    // point addition
    ECPoint appliedCryptography::pointAdd(const ECPoint& P, const ECPoint& Q, const ZZ_p& a) {
    
    if (P.isInfinity) 
        return Q;
    if (Q.isInfinity)  
        return P;
    if (P.x == Q.x && P.y != Q.y) 
        return ECPoint(); // Point at infinity

    // λ = (y2 - y1) * (x2 - x1)^(-1)
    ZZ_p lambda = (Q.y - P.y) * inv(Q.x - P.x);

    // x3 = λ^2 - x1 - x2
    ZZ_p x3 = lambda * lambda - P.x - Q.x;

    // y3 = λ(x1 - x3) - y1
    ZZ_p y3 = lambda * (P.x - x3) - P.y;

    return ECPoint(x3, y3);

    }


    //point doubling
    ECPoint appliedCryptography::pointDouble(const ECPoint& P, const ZZ_p& a) {
    if (P.isInfinity)
        return P;

    // y = 0 -> vertical tangent -> result infinity
    if (P.y == 0) return ECPoint();

    ZZ_p lambda = ( (3 * P.x * P.x) + a ) * inv(2 * P.y);

    // x3 = λ^2 - 2x1
    ZZ_p x3 = lambda * lambda - 2 * P.x;

    // y3 = λ(x1 - x3) - y1
    ZZ_p y3 = lambda * (P.x - x3) - P.y;

    return ECPoint(x3, y3);
}
