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



    // Elliptic curve 
void appliedCryptography::initCurve(const ZZ& _pECC, const ZZ_p& _aECC, const ZZ_p& _bECC) {
    pECC = _pECC;
    ZZ_p::init(pECC);    // set modulus
    aECC = _aECC;
    bECC = _bECC;
}

// Point negation: returns -P
ECPoint appliedCryptography::pointNeg(const ECPoint& P) {
    if (P.isInfinity) return P;
    return ECPoint(P.x, -P.y);    // -y (NTL handles mod p)
}

// Point addition (uses class aECC implicitly in doubling if needed)
ECPoint appliedCryptography::pointAdd(const ECPoint& P, const ECPoint& Q) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    // P + (-P) => infinity
    if (P.x == Q.x && P.y != Q.y) return ECPoint();

    // If P == Q, call doubling
    if (P.x == Q.x && P.y == Q.y) return pointDouble(P);

    // slope lambda = (y2 - y1) * (x2 - x1)^(-1)
    ZZ_p num = Q.y - P.y;
    ZZ_p den = Q.x - P.x;
    ZZ_p lambda = num * inv(den);  // inv from NTL

    ZZ_p x3 = lambda * lambda - P.x - Q.x;
    ZZ_p y3 = lambda * (P.x - x3) - P.y;

    return ECPoint(x3, y3);
}

// Point doubling
ECPoint appliedCryptography::pointDouble(const ECPoint& P) {
    if (P.isInfinity) return P;

    // If y == 0 => slope infinite, result = point at infinity
    if (rep(P.y) == 0) return ECPoint();

    ZZ_p num = ZZ_p(3) * P.x * P.x + aECC;   // 3*x^2 + a
    ZZ_p den = ZZ_p(2) * P.y;                // 2*y
    ZZ_p lambda = num * inv(den);

    ZZ_p x3 = lambda * lambda - ZZ_p(2) * P.x;
    ZZ_p y3 = lambda * (P.x - x3) - P.y;

    return ECPoint(x3, y3);
}

// Scalar multiplication (double-and-add, MSB-first)
ECPoint appliedCryptography::scalarMultiply(const ECPoint& P, const ZZ& k) {
    if (P.isInfinity) return P;
    if (k == 0) return ECPoint();

    ECPoint R;         // starts as point at infinity
    // Q not needed to change; we add P when bit==1
    long n = NumBits(k);
    for (long i = n - 1; i >= 0; --i) {
        // double R every iteration
        R = pointDouble(R);
        if (bit(k, i)) {
            R = pointAdd(R, P);
        }
    }
    return R;
}

// Key generation: choose priv in [1, q-1], compute Q = priv * G
void appliedCryptography::keyGen(const ECPoint& G, const ZZ& q, ZZ& priv, ECPoint& Q) {
    do {
        priv = RandomBnd(q);   // 0..q-1
    } while (priv == 0);
    Q = scalarMultiply(G, priv);
}

// EC-ElGamal: C1 = yG, C2 = M + yQ
pair<ECPoint, ECPoint> appliedCryptography::elgamalEncryptEC(const ECPoint& M, const ECPoint& G, const ECPoint& Q, const ZZ& q) {
    ZZ y;
    do {
        y = RandomBnd(q);
    } while (y == 0);

    ECPoint C1 = scalarMultiply(G, y);
    ECPoint yQ = scalarMultiply(Q, y);
    ECPoint C2 = pointAdd(M, yQ);
    return make_pair(C1, C2);
}

// EC-ElGamal decrypt: M = C2 - priv*C1
ECPoint appliedCryptography::elgamalDecryptEC(const pair<ECPoint, ECPoint>& C, const ZZ& priv) {
    ECPoint mC1 = scalarMultiply(C.first, priv);  // priv * C1
    ECPoint neg = pointNeg(mC1);
    ECPoint M = pointAdd(C.second, neg);
    return M;
}




// ECDSA=(r,s) using y random in [1,q-1]
pair<ZZ, ZZ> appliedCryptography::signECDSA(const ZZ& msg, const ZZ& priv, const ECPoint& G, const ZZ& q) {
    ZZ r, s, y;
    do {
        do {
            y = RandomBnd(q);
        } while (y == 0);

        ECPoint yP = scalarMultiply(G, y);
        if (yP.isInfinity) continue;

        r = rep(yP.x) % q;
        if (r == 0) continue;

        ZZ yinv = InvMod(y, q);             // modular inverse
        s = (yinv * (msg + priv * r)) % q;
    } while (s == 0);

    return make_pair(r, s);
}

// Verify signature
bool appliedCryptography::verifyECDSA(const ZZ& msg, const pair<ZZ, ZZ>& sig, const ECPoint& G, const ECPoint& Q, const ZZ& q) {
    ZZ r = sig.first, s = sig.second;
    if (r <= 0 || r >= q || s <= 0 || s >= q) return false;

    ZZ w = InvMod(s, q);
    ZZ i = (msg * w) % q;
    ZZ j = (r * w) % q;

    ECPoint iP = scalarMultiply(G, i);
    ECPoint jQ = scalarMultiply(Q, j);
    ECPoint R = pointAdd(iP, jQ);

    if (R.isInfinity) return false;
    ZZ x0 = rep(R.x) % q;
    return (x0 == r);
}

 