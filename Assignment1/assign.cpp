#include "assign.hpp"
#include <cctype>
#include <stdexcept>


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
string appliedCryptography::hillEncrypt(string text, mat_ZZ key) {
    string result = "";
    long n = key.NumRows();

    // padding
    while (text.size() % n != 0) text += 'X';

    for (size_t i = 0; i < text.size(); i += n) {
        vec_ZZ P;
        P.SetLength(n);
        for (long j = 0; j < n; j++) {
            P[j] = (toupper(text[i+j]) - 'A');
        }

        vec_ZZ C = key * P;
        for (long j = 0; j < n; j++) {
            result += char(mod26(to_long(C[j])) + 'A');
        }
    }
    return result;
}

string appliedCryptography::hillDecrypt(const string& ciphertext, const mat_ZZ& key) {
    long n = key.NumRows();
    if (key.NumCols() != n) throw std::runtime_error("Key matrix must be square");

    // 1. Determinant
    ZZ det;
    determinant(det, key);
    det %= ZZ(26);  
    if (det < 0) det += 26;

    // 2. Inverse of determinant mod 26  multiplicative inverse
    ZZ detInv;
    if (InvModStatus(detInv, det, ZZ(26)) != 0) {
        throw std::runtime_error("Key matrix not invertible modulo 26");
    }

    // 3. Adjugate matrix 
    mat_ZZ adj;
    adj.SetDims(n, n);
    for (long i = 0; i < n; i++) {
        for (long j = 0; j < n; j++) {
        
            mat_ZZ minor;
            minor.SetDims(n - 1, n - 1);
            long r = 0;
            for (long ii = 0; ii < n; ii++) {
                if (ii == i) continue;
                long c = 0;
                for (long jj = 0; jj < n; jj++) {
                    if (jj == j) continue;
                    minor[r][c] = key[ii][jj];
                    c++;
                }
                r++;
            }
            // Cofactor
            ZZ minorDet;
            determinant(minorDet, minor);
            if (((i + j) % 2) != 0) minorDet = -minorDet;
            adj[j][i] = minorDet; // transpose for adjugate
        }
    }

    // 4. Inverse matrix = detInv * adj mod 26
    mat_ZZ invKey;
    invKey.SetDims(n, n);
    for (long i = 0; i < n; i++) {
        for (long j = 0; j < n; j++) {
            ZZ val = adj[i][j] * detInv;
            val %= ZZ(26);
            if (val < 0) val += 26;
            invKey[i][j] = val;
        }
    }

    // 5. Decrypt ciphertext in blocks of size n
    string result = "";
    for (size_t k = 0; k < ciphertext.size(); k += n) {
        vec_ZZ C;
        C.SetLength(n);
        for (long j = 0; j < n; j++) {
            C[j] = (toupper(ciphertext[k+j]) - 'A');
        }
        vec_ZZ P = invKey * C;
        for (long j = 0; j < n; j++) {
            long val = to_long(P[j] % 26);
            if (val < 0) val += 26;
            result += char(val + 'A');
        }
    }
    return result;
}
