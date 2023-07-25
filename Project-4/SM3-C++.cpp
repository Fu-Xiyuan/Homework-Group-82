#include <iostream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <random>
#include <chrono>

using namespace std;
using namespace chrono;

const unsigned int T[] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
    0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0xf3b14f50, 0x1e7629ea, 0x3cec53d4,
    0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0xb14f50f3, 0x29ea1e76, 0xd43cec53,
    0xd8a7a879, 0x14f50f3b, 0x9ea1e762, 0x3d43cec5,
    0xa7a879d8, 0xf50f3b14, 0xa1e7629e, 0x43cec53d,
    0x7a879d8a, 0x50f3b14f, 0xe7629ea1, 0xec53d43c
};

unsigned int ROTL(unsigned int x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z) {
    return X ^ Y ^ Z;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z) {
    return (X & Y) | (X & Z) | (Y & Z);
}

unsigned int P_0(unsigned int X) {
    return X ^ ROTL(X, 9) ^ ROTL(X, 17);
}

unsigned int P_1(unsigned int X) {
    return X ^ ROTL(X, 15) ^ ROTL(X, 23);
}

void SM3(const string& message, string& digest) {
    unsigned int A = 0x7380166F;
    unsigned int B = 0x4914B2B9;
    unsigned int C = 0x172442D7;
    unsigned int D = 0xDA8A0600;
    unsigned int E = 0xA96F30BC;
    unsigned int F = 0x163138AA;
    unsigned int G = 0xE38DEE4D;
    unsigned int H = 0xB0FB0E4E;

    string padding_message = message;
    padding_message += char(128);

    while (padding_message.size() % 64 != 56) {
        padding_message += char(0);
    }

    unsigned long long bit_length = message.size() * 8;
    for (int i = 7;i >= 0;i--) {
        padding_message += char((bit_length >> (i * 8)) & 255);
    }

    for (int i = 0;i < padding_message.size();i += 64) {
        unsigned int W[68];
        for (int j = 0;j < 16;j++) {
            W[j] = (padding_message[i + 4 * j + 3] & 255) | ((padding_message[i + 4 * j + 2] & 255) << 8)
                | ((padding_message[i + 4 * j + 1] & 255) << 16) | ((padding_message[i + 4 * j] & 255) << 24);
        }
        for (int j = 16;j < 68;j++) {
            W[j] = P_1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        unsigned int W_1[64];
        for (int j = 0;j < 64;j++) {
            W_1[j] = W[j] ^ W[j + 4];
        }
        unsigned int SS1 = 0;
        unsigned int SS2 = 0;
        unsigned int TT1 = 0;
        unsigned int TT2 = 0;
        for (int j = 0;j < 64;j++) {
            if (j < 16) {
                SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
                SS2 = SS1 ^ ROTL(A, 12);
                TT1 = FF(A, B, C) + D + SS2 + W_1[j];
                TT2 = GG(E, F, G) + H + SS1 + W[j];
                D = C;
                C = ROTL(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = ROTL(F, 19);
                F = E;
                E = P_0(TT2);
            }
            else {
                SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j % 32), 7);
                SS2 = SS1 ^ ROTL(A, 12);
                TT1 = FF(A, B, C) + D + SS2 + W_1[j % 16];
                TT2 = GG(E, F, G) + H + SS1 + W[j % 16];
                D = C;
                C = ROTL(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = ROTL(F, 19);
                F = E;
                E = P_0(TT2);
            }
        }
        A ^= 0x7380166F;
        B ^= 0x4914B2B9;
        C ^= 0x172442D7;
        D ^= 0xDA8A0600;
        E ^= 0xA96F30BC;
        F ^= 0x163138AA;
        G ^= 0xE38DEE4D;
        H ^= 0xB0FB0E4E;
    }

    stringstream ss;
    ss << hex << setfill('0') << setw(8) << A << setw(8) << B << setw(8) << C << setw(8) << D
        << setw(8) << E << setw(8) << F << setw(8) << G << setw(8) << H;

    digest = ss.str();
}

string generateRandomString(int length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    static default_random_engine random_engine{random_device{}()};
    static uniform_int_distribution<int> distribution(0, sizeof(charset) - 1);

    string result(length, 0);
    for (int i = 0; i < length; ++i) {
        result[i] = charset[distribution(random_engine)];
    }
    return result;
}

int main() 
{
    int data_size[5] = {1024 * 1024, 1024 * 1024 * 32, 1024 * 1024 * 64, 1024 * 1024 * 128, 1024 * 1024 * 256};
    for (int j = 0;j < 5;j++)
    {
        string message = generateRandomString(data_size[j]);
        string digest;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0;i < 10;i++)
        {
            SM3(message, digest);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        cout << "加密 "<< data_size[j] <<" 字节数据 10 次的总用时为 " << duration << " 毫秒" << endl;
        cout << "加密 " << data_size[j] << " 字节数据 1 次的平均用时为 " << duration / 10 << " 毫秒" << endl;
    }
    return 0;
}
