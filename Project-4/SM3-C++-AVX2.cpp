#include <iostream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <random>
#include <chrono>
#include <immintrin.h>

using namespace std;
using namespace chrono;

const __m256i T[64] = {
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


void SM3_AVX2(const string& message, string& digest) {
    unsigned int A = 0x7380166f;
    unsigned int B = 0x4914b2b9;
    unsigned int C = 0x172442d7;
    unsigned int D = 0xda8a0600;
    unsigned int E = 0xa96f30bc;
    unsigned int F = 0x163138aa;
    unsigned int G = 0xe38dee4d;
    unsigned int H = 0xb0fb0e4e;

    string padding_message = message;
    padding_message += char(128);

    while (padding_message.size() % 64 != 56) {
        padding_message += char(0);
    }

    unsigned long long bit_length = message.size() * 8;
    for (int i = 7;i >= 0;i--) {
        padding_message += char((bit_length >> (i * 8)) & 255);
    }

    __m256i A_vec = _mm256_set1_epi32(A);
    __m256i B_vec = _mm256_set1_epi32(B);
    __m256i C_vec = _mm256_set1_epi32(C);
    __m256i D_vec = _mm256_set1_epi32(D);
    __m256i E_vec = _mm256_set1_epi32(E);
    __m256i F_vec = _mm256_set1_epi32(F);
    __m256i G_vec = _mm256_set1_epi32(G);
    __m256i H_vec = _mm256_set1_epi32(H);

    for (int i = 0;i < padding_message.size();i += 64) {
        __m256i W[68];
        for (int j = 0;j < 16;j++) {
            W[j] = _mm256_set_epi32(0, 0, 0, 0, 0, padding_message[i + j * 4], padding_message[i + j * 4 + 1], padding_message[i + j * 4 + 2]);
        }
        for (int j = 16;j < 68;j++) {
            __m256i tmp1 = _mm256_xor_si256(_mm256_xor_si256(W[j - 16], W[j - 9]), _mm256_slli_epi32(W[j - 3], 15));
            __m256i tmp2 = _mm256_xor_si256(_mm256_xor_si256(W[j - 13], W[j - 6]), _mm256_slli_epi32(W[j - 10], 15));
            W[j] = _mm256_add_epi32(tmp1, tmp2);
            W[j] = _mm256_add_epi32(W[j], W[j - 16]);
        }
        __m256i W_1[64];
        for (int j = 0;j < 64;j++) {
            W_1[j] = _mm256_xor_si256(W[j], W[j + 4]);
        }
        __m256i SS1_vec[64];
        __m256i SS2_vec[64];
        __m256i TT1_vec[64];
        __m256i TT2_vec[64];
        for (int j = 0;j < 64;j++) {
            SS1_vec[j] = _mm256_slli_epi32(_mm256_or_si256(_mm256_slli_epi32(A_vec, 12), _mm256_srli_epi32(A_vec, 20)), 7);
            SS2_vec[j] = _mm256_slli_epi32(_mm256_or_si256(_mm256_slli_epi32(E_vec, 12), _mm256_srli_epi32(E_vec, 20)), 7);
            TT1_vec[j] = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(H_vec, SS1_vec[j]), _mm256_add_epi32(_mm256_ternarylogic_epi32(A_vec, B_vec, C_vec, 0x7), _mm256_load_si256(&T[j]))), _mm256_set1_epi32(0)), W_1[j]);
            TT2_vec[j] = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(SS2_vec[j], _mm256_ternarylogic_epi32(E_vec, F_vec, G_vec, 0x7)), W[j]), _mm256_set1_epi32(0x98BADCFE));
            H_vec = G_vec;
            G_vec = F_vec;
            F_vec = _mm256_rolv_epi32(E_vec, _mm256_set1_epi32(19));
            E_vec = D_vec;
            D_vec = C_vec;
            C_vec = _mm256_rolv_epi32(B_vec, _mm256_set1_epi32(9));
            B_vec = A_vec;
            A_vec = _mm256_add_epi32(TT1_vec[j], TT2_vec[j]);
        }
        A += A_vec.m256i_i32[0];
        B += B_vec.m256i_i32[0];
        C += C_vec.m256i_i32[0];
        D += D_vec.m256i_i32[0];
        E += E_vec.m256i_i32[0];
        F += F_vec.m256i_i32[0];
        G += G_vec.m256i_i32[0];
        H += H_vec.m256i_i32[0];
    }

    ostringstream oss;
    oss << hex << setw(8) << setfill('0') << A << setw(8) << setfill('0') << B << setw(8) << setfill('0') << C << setw(8) << setfill('0') << D
        << setw(8) << setfill('0') << E << setw(8) << setfill('0') << F << setw(8) << setfill('0') << G << setw(8) << setfill('0') << H;
    digest = oss.str();
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
    int data_size[5] = { 1024 * 1024, 1024 * 1024 * 32, 1024 * 1024 * 64, 1024 * 1024 * 128, 1024 * 1024 * 256 };
    for (int j = 0;j < 5;j++)
    {
        string message = generateRandomString(data_size[j]);
        string digest;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0;i < 10;i++)
        {
            SM3_AVX2(message, digest);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        cout << "加密 " << data_size[j] << " 字节数据 10 次的总用时为 " << duration << " 毫秒" << endl;
        cout << "加密 " << data_size[j] << " 字节数据 1 次的平均用时为 " << duration / 10 << " 毫秒" << endl;
    }
    return 0;
}
