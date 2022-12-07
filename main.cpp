#include <iostream>
#include <algorithm>
#include <chrono>
#include <random>
#include <cstring>

//non-linear transform
uint8_t const S[256] = {
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
        147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129,
        28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
        211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112,
        14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154,
        199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
        128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
        3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
        30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
        165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217,
        231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113,
        103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244,
        180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
};

//inverted non-linear transform
const uint8_t INV_S[256] = {
        0xa5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
        0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
        0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
        0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
        0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
        0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
        0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
        0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
        0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
        0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
        0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
        0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
        0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
        0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
        0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74,
};

//linear transform
const uint8_t L[16] = {
1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148,
};

//pows of 2 in Galois field
const uint8_t POWS[255] = {
        1, 2, 4, 8, 16, 32, 64, 128, 195, 69, 138, 215, 109, 218, 119, 238, 31, 62, 124, 248, 51, 102,
        204, 91, 182, 175, 157, 249, 49, 98, 196, 75, 150, 239, 29, 58, 116, 232, 19, 38, 76, 152, 243,
        37, 74, 148, 235, 21, 42, 84, 168, 147, 229, 9, 18, 36, 72, 144, 227, 5, 10, 20, 40, 80, 160,
        131, 197, 73, 146, 231, 13, 26, 52, 104, 208, 99, 198, 79, 158, 255, 61, 122, 244, 43, 86, 172,
        155, 245, 41, 82, 164, 139, 213, 105, 210, 103, 206, 95, 190, 191, 189, 185, 177, 161, 129,
        193, 65, 130, 199, 77, 154, 247, 45, 90, 180, 171, 149, 233, 17, 34, 68, 136, 211, 101, 202,
        87, 174, 159, 253, 57, 114, 228, 11, 22, 44, 88, 176, 163, 133, 201, 81, 162, 135, 205, 89,
        178, 167, 141, 217, 113, 226, 7, 14, 28, 56, 112, 224, 3, 6, 12, 24, 48, 96, 192, 67, 134, 207,
        93, 186, 183, 173, 153, 241, 33, 66, 132, 203, 85, 170, 151, 237, 25, 50, 100, 200, 83, 166,
        143, 221, 121, 242, 39, 78, 156, 251, 53, 106, 212, 107, 214, 111, 222, 127, 254, 63, 126, 252,
        59, 118, 236, 27, 54, 108, 216, 115, 230, 15, 30, 60, 120, 240, 35, 70, 140, 219, 117, 234, 23,
        46, 92, 184, 179, 165, 137, 209, 97, 194, 71, 142, 223, 125, 250, 55, 110, 220, 123, 246, 47,
        94, 188, 187, 181, 169, 145, 225,
};

//(number - 1) to its logarithm in base 2 in Galois field
const uint8_t NUM_TO_POW[255] = {
        0, 1, 157, 2, 59, 158, 151, 3, 53, 60, 132, 159, 70, 152, 216, 4, 118, 54, 38, 61, 47, 133,
        227, 160, 181, 71, 210, 153, 34, 217, 16, 5, 173, 119, 221, 55, 43, 39, 191, 62, 88, 48, 83,
        134, 112, 228, 247, 161, 28, 182, 20, 72, 195, 211, 242, 154, 129, 35, 207, 218, 80, 17, 204,
        6, 106, 174, 164, 120, 9, 222, 237, 56, 67, 44, 31, 40, 109, 192, 77, 63, 140, 89, 185, 49,
        177, 84, 125, 135, 144, 113, 23, 229, 167, 248, 97, 162, 235, 29, 75, 183, 123, 21, 95, 73, 93,
        196, 198, 212, 12, 243, 200, 155, 149, 130, 214, 36, 225, 208, 14, 219, 189, 81, 245, 18, 240,
        205, 202, 7, 104, 107, 65, 175, 138, 165, 142, 121, 233, 10, 91, 223, 147, 238, 187, 57, 253,
        68, 51, 45, 116, 32, 179, 41, 171, 110, 86, 193, 26, 78, 127, 64, 103, 141, 137, 90, 232, 186,
        146, 50, 252, 178, 115, 85, 170, 126, 25, 136, 102, 145, 231, 114, 251, 24, 169, 230, 101, 168,
        250, 249, 100, 98, 99, 163, 105, 236, 8, 30, 66, 76, 108, 184, 139, 124, 176, 22, 143, 96, 166,
        74, 234, 94, 122, 197, 92, 199, 11, 213, 148, 13, 224, 244, 188, 201, 239, 156, 254, 150, 58,
        131, 52, 215, 69, 37, 117, 226, 46, 209, 180, 15, 33, 220, 172, 190, 42, 82, 87, 246, 111, 19,
        27, 241, 194, 206, 128, 203, 79,
};

//MULTIPLICATION_MATRIX[i][j] = i * j in Galois field
uint8_t MULTIPLICATION_MATRIX[256][256] = {};

//Linear transform matrix, which will be used for optimization to avoid multiple multiplications.
//LINEAR_TRANSFORM[i][j] contains the vector of impact of byte j on the i-th place in final linear transformation.
//Another explanation is if linear transformation is <block, L> (where matrix L is matrix of full linear transformation),
//then LINEAR_TRANSFORM[i][block[i]] = block[i] * L[i] (where L[i] is i-th row in L).
uint8_t LINEAR_TRANSFORM[16][256][16] = {};

//for decoding
uint8_t INV_LINEAR_TRANSFORM[16][256][16] = {};

//round keys for encoding/decoding
uint8_t ROUND_KEYS[10][16] = {};

void finish_preprocessing() {
    //fill multiplication matrix
    for (size_t i = 0; i < 256; ++i) {
        for (size_t j = 0; j < 256; ++j) {
            if (i == 0 || j == 0) {
                MULTIPLICATION_MATRIX[i][j] = 0;
                continue;
            }
            size_t k = NUM_TO_POW[i - 1] + NUM_TO_POW[j - 1];
            if (k >= 255) {
                k -= 255;
            }
            MULTIPLICATION_MATRIX[i][j] = POWS[k];
        }
    }

    //fill linear in inverted liner transform matrices
    for (uint8_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 256; ++j) {
            // one linear and inverted linear transform
            LINEAR_TRANSFORM[i][j][i] = j;
            INV_LINEAR_TRANSFORM[i][j][i] = j;
            for (uint8_t k = 0; k < 16; ++k) {
                uint8_t tmp_lin = 0;
                uint8_t tmp_inv = 0;
                for (uint8_t first_ind = 0; first_ind < 16; ++first_ind) {
                    tmp_lin ^= MULTIPLICATION_MATRIX[L[first_ind]]
                    [LINEAR_TRANSFORM[i][j][(first_ind + k) % 16]];
                    tmp_inv ^= MULTIPLICATION_MATRIX[L[15 - first_ind]][INV_LINEAR_TRANSFORM[i][j][(first_ind + 16 - k) % 16]];
                }
                LINEAR_TRANSFORM[i][j][k] = tmp_lin;
                INV_LINEAR_TRANSFORM[i][j][15 - k] = tmp_inv;
            }
        }
    }
}

void apply_linear_transform(uint8_t block[16]) {
    uint8_t result[16] = {};
    for (uint8_t i = 0; i < 16; ++i) {
        for (uint8_t first_ind = 0; first_ind < 16; ++first_ind) {
            result[first_ind] ^= LINEAR_TRANSFORM[i][block[i]][first_ind];
        }
    }
    std::memcpy(block, result, 16);
}

void generate_keys(const uint8_t key[32]) {
    // generate round constants
    uint8_t round_constants[32][16] = {};
    for (uint8_t i = 0; i < 32;  ++i) {
        round_constants[i][0] = i + 1;
        apply_linear_transform(round_constants[i]);
    }

    std::memcpy(ROUND_KEYS[0], key + (uint8_t) 16, 16);
    std::memcpy(ROUND_KEYS[1], key, 16);

    // Feistel net
    for (uint8_t i = 1; i < 5;  ++i) {
        uint8_t left[16] = {};
        uint8_t right[16] = {};
        uint8_t new_left[16] = {};

        std::memcpy(left, ROUND_KEYS[2 * (i - 1)], 16);
        std::memcpy(right, ROUND_KEYS[2 * (i - 1) + 1], 16);

        for (uint8_t j = 0; j < 8;  ++j) {
            for (uint8_t idx = 0; idx < 16;  ++idx) {
                new_left[idx] = S[(left[idx] ^ round_constants[(i-1) * 8 + j][idx])];
            }
            apply_linear_transform(new_left);
            for (uint8_t idx = 0; idx < 16;  ++idx) {
                new_left[idx] ^= right[idx];
            }
            std::memcpy(right, left, 16);
            std::memcpy(left, new_left, 16);
        }

        std::memcpy(ROUND_KEYS[2 * i], left, 16);
        std::memcpy(ROUND_KEYS[2 * i + 1], right, 16);
    }
}

void apply_inv_linear_transform(uint8_t block[16]) {
    uint8_t result[16] = {};
    for (uint8_t i = 0; i < 16; ++i) {
        for (uint8_t first_ind = 0; first_ind < 16; ++first_ind) {
            result[first_ind] ^= INV_LINEAR_TRANSFORM[i][block[i]][first_ind];
        }
    }
    std::memcpy(block, result, 16);
}

void encrypt_block(uint8_t block[16]) {
    for (uint8_t i = 0; i < 9; ++i) {
        for (uint8_t idx = 0; idx < 16; ++idx) {
            block[idx] = S[block[idx] ^ ROUND_KEYS[i][idx]];
        }
        apply_linear_transform(block);
    }
    for (uint8_t idx = 0; idx < 16; ++idx) {
        block[idx] ^= ROUND_KEYS[9][idx];
    }
}

void decrypt_block(uint8_t block[16]) {
    for (uint8_t idx = 0; idx < 16; ++idx) {
        block[idx] ^= ROUND_KEYS[9][idx];
    }
    for (int8_t i = 8; i >= 0; --i) {
        apply_inv_linear_transform(block);
        for (uint8_t idx = 0; idx < 16; ++idx) {
            block[idx] = INV_S[block[idx]] ^ ROUND_KEYS[i][idx];
        }
    }
}

int main() {
    const uint8_t key[32] = {
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x77,0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    };
    finish_preprocessing();
    generate_keys(key);

    // generate 200 MB of random data for encrypt and decrypt test
    auto data = new uint8_t[6400][2048][16];

    std::random_device rd;
    std::mt19937_64 g(rd());
    std::uniform_int_distribution<std::uint8_t> dist(0, 255);
    for (size_t i = 0; i < 6400 * 2048 * 16; ++i)
        ((std::uint8_t*)data)[i] = dist(g);

    auto test = new uint8_t[6400][2048][16];
    std::memcpy((std::uint8_t*)test, (std::uint8_t*)data, 6400 * 2048 * 16);

    std::cout << "START ENCRYPT\n";
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    for (size_t i = 0; i < 6400; ++i) {
        for (size_t j = 0; j < 2048; ++j) {
            encrypt_block(data[i][j]);
        }
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::cout << "Encrypt took = " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()
    << "[ms]" << std::endl;

    // test correctness
    for (size_t i = 0; i < 6400; ++i) {
        for (size_t j = 0; j < 2048; ++j) {
            decrypt_block(data[i][j]);
            for (size_t k = 0; k < 16; ++k) {
                if (data[i][j][k] != test[i][j][k]) {
                    std::clog << "MISMATCH " << i << ' ' << j << ' ' << k << std::endl;
                }
            }
        }
    }
    std::cout << "ENCRYPT AND DECRYPT ARE CORRECT!";
    delete[] data;
    return 0;
}
