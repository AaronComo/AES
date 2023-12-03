/**
 * @file AES.cpp
 * @author AaronComo (https://github.com/AaronComo)
 * @brief 128位AES算法
 * @version 0.1
 * @date 2023-09-23
 * @copyright Copyright (c) 2023
 */

#include <iostream>
#include <sstream>
#include <chrono>
using namespace std;


class AES128 {
private:
    // S盒
    const unsigned char S[16][16] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // 逆S盒
    const unsigned char S_REVERSE[16][16] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // 轮常量, 用于密钥扩展, RCON[0]是占位符
    const unsigned char RCON[11] = {
        0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // 列混淆左乘矩阵
    const unsigned char MIX_MATRIX[4][4] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02,
    };

    // 逆列混淆左乘矩阵
    const unsigned char MIX_MATRIX_REVERSE[4][4] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e,
    };

    // 状态量
    static const int KEY = 0;
    static const int STATE = 1;
    static const int ENCODE = 0;
    static const int DECODE = 1;

    // 每个元素都是字节(8位)
    unsigned char key[16], state[16];
    unsigned char expanded_key[4][44];

    string result;


    inline void print_expanded_key() {
        cout << "扩展密钥:" << endl;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 44; j++) {
                printf("%x%x ", expanded_key[i][j] >> 4, expanded_key[i][j] & 0x0f);
            }
            cout << endl;
        }
        cout << "\n\n";
    }

    /**
     * @brief 打印给定矩阵
     * @param option KEY: 密钥, STATE: 状态
     */
    inline void print_value(int option) {
        unsigned char *p = nullptr;
        if (!option) {
            cout << "密钥:" << endl;
            p = key;
        } else {
            cout << "状态:" << endl;
            p = state;
        }
        for (int i = 0; i < 16; i++) {
            printf("%x%x ", p[i] >> 4, p[i] & 0x0f);
            if ((i + 1) % 4 == 0) {
                cout << endl;
            }
        }
        cout << "\n\n";
    }

    inline void assign_data() {
        result.clear();
        char buffer[3];
        unsigned char(*p)[4] = (unsigned char(*)[4])state;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                snprintf(buffer, 3, "%x%x", p[j][i] >> 4, p[j][i] & 0x0f);
                result.append(buffer);
            }
        }
    }

    /**
     * @brief 将col-1列复制到col列, 并将col列的字以字节形式循环移位. e.g. 上(1, 2, 3, 4)下 -> (2, 3, 4, 1)
     * @param col 4的整数倍
     * @return 入参col
     */
    inline int rotl(int col) {
        for (int i = 0; i < 4; i++) {
            expanded_key[i][col] = expanded_key[(i + 1) % 4][col - 1];
        }
        return col;
    }

    /**
     * @brief 轮密钥扩展
     * @param key 密钥
     */
    inline void key_expansion(const unsigned char(*key)[4]) {
        // 密钥放在前四列
        for (int i = 0; i < (4 << 2); i++) {
            expanded_key[i & 0x03][i >> 2] = key[i & 0x03][i >> 2];
        }

        // 密钥扩展 (10轮)
        for (int i = 1; i < 11; i++) {
            // 处理4的整数倍列(第一个字), 之后将第一行的元素跟RCON[i]进行异或
            key_S_substitution(rotl(4 * i));
            expanded_key[0][4 * i] ^= RCON[i];

            // 处理第一个字
            for (int j = 0; j < 4; j++) {
                expanded_key[j][4 * i] = expanded_key[j][4 * i] ^ expanded_key[j][4 * (i - 1)];
            }

            // 处理2-4字
            for (int word = 1; word < 4; word++) {
                for (int j = 0; j < 4; j++) {
                    expanded_key[j][4 * i + word] = expanded_key[j][4 * (i - 1) + word]
                        ^ expanded_key[j][4 * i + word - 1];
                }
            }
        }
    }

    /**
     * @brief 将字符串处理成16进制字节矩阵
     * @param S 明文/密文字符串
     * @param K 密钥字符串
     */
    inline void convert_to_bytes(const string S, const string K) {
        unsigned char(*ps)[4] = (unsigned char(*)[4]) state;
        unsigned char(*pk)[4] = (unsigned char(*)[4]) key;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ps[j][i] = (char)stoi(S.substr(2 * (4 * i + j), 2), nullptr, 16);
                pk[j][i] = (char)stoi(K.substr(2 * (4 * i + j), 2), nullptr, 16);
            }
        }
    }

    /**
     * @brief 轮密钥加法, 将每轮对应的密钥异或到状态矩阵中
     * @param round 轮数
     */
    inline void add_round_key(int round) {
        unsigned char(*p)[4] = (unsigned char(*)[4]) state;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                p[i][j] ^= expanded_key[i][4 * round + j];
            }
        }
    }

    /**
     * @brief 对给定的扩展密钥字进行S盒变换
     * @param col 列
     */
    inline void key_S_substitution(const int col) {
        for (int i = 0; i < 4; i++) {
            expanded_key[i][col] = S[expanded_key[i][col] >> 4][expanded_key[i][col] & 0x0f];
        }
    }

    /**
     * @brief S盒变换
     * @param option ENCODE: S盒变换, DECODE: 逆S盒变换
     */
    inline void S_substitution(const int option) {
        const unsigned char(*p)[16] = (!option) ? S : S_REVERSE;
        for (int i = 0; i < 16; i++) {
            state[i] = p[state[i] >> 4][state[i] & 0x0f];
        }
    }

    /**
     * @brief 行位移变换, 第0行不动, 其余行加密左移一位, 解密右移一位
     * @param option ENCODE / DECODE
     */
    inline void shift_rows(const int option) {
        // 将char[16]转换成int[4], 方便单行处理
        unsigned int *p = (unsigned int *)state;
        char offset[2][3] = { { 8, 16, 24 }, { 24, 16, 8 } };
        
        // 注意: 
        // C语言是小端存储(低位放低位), 左移数字其实对应内存向高位移动(右侧)
        // 对数组进行左移, 等同于对内存进行左移, 需要使用对int变量使用右移符号
        p[1] = (p[1] >> offset[option][0]) | (p[1] << offset[option][2]);
        p[2] = (p[2] >> offset[option][1]) | (p[2] << offset[option][1]);
        p[3] = (p[3] >> offset[option][2]) | (p[3] << offset[option][0]);
    }

    /**
     * @brief GF(2^8)上的乘法
     * @return 运算结果 (a * b mod 0x1b)
     */
    inline unsigned char multiply_GF128(unsigned char a, unsigned char b) {
        unsigned char result = 0;
        while (b) {
            if (b & 1) {
                result ^= a;
            }
            // 如果a的最高位为1，则进行模2除法并与不可约多项式异或
            if (a & 0x80) {
                a = (a << 1) ^ 0x1b;
            } else {
                a <<= 1;
            }
            b >>= 1;
        }
        return result;
    }

    /**
     * @brief 列混淆
     * @param option ENCODE / DECODE
     */
    inline void mix_columns(const int option) {
        // 保存矩阵乘法时需要用到的矩阵初始值
        unsigned char temp[4][4];
        unsigned char(*p)[4] = (unsigned char(*)[4]) state;
        const unsigned char(*mat)[4] = (!option) ? MIX_MATRIX : MIX_MATRIX_REVERSE;
        memcpy(temp, state, 16);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                p[i][j] = multiply_GF128(mat[i][0], temp[0][j])
                    ^ multiply_GF128(mat[i][1], temp[1][j])
                    ^ multiply_GF128(mat[i][2], temp[2][j])
                    ^ multiply_GF128(mat[i][3], temp[3][j]);
            }
        }
    }

    inline void validate(const string a, const string b) {
        if (a.length() != 32 or b.length() != 32) {
            printf("请使用128位的输入(32个字符)\n");
            exit(1);
        }
    }

public:
    /**
     * @brief 加密函数
     * @param M 明文字符串
     * @param K 密钥字符串
     * @return 加密后的字符串
     */
    inline string encode(const string M, const string K) {
        validate(M, K);
        convert_to_bytes(M, K);

        // 强制转换为指向char[4]的指针数组
        key_expansion((const unsigned char(*)[4]) key);

        add_round_key(0);

        // 前9轮
        for (int i = 1; i < 10; i++) {
            S_substitution(ENCODE);
            shift_rows(ENCODE);
            mix_columns(ENCODE);
            add_round_key(i);
        }

        // 第10轮
        S_substitution(ENCODE);
        shift_rows(ENCODE);
        add_round_key(10);
        assign_data();
        return result;
    }

    /**
     * @brief 解密函数
     * @param C 密文字符串
     * @param K 密钥字符串
     * @return 解密后的字符串
     */
    inline string decode(const string C, const string K) {
        validate(C, K);
        convert_to_bytes(C, K);
        key_expansion((const unsigned char(*)[4]) key);
        add_round_key(10);
        for (int i = 9; i >= 1; i--) {
            shift_rows(DECODE);
            S_substitution(DECODE);
            add_round_key(i);
            mix_columns(DECODE);
        }
        shift_rows(DECODE);
        S_substitution(DECODE);
        add_round_key(0);
        assign_data();
        return result;
    }

    /**
     * @brief 测试加解密效率
     * @param round 测试轮数
     */
    void evaluate(const int round) {
        printf("\n性能测试中...\n");
        string M = "0001000101a198afda78173486153566";
        string K = "00012001710198aeda79171460153594";
        auto t1 = chrono::high_resolution_clock::now();
        for (int i = 0; i < round; i++) encode(M, K);
        auto t2 = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(t2 - t1);
        float t = (float) duration.count() / 1000;
        printf("%d 轮加/解密耗时:\t%.4f\t秒\n", round, t);
        printf("每秒可加/解密次数:\t%d\t次\n", (int)(1.0 / t * round));
    }
};


int main(int argc, char *argv[]) {
    AES128 aes = AES128();
    string M = "0001000101a198afda78173486153566";
    string K = "00012001710198aeda79171460153594";
    string C = "6cdd596b8f5642cbd23b47981a65422a";
    string encode = aes.encode(M, K);
    string decode = aes.decode(C, K);
    cout << "明文:\t" << M << endl;
    cout << "密钥:\t" << K << endl;
    cout << "加密后:\t" << encode << endl;
    cout << "解密后:\t" << decode << endl;
    aes.evaluate(100000);
    return 0;
}
