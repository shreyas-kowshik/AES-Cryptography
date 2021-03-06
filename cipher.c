/*
Shreyas Kowshik
17MA20039
*/

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/********************
AES IMPLEMENTATION
********************/

typedef uint8_t state_arr[4][4]; // stores AES round state as a 2d array
typedef uint8_t** state; // stores AES round state as a double pointer

// AES S-Box
const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
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
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// AES Inverse S-Box
const uint8_t invsbox[256] = {
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
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// Matrix for GF(2^8) multiplication for MixColumns
const uint8_t mixColMat[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

// Inverse Matrix for GF(2^8) multiplication for InverseMixColumns
const uint8_t invMixColMat[4][4] = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
};

// Round Constants for the 10 rounds for the round key generation
const uint32_t Rcon[11] = {
    0x00000000, // dummy value
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000
};

/* Utility functions */
void print_as_hex_arr(uint8_t a[16]) {
    int i;
    for(i=0;i<16;i++) {
        int t=a[i]>>4;
        int u=a[i]&(15);
        if(t<=9) printf("%d", t);
        else printf("%c", 'a' + (t-10));
        if(u<=9) printf("%d", u);
        else printf("%c", 'a' + (u-10));
    }
}

void print_as_hex_word(uint32_t a) {
    int i;
    for(i=0;i<4;i++) {
        int tem=a>>(8*(3-i));
        tem=tem&(255);
        int t=tem>>4;
        int u=tem&(15);
        if(t<=9) printf("%d", t);
        else printf("%c", 'a' + (t-10));
        if(u<=9) printf("%d", u);
        else printf("%c", 'a' + (u-10));
    }
}

void print_as_hex_state(state s) {
    int i,j;
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            int t=s[j][i]>>4;
            int u=s[j][i]&(15);
            if(t<=9) printf("%d", t);
            else printf("%c", 'a' + (t-10));
            if(u<=9) printf("%d", u);
            else printf("%c", 'a' + (u-10));
        }
    }
}

void SubBytesCheckArrayChanged(state s) {
    int i;
    int j;
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            s[i][j]=0x00;
        }
    }
}
/***********************/

/* AES functions for each round */
void SubBytes(state s) {
    int i,j;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            s[i][j]=sbox[s[i][j]];
}

void InvSubBytes(state s) {
    int i,j;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            s[i][j]=invsbox[s[i][j]];
}

void ShiftRows(state s) {
    uint8_t tem;

    state_arr new;
    int i,j;

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            new[i][j]=s[i][(j+i)%4];
        }
    }

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            s[i][j]=new[i][j];
        }
    }
}

void InvShiftRows(state s) {
    uint8_t tem;

    state_arr new;
    int i,j;

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            new[i][(j+i)%4]=s[i][j];
        }
    }

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            s[i][j]=new[i][j];
        }
    }
}

/* Utility functions for add/multiply */
uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))) ^

       ((y>>5 & 1) * xtime(xtime(xtime(xtime(xtime(x)))))) ^
       ((y>>6 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(x))))))) ^
       ((y>>7 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(xtime(x)))))))) 
       
       ); /* this last call to xtime() can be omitted */
}
/**/

void MixColumns(state s) {
    // add, multiply two uint8_t types in GF(2^8)
    int i,j,k;
    uint8_t res=0;
    uint8_t resMat[4][4];
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            res=0;
            for(k=0;k<4;k++) {
                res=res^(Multiply(mixColMat[i][k], s[k][j]));
                // if(i==0&&j==0) {
                //     printf("%d : %d\n", k, res);
                // }
            }
            // printf("%d %d %d\n", i, j, res);
            resMat[i][j]=res;
        }
    }

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            s[i][j]=resMat[i][j];
        }
    }
}

void InvMixColumns(state s) {
    // add, multiply two uint8_t types in GF(2^8)
    int i,j,k;
    uint8_t res=0;
    uint8_t resMat[4][4];
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            res=0;
            for(k=0;k<4;k++) {
                res=res^(Multiply(invMixColMat[i][k], s[k][j]));
                
            }
            resMat[i][j]=res;
        }
    }

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            s[i][j]=resMat[i][j];
        }
    }
}


void AddRoundKey(state s, uint8_t** key) {
    int i,j;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            s[i][j]=s[i][j]^key[i][j];
}
/*******************/

/* AES Key Scheduling */
uint32_t RotWord(uint32_t x) {
    return ((x>>24)^(x<<8));
}

uint32_t SubWord(uint32_t x) {
    uint32_t res=0;
    int i;
    for(i=0;i<4;i++) {
        res=res<<8;
        res=res^(sbox[((x>>(8*(3-i)))&(255))]);
    }

    return res;
}

void keySchedule(uint8_t key[16], uint32_t w[44]) {
    // following notation from the slides
    uint32_t temp;
    int i;
    for(i=0;i<4;i++) {
        w[i] = (((uint32_t)key[4*i])<<24)^(((uint32_t)key[4*i+1])<<16)^(((uint32_t)key[4*i+2])<<8)^(((uint32_t)key[4*i+3]));
    }

    for(i=4;i<44;i++) {
        temp=w[i-1];
        if(i%4==0) temp=SubWord(RotWord(temp))^(Rcon[i/4]);
        w[i] = w[i-4]^temp;
    }
}
/**/

// convert a 128-bit input to a 4x4 matrix for the state in AES processing
uint8_t** state_from_block(uint8_t in[16]) {
    uint8_t** out;
    out = (uint8_t **) malloc(sizeof(uint8_t *)*4);
    int i, j;
    for(i=0;i<4;i++) out[i]=(uint8_t *)malloc(sizeof(uint8_t)*4);

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            out[j][i]=in[4*i + j];
        }
    }

    return out;
}

// convert 4 words (32-bit each) to a 4x4 matrix of 8-bit keys
uint8_t** roundKeyMat(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3) {
    uint8_t** out;
    out = (uint8_t **) malloc(sizeof(uint8_t *)*4);
    int i, j;
    for(i=0;i<4;i++) out[i]=(uint8_t *)malloc(sizeof(uint8_t)*4);

    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            // fill each column
            if(i==0) out[j][i]=(uint8_t)((w0>>(8*(3-j)))&(255));
            else if(i==1) out[j][i]=(uint8_t)((w1>>(8*(3-j)))&(255));
            else if(i==2) out[j][i]=(uint8_t)((w2>>(8*(3-j)))&(255));
            else out[j][i]=(uint8_t)((w3>>(8*(3-j)))&(255));
        }
    }

    return out;
}
/********************************/
/********************
AES IMPLEMENTATION ENDS
********************/



/********************
FIETSEL CIPHER IMPLEMENTATION
********************/
const uint8_t fietsel_sbox[256] = {
  0x02, 0x09, 0x0a, 0x05, 0x00, 0x06, 0x05, 0x08, 0x0f, 0x00, 0x03, 0x0e, 0x01, 0x03, 0x07, 0x0b,
  0x0c, 0x03, 0x09, 0x02, 0x0b, 0x0f, 0x0f, 0x07, 0x04, 0x0e, 0x03, 0x04, 0x04, 0x0e, 0x09, 0x0b,
  0x04, 0x0b, 0x04, 0x02, 0x06, 0x02, 0x03, 0x0d, 0x0e, 0x0c, 0x05, 0x0b, 0x02, 0x0a, 0x03, 0x0e,
  0x08, 0x0e, 0x01, 0x06, 0x08, 0x09, 0x04, 0x02, 0x06, 0x0b, 0x02, 0x09, 0x0d, 0x0b, 0x01, 0x05,
  0x02, 0x08, 0x06, 0x04, 0x06, 0x08, 0x08, 0x06, 0x04, 0x04, 0x0c, 0x0c, 0x0d, 0x05, 0x06, 0x02,
  0x0c, 0x00, 0x08, 0x00, 0x0d, 0x0d, 0x09, 0x0a, 0x0e, 0x05, 0x06, 0x07, 0x07, 0x0d, 0x0d, 0x04,
  0x00, 0x08, 0x0b, 0x00, 0x0c, 0x0c, 0x03, 0x0a, 0x07, 0x04, 0x08, 0x05, 0x08, 0x03, 0x05, 0x06,
  0x00, 0x0c, 0x0e, 0x0f, 0x0a, 0x0f, 0x0f, 0x02, 0x01, 0x0f, 0x0d, 0x03, 0x01, 0x03, 0x0a, 0x0b,
  0x0a, 0x01, 0x01, 0x01, 0x0f, 0x07, 0x0c, 0x0a, 0x07, 0x02, 0x0f, 0x0e, 0x00, 0x04, 0x06, 0x03,
  0x06, 0x0c, 0x04, 0x02, 0x07, 0x0d, 0x05, 0x05, 0x02, 0x09, 0x07, 0x08, 0x0c, 0x05, 0x0f, 0x0e,
  0x07, 0x01, 0x0a, 0x01, 0x0d, 0x09, 0x05, 0x09, 0x0f, 0x07, 0x02, 0x0e, 0x0a, 0x08, 0x0e, 0x0b,
  0x0c, 0x06, 0x0e, 0x0b, 0x06, 0x02, 0x09, 0x00, 0x0a, 0x0b, 0x00, 0x0e, 0x08, 0x0d, 0x0a, 0x04,
  0x0f, 0x0d, 0x08, 0x03, 0x08, 0x07, 0x07, 0x01, 0x01, 0x02, 0x00, 0x09, 0x07, 0x00, 0x0c, 0x0f,
  0x00, 0x01, 0x0f, 0x09, 0x09, 0x05, 0x0a, 0x0d, 0x0d, 0x05, 0x0a, 0x0f, 0x03, 0x09, 0x0c, 0x0f,
  0x00, 0x00, 0x0b, 0x0d, 0x0e, 0x0a, 0x05, 0x00, 0x08, 0x0b, 0x0b, 0x0c, 0x03, 0x03, 0x09, 0x01,
  0x07, 0x0b, 0x04, 0x0e, 0x0a, 0x07, 0x06, 0x06, 0x01, 0x09, 0x04, 0x03, 0x05, 0x01, 0x0c, 0x0d };

const uint8_t fietsel_permute_table[8] = {
    3, 4, 6, 5, 1, 0, 7, 2
};

const uint8_t inv_fietsel_permute_table[8] = {
    5, 4, 7, 0, 1, 3, 2, 6
};

const uint8_t fietsel_key_permute[128] = {
    78,  74,  29,  92,  23,  81,  61,  68,  86,  27,  13,  87,  30,
    114,  85,  99, 109, 110,  56,  11,  33,  96,  67, 125,  89, 121,
    3,  63,  12,   1, 117, 118,  44,  62,   6,  40,  58,  22,  84,
    91,  76,  16,  25,  14, 105, 107, 103, 108,  52, 120, 112, 113,
    8,  42, 124,  10,  45,  28,  88,  43,  39,  31,  24,  21, 127,
    50,  26,  41, 115,  34,  83,  54, 116, 101,  93, 102,  95,  64,
    123,   0,  94,   2,  51, 126,  18,  82,  55,  80,  57,  70,  60,
    48,  53,  47,  69,  35,  97,  32,   9, 119, 122,  37,  73,  38,
    104,  19, 111,  79,   4,  49,  59, 106,  72,   7,  15,  75,  17,
    100,  20,  77,  71,  98,  65,  46,  66,  90,  36,   5
};

void print_as_hex_arr64(uint8_t a[8]) {
    int i;
    for(i=0;i<8;i++) {
        int t=a[i]>>4;
        int u=a[i]&(15);
        if(t<=9) printf("%d", t);
        else printf("%c", 'a' + (t-10));
        if(u<=9) printf("%d", u);
        else printf("%c", 'a' + (u-10));
    }
}

uint8_t* Expansion(uint8_t* in) {
    /*
    Expand 64-bit input to 128-bit output

    input : 0 1 2 3 4 5 6 7
    output : 7 6 5 4 0 1 2 3 4 5 6 7 0 1 2 3
    */
    uint8_t* out = (uint8_t *)malloc(sizeof(uint8_t) * 16);
    // shuffle bytes
    int i;
    for(i=0;i<16;i++) {
        if(i<4) out[i]=in[7-i]; // fill in from last bytes
        else if(i>=4 && i<12) out[i]=in[i-4];
        else out[i]=in[i-12];
    }

    return out;
}

void permute(uint8_t* in) {
    // shuffle bits of 128-bit input
    int i;
    uint8_t out[8];
    for(i=0;i<8;i++) out[i]=in[fietsel_permute_table[i]];
    for(i=0;i<8;i++) in[i]=out[i];
}

void inv_permute(uint8_t in[8]) {
    // shuffle bits of 128-bit input
    int i;
    uint8_t out[8];
    for(i=0;i<8;i++) out[i]=in[inv_fietsel_permute_table[i]];
    for(i=0;i<8;i++) in[i]=out[i];
}

/* Utility functions */
// get nth bit of x (0 <= n <= 7)
uint8_t get_bit(uint8_t x,
                 uint8_t n) {
    return (x >> n) & 1;
}

// Set the nth bit of the value of x to v.
// Assume 0 <= n <= 8, and v is 0 or 1
void set_bit(uint8_t *x, uint8_t n, uint8_t v) {
        int y=*x;
        y = y >> (n+1);
        y = y << 1;
        y = y | v;
        int i;
        uint8_t t;
        for(i=n-1;i>=0;i--) {
                t=get_bit(*x, i);
                y=y<<1;
                y=y|t;
        }
        *x=y;
}

uint8_t** keyScheduler(uint8_t key[16], int rounds) {
    int round;
    uint8_t** keys = (uint8_t **)malloc(sizeof(uint8_t *)*rounds);
    int i;

    for(i=0;i<rounds;i++) { keys[i]=(uint8_t *)malloc(sizeof(uint8_t)*16); }

    for(round=0;round<rounds;round++) {
        // printf("%d\n", round);

        /* Left Shift Values */
        uint64_t v=0;

        // construct 64-bit value out of first 8 bytes
        for(i=0;i<8;i++) {
            v=v<<8;
            if(round==0) v=v^key[i];
            else v=v^keys[round-1][i];
        }

        // do a left circular shift
        v=(v<<1)^((v>>63)&1);

        // write back to current round key values
        for(i=0;i<8;i++) keys[round][i]=(v>>(8*(7-i)))&255;

        // construct 64-bit value out of last 8 bytes
        for(i=8;i<16;i++) {
            v=v<<8;
            if(round==0) v=v^key[i];
            else v=v^keys[round-1][i];
        }

        // do a left circular shift
        v=(v<<1)^((v>>63)&1);

        // write back to current round key values
        for(i=8;i<16;i++) keys[round][i]=(v>>(8*(15-i)))&255;
        /******/

        // keys[round]=[ LS(keys[round][0...7]) LS(keys[round][8...15]) ] now

        // Apply permutation on current round key
        uint8_t tem[16];
        for(i=0;i<16;i++) tem[i]=0;
        for(i=0;i<128;i++) {
            int loc=i/8;
            int bit_loc=i%8;
            // extract bit
            uint8_t bit=get_bit(keys[round][loc], bit_loc);
            // move bit
            set_bit(&tem[fietsel_key_permute[i]/8], fietsel_key_permute[i]%8, bit);
        }

        for(i=0;i<16;i++) keys[round][i]=tem[i];
    }

    return keys;
}

void fietsel_f(uint8_t *in, uint8_t *key) {
    // compute f(A,B)
    // expand 64-128 bits
    // xor
    // sbox on 16 bytes
    // permute
    
    uint8_t* expanded_in=Expansion(in);

    int i;
    for(i=0;i<16;i++) expanded_in[i]=expanded_in[i]^key[i];

    // apply sbox and reduce down to 8 bytes
    for(i=0;i<16;i++) expanded_in[i]=fietsel_sbox[expanded_in[i]];

    for(i=0;i<16;i+=2) expanded_in[i]=(expanded_in[i]<<4)^(expanded_in[i+1]&15);

    for(i=0;i<8;i++) in[i]=expanded_in[2*i];

    // apply permutation
    permute(in);
}

// Encryption for Fietsel cipher sturcutre
void encrypt_f(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds, int verbose) {
    uint8_t** keys = keyScheduler(key, rounds);

    int round;
    int i;

    for(i=0;i<16;i++) out[i]=in[i]; // copy initial input to output

    if(verbose) {
        printf("Encryption : Start of Fietsel Cipher : Input : ");
        print_as_hex_arr(out);
        printf("\n");
    }

    for(round=0;round<rounds;round++) {
        // fietsel cipher
        // split input
        uint8_t L[8];
        uint8_t R[8];
        for(i=0;i<8;i++) L[i]=out[i];
        for(i=8;i<16;i++) R[i-8]=out[i];

        fietsel_f(R, keys[round]); // R is now updated to new values

        for(i=0;i<8;i++) out[i]=out[i+8]; // copy original R
        for(i=8;i<16;i++) {
            out[i]=L[i-8]^R[i-8];
        }

        if(verbose) {
            printf("Encryption : Fietsel Cipher : round %d Key : ", round + 1);
            print_as_hex_arr(keys[round]);
            printf("\n");
            printf("Encryption : Fietsel Cipher : round %d Output : ", round + 1);
            print_as_hex_arr(out);
            printf("\n");
            printf("---\n");
        }
    }
}

// Decryption for Fietsel cipher sturcutre
void decrypt_f(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds, int verbose) {
    uint8_t** keys = keyScheduler(key, rounds);
    int round;
    int i;
    for(i=0;i<16;i++) out[i]=in[i]; // copy initial input to output

    if(verbose) {
        printf("Decryption : Start of Fietsel Cipher : Input : ");
        print_as_hex_arr(out);
        printf("\n");
    }

    for(round=rounds-1;round>=0;round--) {
        // fietsel cipher
        // split input
        uint8_t L[8];
        uint8_t R[8];
        for(i=0;i<8;i++) L[i]=out[i];
        for(i=8;i<16;i++) R[i-8]=out[i];

        fietsel_f(L, keys[round]); // L is now updated to new values
        for(i=8;i<16;i++) out[i]=out[i-8];
        for(i=0;i<8;i++) out[i]=L[i]^R[i];

        if(verbose) {
            printf("Decryption : Fietsel Cipher : round %d Key : ", round + 1);
            print_as_hex_arr(keys[round]);
            printf("\n");
            printf("Decryption : Fietsel Cipher : round %d Output : ", round + 1);
            print_as_hex_arr(out);
            printf("\n");
            printf("---\n");
        }
    }
}
/*************************************/
/********************
FIETSEL CIPHER IMPLEMENTATION ENDS
********************/

/********************
ENCRYPTION/DECRYPTION FUNCTIONS COMBINING THE TWO
********************/

/* Combined Encryption/Decryption */
void encrypt(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds, int verbose) {
    /*
    5 rounds of AES
    `rounds` rounds of Fietsel
    5 rounds of AES
    */

    uint8_t** s=state_from_block(in);
    uint32_t w[44];
    keySchedule(key, w);
    int round=0;

    uint8_t** keyMat=roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]);
    AddRoundKey(s, keyMat);

    if(verbose) {
        printf("AES : After add round key round %d : ", round);
        print_as_hex_state(s);
        printf("\n");
    }

    for(round=1;round<=5;round++) {
        if(verbose) {
            printf("\n---\n");
            printf("AES Encryption : Round %d Start Output : ", round);
            print_as_hex_state(s);
            printf("\n");
            printf("AES Encryption : Round %d Key : ", round);
            print_as_hex_word(w[4*(round)]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 1]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 2]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 3]);
            printf("\n");
        }

        
        SubBytes(s);
        if(verbose) {
            printf("AES Encryption : After sub bytes round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        ShiftRows(s);
        if(verbose) {
            printf("AES Encryption : After shift rows round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        if(round < 10) {
            MixColumns(s);
            if(verbose) {
                printf("AES Encryption : After mix columns round %d : ", round);
                print_as_hex_state(s);
                printf("\n");
            }
        }

        AddRoundKey(s, roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]));
        if(verbose) {
            printf("AES Encryption : After add round key round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }
    }

    for(int i=0;i<4;i++) {
        for(int j=0;j<4;j++) {
            out[4*i+j] = s[j][i];
        }
    }

    // Start Fietsel Encryption
    uint8_t fietsel_out[16];

    printf("\n\n---Fietsel Cipher Block---\n");
    printf("Encryption : Fietsel  Input : ");
    print_as_hex_arr(out);
    printf("\n");
    encrypt_f(out, key, fietsel_out, rounds, verbose);
    printf("Encryption : Fietsel Output : ");
    print_as_hex_arr(fietsel_out);
    printf("\n-----------\n\n\n");

    s=state_from_block(fietsel_out);
    // End Fietsel Encryption

    for(round=6;round<=10;round++) {
        if(verbose) {
            printf("\n---\n");
            printf("AES Encryption : Round %d Start Output : ", round);
            print_as_hex_state(s);
            printf("\n");
            printf("AES Encryption : Round %d Key : ", round);
            print_as_hex_word(w[4*(round)]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 1]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 2]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 3]);
            printf("\n");
        }

        
        SubBytes(s);
        if(verbose) {
            printf("AES Encryption : After sub bytes round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        ShiftRows(s);
        if(verbose) {
            printf("AES Encryption : After shift rows round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        if(round < 10) {
            MixColumns(s);
            if(verbose) {
                printf("AES Encryption : After mix columns round %d : ", round);
                print_as_hex_state(s);
                printf("\n");
            }
        }

        AddRoundKey(s, roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]));
        if(verbose) {
            printf("AES Encryption : After add round key round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }
    }

    for(int i=0;i<4;i++) {
        for(int j=0;j<4;j++) {
            out[4*i+j] = s[j][i];
        }
    }
    

}

void decrypt(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds, int verbose) {
    /*
    5 rounds of AES
    `rounds` rounds of Fietsel
    5 rounds of AES
    */

    uint8_t** s=state_from_block(in);
    uint32_t w[44];
    keySchedule(key, w);

    int round=10;

    uint8_t** keyMat=roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]);

    for(round=10;round>=6;round--) {
        if(verbose) {
            printf("\n---\n");
            printf("AES Decryption : Round %d Start Output : ", round);
            print_as_hex_state(s);
            printf("\n");
            printf("AES Decryption : Round %d Key : ", round);
            print_as_hex_word(w[4*(round)]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 1]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 2]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 3]);
            printf("\n");
        }

        AddRoundKey(s, roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]));
        if(verbose) {
            printf("AES Decryption : After add round key round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        if(round < 10) {
            InvMixColumns(s);
            if(verbose) {
                printf("AES Decryption : After inverse mix columns round %d : ", round);
                print_as_hex_state(s);
                printf("\n");
            }
        }

        InvShiftRows(s);
        if(verbose) {
            printf("AES Decryption : After inverse shift rows round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        InvSubBytes(s);
        if(verbose) {
            printf("AES Decryption : After sub bytes round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }
    }

    for(int i=0;i<4;i++) {
        for(int j=0;j<4;j++) {
            out[4*i+j] = s[j][i];
        }
    }

    // Start Fietsel Decryption
    uint8_t fietsel_out[16];
    printf("\n\n---Fietsel Cipher Block---\n");
    printf("Decryption : Fietsel  Input : ");
    print_as_hex_arr(out);
    printf("\n");
    decrypt_f(out, key, fietsel_out, rounds, verbose);
    printf("Decryption : Fietsel Output : ");
    print_as_hex_arr(fietsel_out);
    printf("\n-----------\n\n\n");

    s=state_from_block(fietsel_out);
    // End Fietsel Decryption

    for(round=5;round>=1;round--) {
        if(verbose) {
            printf("\n---\n");
            printf("AES Decryption : Round %d Start Output : ", round);
            print_as_hex_state(s);
            printf("\n");
            printf("AES Decryption : Round %d Key : ", round);
            print_as_hex_word(w[4*(round)]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 1]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 2]);
            // printf(" ");
            print_as_hex_word(w[4*(round) + 3]);
            printf("\n");
        }

        AddRoundKey(s, roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]));
        if(verbose) {
            printf("AES Decryption : After add round key round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        if(round < 10) {
            InvMixColumns(s);
            if(verbose) {
                printf("AES Decryption : After inverse mix columns round %d : ", round);
                print_as_hex_state(s);
                printf("\n");
            }
        }

        InvShiftRows(s);
        if(verbose) {
            printf("AES Decryption : After inverse shift rows round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }

        InvSubBytes(s);
        if(verbose) {
            printf("AES Decryption : After sub bytes round %d : ", round);
            print_as_hex_state(s);
            printf("\n");
        }
    }

    AddRoundKey(s, roundKeyMat(w[round*4], w[round*4 + 1], w[round*4 + 2], w[round*4 + 3]));
    if(verbose) {
        printf("AES Decryption : After add round key round %d : ", round);
        print_as_hex_state(s);
        printf("\n");
    }

    for(int i=0;i<4;i++) {
        for(int j=0;j<4;j++) {
            out[4*i+j] = s[j][i];
        }
    }

}
/*************************************/

/* Utility function for input values */
uint8_t char2hex(char c) {
    if(c>='0'&&c<='9') return ((int)c)-48;
    else return ((int)c)-87;
}

int main() {
    printf("\n---17MA20039 : AES+Fietsel Implementation---\n");
    printf("Enter plaintext in following format as 32 hexadecimal characters (eg. 00000000000000000000000000000000) :\n");
    printf("Enter Plaintext : ");
    int idx;
    char c;

    // Take input plaintext
    uint8_t in[16];
    for(idx=0;idx<32;idx++) {
        scanf("%c", &c);
        if(!((c>='0'&&c<='9') || (c>='a'&&c<='f'))) {
            printf("\nInvalid hexadecimal character. Exiting...\n");
            exit(1);
        }
        if(idx%2 == 0) in[idx/2]=char2hex(c);
        else in[idx/2]=(in[idx/2]<<4)^(char2hex(c));
    }
    scanf("%c", &c);

    printf("Enter cipherkey in following format as 32 hexadecimal characters (eg. 00000000000000000000000000000000) :\n");
    printf("Enter Cipherkey : ");

    // Take input cipherkey
    uint8_t key[16];
    for(idx=0;idx<32;idx++) {
        scanf("%c", &c);
        if(!((c>='0'&&c<='9') || (c>='a'&&c<='f'))) {
            printf("\nInvalid hexadecimal character. Exiting...\n");
            exit(1);
        }
        if(idx%2 == 0) key[idx/2]=char2hex(c);
        else key[idx/2]=(key[idx/2]<<4)^(char2hex(c));
    }
    scanf("%c", &c);

    int rounds=5;
    int verbose=1;

    printf("Enter number of Fietsel Rounds (eg. 5) : ");
    scanf("%d", &rounds);
    printf("Do you want to generate outputs for intermediate steps of envryption/decryption? (0:no,1:yes) : ");
    scanf("%d", &verbose);

    /* Alternatively, one can also uncomment the below lines and manually enter the values */

    // uint8_t in[16] = {
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00
    // };

    // uint8_t key[16] = {
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00
    // };

    // Begin Encryption/Decryption
    uint8_t out[16];
    int i,j;

    // for(i=0;i<16;i++) printf("%d ", in[i]);
    // printf("\n");
    printf("Cipher Input : ");
    print_as_hex_arr(in);

    printf("\n---\n");

    // for(i=0;i<16;i++) printf("%d ", key[i]);
    // printf("\n");
    printf("Key : ");
    print_as_hex_arr(key);
    printf("\n---\n");

    encrypt(in, key, out, rounds, verbose);
    printf("\n\n\n");

    // for(i=0;i<16;i++) printf("%d ", out[i]);
    // printf("\n");
    printf("Cipher text : ");
    print_as_hex_arr(out);
    printf("\n---\n\n\n\n\n---\n");

    uint8_t decrypt_out[16];
    decrypt(out, key, decrypt_out, rounds, verbose);

    printf("\n\n\n");
    printf("Decrypted plaintext from ciphertext : ");
    print_as_hex_arr(decrypt_out);
    printf("\n");

}
