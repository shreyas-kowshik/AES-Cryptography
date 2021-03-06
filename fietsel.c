/*
Shreyas Kowshik
17MA20039

Only Fietsel implementation for 128-bit message and 128-bit key
*/

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>



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

// const uint8_t invfietsel_sbox[256] = {
//   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
//   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
//   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
//   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
//   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
//   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
//   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
//   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
//   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
//   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
//   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
//   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
//   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
//   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
//   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

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

    printf("Malloc done\n");

    for(round=0;round<rounds;round++) {
        printf("%d\n", round);

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

    // printf("Expanded Key 0 : "); print_as_hex_arr(expanded_in); printf("\n");

    int i;
    for(i=0;i<16;i++) expanded_in[i]=expanded_in[i]^key[i];
    // printf("Expanded Key 1 : "); print_as_hex_arr(expanded_in); printf("\n");

    // apply sbox and reduce down to 8 bytes
    for(i=0;i<16;i++) expanded_in[i]=fietsel_sbox[expanded_in[i]];
    // printf("Expanded Key 2 : "); print_as_hex_arr(expanded_in); printf("\n");

    for(i=0;i<16;i+=2) expanded_in[i]=(expanded_in[i]<<4)^(expanded_in[i+1]&15);
    // printf("Expanded Key 3 : "); print_as_hex_arr(expanded_in); printf("\n");

    for(i=0;i<8;i++) in[i]=expanded_in[2*i];

    // printf("After expanded key 3 in : "); print_as_hex_arr64(in); printf("\n");

    // apply permutation
    permute(in);
    // printf("After permutation in : "); print_as_hex_arr64(in); printf("\n");
}


void encrypt(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds) {
    uint8_t** keys = keyScheduler(key, rounds);

    printf("Printing key schedule : ");

    int round;
    int i;
    for(i=0;i<rounds;i++) {
        print_as_hex_arr(keys[i]);
        printf("\n---");
    }

    for(i=0;i<16;i++) out[i]=in[i]; // copy initial input to output

    printf("Input copying done\n");

    for(round=0;round<rounds;round++) {
        printf("%d\n", round);
        print_as_hex_arr(out);
        // printf("\n---\n");
        // fietsel cipher


        // split input
        uint8_t L[8];
        uint8_t R[8];
        for(i=0;i<8;i++) L[i]=out[i];
        for(i=8;i<16;i++) R[i-8]=out[i];
        // printf("L : "); print_as_hex_arr64(L); printf("\n");
        // printf("R : "); print_as_hex_arr64(R); printf("\n");

        fietsel_f(R, keys[round]); // R is now updated to new values
        // printf("After fietsel L : "); print_as_hex_arr64(L); printf("\n");
        // printf("After fietsel R : "); print_as_hex_arr64(R); printf("\n");

        for(i=0;i<8;i++) out[i]=out[i+8]; // copy original R
        for(i=8;i<16;i++) {
            out[i]=L[i-8]^R[i-8];
            // printf("%d %d %d %d\n", i, L[i-8], R[i-8], out[i]);
        }

        printf("Out at end : "); print_as_hex_arr(out); printf("\n");
        printf("\n---\n");
    }

    printf("Coming out\n");
}

void decrypt(uint8_t in[16], uint8_t key[16], uint8_t out[16], int rounds) {
    uint8_t** keys = keyScheduler(key, rounds);
    int round;
    int i;
    for(i=0;i<16;i++) out[i]=in[i]; // copy initial input to output

    printf("Input copying done\n");

    for(round=rounds-1;round>=0;round--) {
        printf("%d\n", round);
        print_as_hex_arr(out);
        // fietsel cipher


        // split input
        uint8_t L[8];
        uint8_t R[8];
        for(i=0;i<8;i++) L[i]=out[i];
        for(i=8;i<16;i++) R[i-8]=out[i];
        // printf("L : "); print_as_hex_arr64(L); printf("\n");
        // printf("R : "); print_as_hex_arr64(R); printf("\n");


        fietsel_f(L, keys[round]); // L is now updated to new values
        // printf("After fietsel L : "); print_as_hex_arr64(L); printf("\n");
        // printf("After fietsel R : "); print_as_hex_arr64(R); printf("\n");
        for(i=8;i<16;i++) out[i]=out[i-8];
        for(i=0;i<8;i++) out[i]=L[i]^R[i];

        printf("Out at end : "); print_as_hex_arr(out); printf("\n");

        printf("\n---\n");
    }

    printf("Coming out\n");
}

int main() {
    

    /*
    Tests
    */
    // Expansion test
    // uint8_t in[8]={0, 1, 2, 3, 4, 5, 6, 7};
    // uint8_t *exp_in=Expansion(in);
    // print_as_hex_arr(exp_in);

    // keyScheduler test
    // uint8_t key[16] = {
    //     0x00,
    //     0x01,
    //     0x02,
    //     0x03,
    //     0x04,
    //     0x05,
    //     0x05,
    //     0x04,
    //     0x03,
    //     0x02,
    //     0x01,
    //     0x02,
    //     0x01,
    //     0x02,
    //     0x03,
    //     0x02
    // };
    // int rounds=5;
    // int i;

    // uint8_t** keys=keyScheduler(key, rounds);
    // for(i=0;i<rounds;i++) {
    //     print_as_hex_arr(keys[i]);
    //     printf("\n---");
    // }



    // encryption test
    uint8_t in[16] = {
        0x01,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x06,
        0x00,
        0x07,
        0x00,
        0x00,
        0x09,
        0x00
    };

    uint8_t key[16] = {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x05,
        0x04,
        0x05,
        0x02,
        0x01,
        0x02,
        0x07,
        0x02,
        0x03,
        0x02
    };

    uint8_t out[16];

    int rounds=5;
    encrypt(in, key, out, rounds);

    print_as_hex_arr(in);
    printf("\n");
    print_as_hex_arr(key);
    printf("\n");
    print_as_hex_arr(out);
    printf("\n");

    printf("---\n");
    uint8_t dec_out[16];
    decrypt(out, key, dec_out, rounds);

    print_as_hex_arr(out);
    printf("\n");
    print_as_hex_arr(key);
    printf("\n");
    print_as_hex_arr(dec_out);
    printf("\n");

    return 0;
}