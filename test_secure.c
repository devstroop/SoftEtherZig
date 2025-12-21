#include <stdio.h>
#include <string.h>
#include <stdint.h>

// SHA-0 implementation
typedef struct SHA_CTX0 {
    uint32_t h[5];
    uint32_t block[16];
    size_t total_len;
    size_t block_len;
} SHA_CTX0;

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha0_init(SHA_CTX0 *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xc3d2e1f0;
    ctx->total_len = 0;
    ctx->block_len = 0;
}

static void sha0_process_block(SHA_CTX0 *ctx) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int i;
    
    for (i = 0; i < 16; i++) {
        w[i] = ctx->block[i];
    }
    
    // SHA-0 does NOT rotate in message schedule
    for (i = 16; i < 80; i++) {
        w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    
    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        
        uint32_t tmp = ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = tmp;
    }
    
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

static void sha0_update(SHA_CTX0 *ctx, const unsigned char *data, size_t len) {
    ctx->total_len += len;
    
    while (len > 0) {
        size_t block_offset = ctx->block_len;
        size_t byte_offset = block_offset % 4;
        size_t word_idx = block_offset / 4;
        
        if (byte_offset == 0) {
            ctx->block[word_idx] = 0;
        }
        
        ctx->block[word_idx] |= ((uint32_t)*data) << (24 - byte_offset * 8);
        
        ctx->block_len++;
        data++;
        len--;
        
        if (ctx->block_len == 64) {
            sha0_process_block(ctx);
            ctx->block_len = 0;
        }
    }
}

static void sha0_final(SHA_CTX0 *ctx, unsigned char *digest) {
    size_t total_bits = ctx->total_len * 8;
    
    unsigned char pad = 0x80;
    sha0_update(ctx, &pad, 1);
    
    while (ctx->block_len != 56) {
        pad = 0;
        sha0_update(ctx, &pad, 1);
    }
    
    unsigned char len_bytes[8] = {
        (total_bits >> 56) & 0xff,
        (total_bits >> 48) & 0xff,
        (total_bits >> 40) & 0xff,
        (total_bits >> 32) & 0xff,
        (total_bits >> 24) & 0xff,
        (total_bits >> 16) & 0xff,
        (total_bits >> 8) & 0xff,
        total_bits & 0xff
    };
    sha0_update(ctx, len_bytes, 8);
    
    for (int i = 0; i < 5; i++) {
        digest[i*4 + 0] = (ctx->h[i] >> 24) & 0xff;
        digest[i*4 + 1] = (ctx->h[i] >> 16) & 0xff;
        digest[i*4 + 2] = (ctx->h[i] >> 8) & 0xff;
        digest[i*4 + 3] = ctx->h[i] & 0xff;
    }
}

void sha0_hash(unsigned char *dst, const unsigned char *src, size_t size) {
    SHA_CTX0 ctx;
    sha0_init(&ctx);
    sha0_update(&ctx, src, size);
    sha0_final(&ctx, dst);
}

int main() {
    unsigned char password_hash[20];
    unsigned char server_random[20];
    unsigned char combined[40];
    unsigned char secure[20];
    
    const char *ph = "092f595c1aefb7d185be81d2bcdb947e13f8ae6c";
    const char *sr = "72cfa598ef66f8dd8c06d48159e61631e2595180";
    
    for (int i = 0; i < 20; i++) {
        unsigned int b;
        sscanf(ph + i*2, "%02x", &b);
        password_hash[i] = b;
        sscanf(sr + i*2, "%02x", &b);
        server_random[i] = b;
    }
    
    memcpy(combined, password_hash, 20);
    memcpy(combined + 20, server_random, 20);
    
    sha0_hash(secure, combined, 40);
    
    printf("Password hash: ");
    for (int i = 0; i < 20; i++) printf("%02x", password_hash[i]);
    printf("\n");
    
    printf("Server random: ");
    for (int i = 0; i < 20; i++) printf("%02x", server_random[i]);
    printf("\n");
    
    printf("Secure password (SHA-0): ");
    for (int i = 0; i < 20; i++) printf("%02x", secure[i]);
    printf("\n");
    
    return 0;
}
