#include <stdint.h>
#include <string.h>
#include "../../Syscalls.h"
#include "PNG_Decoder.h"

extern void* kmalloc(uint32_t size);
extern void kfree(void* ptr);

extern int zlib_decompress(const uint8_t* in, uint32_t in_len,
                           uint8_t* out, uint32_t* out_len);

#define PNG_CHUNK_IHDR 0x49484452u
#define PNG_CHUNK_PLTE 0x504C5445u
#define PNG_CHUNK_IDAT 0x49444154u
#define PNG_CHUNK_IEND 0x49454E44u
#define PNG_CHUNK_tRNS 0x74524E53u

#define DEFLATE_WINDOW_SIZE 32768

#define PNG_COLOR_GRAY       0
#define PNG_COLOR_RGB        2
#define PNG_COLOR_INDEXED    3
#define PNG_COLOR_GRAY_ALPHA 4
#define PNG_COLOR_RGBA       6

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t idat_total_size;
    uint8_t  bit_depth;
    uint8_t  color_type;
    uint8_t  has_ihdr;
    uint8_t  has_idat;
    uint8_t  has_plte;
    uint8_t  palette[256 * 3];
    uint32_t palette_count;
    uint8_t  trns[256];
    uint32_t trns_count;
    uint16_t trns_gray;
    uint16_t trns_r, trns_g, trns_b;
    uint8_t  has_trns;
} PNGMeta;

typedef struct {
    const uint8_t* data;
    uint32_t pos;
    uint32_t bit_pos;
    uint32_t size;
} BitReader;

typedef struct {
    uint8_t data[DEFLATE_WINDOW_SIZE];
    uint32_t pos;
} DeflateWindow;

static PNGDecodeStatus g_png_last_status = PNG_DECODE_OK;

static void png_set_status(PNGDecodeStatus status)
{
    g_png_last_status = status;
}

PNGDecodeStatus png_decoder_last_status(void)
{
    return g_png_last_status;
}

const char* png_decode_status_string(PNGDecodeStatus status)
{
    switch (status) {
    case PNG_DECODE_OK:                    return "ok";
    case PNG_DECODE_ERR_NULL_ARGUMENT:     return "null argument";
    case PNG_DECODE_ERR_BAD_SIGNATURE:     return "bad png signature";
    case PNG_DECODE_ERR_TRUNCATED_CHUNK:   return "truncated png chunk";
    case PNG_DECODE_ERR_INVALID_IHDR:      return "invalid ihdr";
    case PNG_DECODE_ERR_UNSUPPORTED_FORMAT:return "unsupported png format";
    case PNG_DECODE_ERR_MISSING_IHDR:      return "missing ihdr";
    case PNG_DECODE_ERR_MISSING_IDAT:      return "missing idat";
    case PNG_DECODE_ERR_MISSING_IEND:      return "missing iend";
    case PNG_DECODE_ERR_SIZE_OVERFLOW:     return "size overflow";
    case PNG_DECODE_ERR_OOM:               return "out of memory";
    case PNG_DECODE_ERR_ZLIB_UNSUPPORTED:  return "unsupported zlib stream";
    case PNG_DECODE_ERR_ZLIB_TRUNCATED:    return "truncated zlib stream";
    case PNG_DECODE_ERR_ZLIB_LEN_MISMATCH: return "zlib len mismatch";
    case PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH: return "decompressed size mismatch";
    case PNG_DECODE_ERR_BAD_FILTER:        return "unsupported png filter";
    default:                               return "unknown decode error";
    }
}

const char* png_decoder_last_status_string(void)
{
    return png_decode_status_string(g_png_last_status);
}

static void bit_reader_init(BitReader* br, const uint8_t* data, uint32_t size)
{
    br->data    = data;
    br->pos     = 0;
    br->bit_pos = 0;
    br->size    = size;
}

static int bit_reader_read(BitReader* br, uint32_t bits, uint32_t* out)
{
    uint32_t result = 0;
    uint32_t shift  = 0;

    if (bits > 32 || bits == 0) return -1;

    for (uint32_t i = 0; i < bits; i++) {
        if (br->pos >= br->size) return -1;
        uint32_t bit = (br->data[br->pos] >> br->bit_pos) & 1u;
        result |= (bit << shift);
        shift++;
        if (++br->bit_pos >= 8) { br->bit_pos = 0; br->pos++; }
    }
    *out = result;
    return 0;
}

static void bit_reader_align(BitReader* br)
{
    if (br->bit_pos != 0) { br->bit_pos = 0; br->pos++; }
}

static int inflate_uncompressed_block(BitReader* br, uint8_t* out,
                                      uint32_t* out_pos, uint32_t out_size)
{
    uint32_t len, nlen;
    bit_reader_align(br);
    if (br->pos + 4u > br->size) return -1;
    len  = br->data[br->pos] | ((uint32_t)br->data[br->pos + 1] << 8);
    nlen = br->data[br->pos + 2] | ((uint32_t)br->data[br->pos + 3] << 8);
    br->pos += 4;
    if ((uint16_t)(len ^ 0xFFFFu) != (uint16_t)nlen) return -1;
    if (br->pos + len > br->size)         return -1;
    if (*out_pos + len > out_size)        return -1;
    memcpy(out + *out_pos, br->data + br->pos, len);
    *out_pos += len;
    br->pos  += len;
    return 0;
}

static int build_huffman_table(const uint8_t* lengths, int code_count,
                               uint16_t* count, uint16_t* symbol, int* out_max_bits)
{
    uint16_t offsets[16];
    uint16_t sum = 0;
    memset(count, 0, sizeof(uint16_t) * 16u);
    *out_max_bits = 0;

    for (int i = 0; i < code_count; i++) {
        uint8_t len = lengths[i];
        if (len > 15u) return -1;
        if (len > 0u) {
            count[len]++;
            if ((int)len > *out_max_bits) *out_max_bits = (int)len;
        }
    }

    for (int bits = 1; bits <= 15; bits++) {
        offsets[bits] = sum;
        sum = (uint16_t)(sum + count[bits]);
    }

    for (int i = 0; i < code_count; i++) {
        uint8_t len = lengths[i];
        if (len > 0u) {
            symbol[offsets[len]++] = (uint16_t)i;
        }
    }
    return 0;
}

static int huffman_decode(BitReader* br, const uint16_t* count,
                          const uint16_t* symbol, int max_bits)
{
    uint32_t code  = 0;
    uint32_t first = 0;
    uint32_t index = 0;

    for (int bits = 1; bits <= max_bits; bits++) {
        uint32_t bit = 0;
        if (bit_reader_read(br, 1, &bit) != 0) return -1;

        code |= bit;
        if (code < first + count[bits]) {
            return symbol[index + (code - first)];
        }

        index += count[bits];
        first += count[bits];
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static int get_length_value(int symbol, uint32_t* base, uint32_t* extra_bits)
{
    static const uint32_t tbl_base[29] = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,
        35,43,51,59,67,83,99,115,131,163,195,227,258
    };
    static const uint32_t tbl_extra[29] = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
        3,3,3,3,4,4,4,4,5,5,5,5,0
    };
    if (symbol < 257 || symbol > 285) return -1;
    *base       = tbl_base[symbol - 257];
    *extra_bits = tbl_extra[symbol - 257];
    return 0;
}

static int get_distance_value(int symbol, uint32_t* base, uint32_t* extra_bits)
{
    if (symbol < 0 || symbol >= 30) return -1;
    if (symbol <= 3) {
        *base = (uint32_t)symbol + 1; *extra_bits = 0;
    } else {
        int pair = (symbol - 4) / 2;
        *extra_bits = (uint32_t)(pair + 1);
        *base = (1u << (*extra_bits + 1)) + 1u + (uint32_t)((symbol - 4) % 2) * (1u << *extra_bits);
    }
    return 0;
}

static int inflate_lz_loop(BitReader* br,
                            const uint16_t* lit_count, const uint16_t* lit_symbol, int lit_max,
                            const uint16_t* dst_count, const uint16_t* dst_symbol, int dst_max,
                            uint8_t* out, uint32_t* out_pos, uint32_t out_size)
{
    while (*out_pos < out_size) {
        int lit = huffman_decode(br, lit_count, lit_symbol, lit_max);
        if (lit < 0) return -1;

        if (lit < 256) {
            if (*out_pos >= out_size) return -1;
            out[(*out_pos)++] = (uint8_t)lit;
        } else if (lit == 256) {
            return 0;
        } else if (lit <= 285) {
            uint32_t length_base = 0, length_extra = 0;
            if (get_length_value(lit, &length_base, &length_extra) != 0) return -1;
            uint32_t length = length_base;
            if (length_extra > 0) {
                uint32_t ex = 0;
                if (bit_reader_read(br, length_extra, &ex) != 0) return -1;
                length += ex;
            }
            int dist_code = huffman_decode(br, dst_count, dst_symbol, dst_max);
            if (dist_code < 0) return -1;
            uint32_t dist_base = 0, dist_extra = 0;
            if (get_distance_value(dist_code, &dist_base, &dist_extra) != 0) return -1;
            uint32_t distance = dist_base;
            if (dist_extra > 0) {
                uint32_t ex = 0;
                if (bit_reader_read(br, dist_extra, &ex) != 0) return -1;
                distance += ex;
            }
            if (distance > DEFLATE_WINDOW_SIZE || distance > *out_pos) return -1;
            for (uint32_t i = 0; i < length; i++) {
                if (*out_pos >= out_size) return -1;
                out[*out_pos] = out[*out_pos - distance];
                (*out_pos)++;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

static int inflate_fixed_huffman_block(BitReader* br, uint8_t* out,
                                       uint32_t* out_pos, uint32_t out_size)
{
    uint8_t  lit_lengths[288], dist_lengths[32];
    uint16_t lit_count[16],    dist_count[16];
    uint16_t lit_symbol[288],  dist_symbol[32];
    int lit_max = 0, dist_max = 0;

    memset(lit_lengths, 0, sizeof(lit_lengths));
    for (int i = 0;   i <= 143; i++) lit_lengths[i] = 8;
    for (int i = 144; i <= 255; i++) lit_lengths[i] = 9;
    for (int i = 256; i <= 279; i++) lit_lengths[i] = 7;
    for (int i = 280; i <= 287; i++) lit_lengths[i] = 8;
    for (int i = 0;   i <  32;  i++) dist_lengths[i] = 5;

    if (build_huffman_table(lit_lengths,  288, lit_count,  lit_symbol,  &lit_max)  != 0) return -1;
    if (build_huffman_table(dist_lengths, 32,  dist_count, dist_symbol, &dist_max) != 0) return -1;

    return inflate_lz_loop(br,
        lit_count,  lit_symbol,  lit_max,
        dist_count, dist_symbol, dist_max,
        out, out_pos, out_size);
}

static int inflate_dynamic_huffman_block(BitReader* br, uint8_t* out,
                                         uint32_t* out_pos, uint32_t out_size)
{
    static const int clen_order[19] = {
        16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
    };
    uint32_t hlit = 0, hdist = 0, hclen = 0;
    uint8_t  code_lengths[19], lit_lengths[288], dist_lengths[32];
    uint16_t clen_count[16],   lit_count[16],    dist_count[16];
    uint16_t clen_symbol[19],  lit_symbol[288],  dist_symbol[32];
    int clen_max = 0, lit_max = 0, dist_max = 0;

    if (bit_reader_read(br, 5, &hlit)  != 0) return -1;
    if (bit_reader_read(br, 5, &hdist) != 0) return -1;
    if (bit_reader_read(br, 4, &hclen) != 0) return -1;
    hlit += 257; hdist += 1; hclen += 4;
    if (hlit > 286 || hdist > 32 || hclen > 19) return -1;

    memset(code_lengths, 0, sizeof(code_lengths));
    for (int i = 0; i < (int)hclen; i++) {
        uint32_t len = 0;
        if (bit_reader_read(br, 3, &len) != 0) return -1;
        code_lengths[clen_order[i]] = (uint8_t)len;
    }
    if (build_huffman_table(code_lengths, 19, clen_count, clen_symbol, &clen_max) != 0) return -1;

    memset(lit_lengths,  0, sizeof(lit_lengths));
    memset(dist_lengths, 0, sizeof(dist_lengths));

    int i = 0;
    while (i < (int)(hlit + hdist)) {
        int symbol = huffman_decode(br, clen_count, clen_symbol, clen_max);
        if (symbol < 0) return -1;

        if (symbol < 16) {
            if (i < (int)hlit) lit_lengths[i] = (uint8_t)symbol;
            else               dist_lengths[i - hlit] = (uint8_t)symbol;
            i++;
        } else {
            uint32_t rep = 0;
            uint8_t  val = 0;
            if (symbol == 16) {
                if (i == 0) return -1;
                if (bit_reader_read(br, 2, &rep) != 0) return -1;
                rep += 3;
                val = ((uint32_t)i <= hlit) ? lit_lengths[i - 1] : dist_lengths[i - (int)hlit - 1];
            } else if (symbol == 17) {
                if (bit_reader_read(br, 3, &rep) != 0) return -1;
                rep += 3; val = 0;
            } else if (symbol == 18) {
                if (bit_reader_read(br, 7, &rep) != 0) return -1;
                rep += 11; val = 0;
            } else return -1;
            if (rep > (uint32_t)((int)(hlit + hdist) - i)) return -1;
            while (rep > 0) {
                if (i < (int)hlit) lit_lengths[i] = val;
                else               dist_lengths[i - hlit] = val;
                i++; rep--;
            }
        }
    }

    if (build_huffman_table(lit_lengths,  288, lit_count,  lit_symbol,  &lit_max)  != 0) return -1;
    if (build_huffman_table(dist_lengths, 32,  dist_count, dist_symbol, &dist_max) != 0) return -1;

    return inflate_lz_loop(br,
        lit_count,  lit_symbol,  lit_max,
        dist_count, dist_symbol, dist_max,
        out, out_pos, out_size);
}

int zlib_decompress(const uint8_t* in, uint32_t in_len,
                    uint8_t* out, uint32_t* out_len)
{
    BitReader br;
    uint32_t out_pos    = 0;
    uint32_t max_out    = *out_len;
    int      final_block = 0;

    if (!in || !out || !out_len) return -1;
    bit_reader_init(&br, in, in_len);

    while (!final_block) {
        uint32_t bfinal = 0, btype = 0;
        if (bit_reader_read(&br, 1, &bfinal) != 0) return -1;
        if (bit_reader_read(&br, 2, &btype)  != 0) return -1;
        final_block = (bfinal == 1);

        int res;
        if      (btype == 0) res = inflate_uncompressed_block(&br, out, &out_pos, max_out);
        else if (btype == 1) res = inflate_fixed_huffman_block(&br, out, &out_pos, max_out);
        else if (btype == 2) res = inflate_dynamic_huffman_block(&br, out, &out_pos, max_out);
        else return -1;
        if (res != 0) return -1;
    }
    *out_len = out_pos;
    return 0;
}

static uint32_t read_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint16_t read_be16(const uint8_t* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static int add_u32_checked(uint32_t a, uint32_t b, uint32_t* out)
{
    if (a > UINT32_MAX - b) return 0;
    *out = a + b; return 1;
}

static int mul_u64_checked(uint64_t a, uint64_t b, uint64_t* out)
{
    if (a != 0 && b > UINT64_MAX / a) return 0;
    *out = a * b; return 1;
}

static int png_channels(uint8_t color_type)
{
    switch (color_type) {
    case PNG_COLOR_GRAY:       return 1;
    case PNG_COLOR_RGB:        return 3;
    case PNG_COLOR_INDEXED:    return 1;
    case PNG_COLOR_GRAY_ALPHA: return 2;
    case PNG_COLOR_RGBA:       return 4;
    default: return -1;
    }
}

static int png_valid_bit_depth(uint8_t color_type, uint8_t bit_depth)
{
    switch (color_type) {
    case PNG_COLOR_GRAY:
        return (bit_depth == 1 || bit_depth == 2 || bit_depth == 4 ||
                bit_depth == 8 || bit_depth == 16);
    case PNG_COLOR_RGB:
    case PNG_COLOR_GRAY_ALPHA:
    case PNG_COLOR_RGBA:
        return (bit_depth == 8 || bit_depth == 16);
    case PNG_COLOR_INDEXED:
        return (bit_depth == 1 || bit_depth == 2 ||
                bit_depth == 4 || bit_depth == 8);
    default: return 0;
    }
}

static uint32_t png_bpp(uint8_t color_type, uint8_t bit_depth)
{
    int ch = png_channels(color_type);
    if (ch < 0) return 1;
    uint32_t bits = (uint32_t)ch * (uint32_t)bit_depth;
    return (bits + 7u) / 8u;
}

static uint32_t png_scanline_bytes(uint32_t width, uint8_t color_type, uint8_t bit_depth)
{
    int ch = png_channels(color_type);
    if (ch < 0) return 0;
    uint64_t bits = (uint64_t)width * (uint32_t)ch * (uint32_t)bit_depth;
    return (uint32_t)((bits + 7u) / 8u);
}

static int png_parse_meta(const uint8_t* buffer, uint64_t size, PNGMeta* meta)
{
    const uint8_t* p   = buffer + 8;
    const uint8_t* end = buffer + size;

    memset(meta, 0, sizeof(*meta));

    while (p < end) {
        if ((uint64_t)(end - p) < 8u) {
            png_set_status(PNG_DECODE_ERR_TRUNCATED_CHUNK); return 0;
        }
        uint32_t len  = read_be32(p); p += 4;
        uint32_t type = read_be32(p); p += 4;

        if ((uint64_t)(end - p) < (uint64_t)len + 4u) {
            png_set_status(PNG_DECODE_ERR_TRUNCATED_CHUNK); return 0;
        }

        if (type == PNG_CHUNK_IHDR) {
            if (len < 13u || meta->has_ihdr) {
                png_set_status(PNG_DECODE_ERR_INVALID_IHDR); return 0;
            }
            meta->width      = read_be32(p);
            meta->height     = read_be32(p + 4);
            meta->bit_depth  = p[8];
            meta->color_type = p[9];

            if (meta->width == 0u || meta->height == 0u) {
                png_set_status(PNG_DECODE_ERR_INVALID_IHDR); return 0;
            }

            if (p[10] != 0u || p[11] != 0u) {
                png_set_status(PNG_DECODE_ERR_UNSUPPORTED_FORMAT); return 0;
            }

            if (p[12] != 0u) {
                png_set_status(PNG_DECODE_ERR_UNSUPPORTED_FORMAT); return 0;
            }
            if (png_channels(meta->color_type) < 0 ||
                !png_valid_bit_depth(meta->color_type, meta->bit_depth)) {
                png_set_status(PNG_DECODE_ERR_UNSUPPORTED_FORMAT); return 0;
            }
            meta->has_ihdr = 1;

        } else if (type == PNG_CHUNK_PLTE) {
            if (!meta->has_ihdr || len == 0u || len % 3u != 0u || len > 768u) {
                png_set_status(PNG_DECODE_ERR_INVALID_IHDR); return 0;
            }
            meta->palette_count = len / 3u;
            memcpy(meta->palette, p, len);

            memset(meta->trns, 0xFF, sizeof(meta->trns));
            meta->has_plte = 1;

        } else if (type == PNG_CHUNK_tRNS) {
            if (!meta->has_ihdr) {
                png_set_status(PNG_DECODE_ERR_INVALID_IHDR); return 0;
            }
            meta->has_trns = 1;
            if (meta->color_type == PNG_COLOR_INDEXED) {
                uint32_t cnt = (len < 256u) ? len : 256u;
                for (uint32_t i = 0; i < cnt; i++) meta->trns[i] = p[i];
                meta->trns_count = cnt;
            } else if (meta->color_type == PNG_COLOR_GRAY) {
                if (len >= 2u) meta->trns_gray = read_be16(p);
            } else if (meta->color_type == PNG_COLOR_RGB) {
                if (len >= 6u) {
                    meta->trns_r = read_be16(p);
                    meta->trns_g = read_be16(p + 2);
                    meta->trns_b = read_be16(p + 4);
                }
            }

        } else if (type == PNG_CHUNK_IDAT) {
            if (!meta->has_ihdr) {
                png_set_status(PNG_DECODE_ERR_INVALID_IHDR); return 0;
            }
            uint32_t next;
            if (!add_u32_checked(meta->idat_total_size, len, &next)) {
                png_set_status(PNG_DECODE_ERR_SIZE_OVERFLOW); return 0;
            }
            meta->idat_total_size = next;
            meta->has_idat = 1;

        } else if (type == PNG_CHUNK_IEND) {
            if (!meta->has_ihdr) { png_set_status(PNG_DECODE_ERR_MISSING_IHDR); return 0; }
            if (!meta->has_idat) { png_set_status(PNG_DECODE_ERR_MISSING_IDAT); return 0; }
            return 1;
        }

        p += (uint64_t)len + 4u;
    }

    png_set_status(PNG_DECODE_ERR_MISSING_IEND);
    return 0;
}

static int png_copy_idat(const uint8_t* buffer, uint64_t size,
                         uint8_t* out, uint32_t out_size)
{
    const uint8_t* p       = buffer + 8;
    const uint8_t* end     = buffer + size;
    uint32_t       written = 0;

    while (p < end) {
        if ((uint64_t)(end - p) < 8u) {
            png_set_status(PNG_DECODE_ERR_TRUNCATED_CHUNK); return 0;
        }
        uint32_t len  = read_be32(p); p += 4;
        uint32_t type = read_be32(p); p += 4;
        if ((uint64_t)(end - p) < (uint64_t)len + 4u) {
            png_set_status(PNG_DECODE_ERR_TRUNCATED_CHUNK); return 0;
        }
        if (type == PNG_CHUNK_IDAT) {
            if ((uint64_t)written + (uint64_t)len > (uint64_t)out_size) {
                png_set_status(PNG_DECODE_ERR_SIZE_OVERFLOW); return 0;
            }
            memcpy(out + written, p, len);
            written += len;
        } else if (type == PNG_CHUNK_IEND) {
            break;
        }
        p += (uint64_t)len + 4u;
    }

    if (written != out_size) {
        png_set_status(PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH); return 0;
    }
    return 1;
}

static int png_unfilter(uint8_t* data, uint32_t data_size,
                        uint32_t width, uint32_t height,
                        uint8_t color_type, uint8_t bit_depth)
{
    uint32_t stride  = png_scanline_bytes(width, color_type, bit_depth);
    uint32_t scanline = stride + 1u;
    uint32_t bpp     = png_bpp(color_type, bit_depth);

    if ((uint64_t)scanline * (uint64_t)height != (uint64_t)data_size) {
        png_set_status(PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH); return 0;
    }

    uint8_t* prev = NULL;
    uint8_t* cur  = data;

    for (uint32_t y = 0; y < height; y++) {
        uint8_t  filter = cur[0];
        uint8_t* row    = cur + 1;

        switch (filter) {
        case 0:
            break;
        case 1:
            for (uint32_t x = bpp; x < stride; x++)
                row[x] = (uint8_t)(row[x] + row[x - bpp]);
            break;
        case 2:
            if (prev)
                for (uint32_t x = 0; x < stride; x++)
                    row[x] = (uint8_t)(row[x] + prev[x]);
            break;
        case 3:
            for (uint32_t x = 0; x < stride; x++) {
                uint8_t left = (x >= bpp) ? row[x - bpp] : 0;
                uint8_t up   = prev ? prev[x] : 0;
                row[x] = (uint8_t)(row[x] + ((left + up) / 2));
            }
            break;
        case 4:
            for (uint32_t x = 0; x < stride; x++) {
                uint8_t a = (x >= bpp) ? row[x - bpp] : 0;
                uint8_t b = prev ? prev[x] : 0;
                uint8_t c = (x >= bpp && prev) ? prev[x - bpp] : 0;
                int p2  = (int)a + (int)b - (int)c;
                int pa = p2 - (int)a; if (pa < 0) pa = -pa;
                int pb = p2 - (int)b; if (pb < 0) pb = -pb;
                int pc = p2 - (int)c; if (pc < 0) pc = -pc;
                uint8_t pr = (pa <= pb && pa <= pc) ? a : ((pb <= pc) ? b : c);
                row[x] = (uint8_t)(row[x] + pr);
            }
            break;
        default:
            png_set_status(PNG_DECODE_ERR_BAD_FILTER); return 0;
        }
        prev = row;
        cur += scanline;
    }
    return 1;
}

static uint8_t* zlib_decompress_png(const uint8_t* data, uint32_t size,
                                    uint32_t expected_size, uint32_t* out_size)
{
    if (!data || !out_size) {
        png_set_status(PNG_DECODE_ERR_NULL_ARGUMENT); return NULL;
    }
    if (size < 2u) {
        png_set_status(PNG_DECODE_ERR_ZLIB_TRUNCATED); return NULL;
    }
    if (expected_size == 0u) {
        png_set_status(PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH); return NULL;
    }

    uint8_t cmf = data[0];
    uint8_t flg = data[1];
    uint32_t pos = 2u;

    if ((cmf & 0x0Fu) != 8u) {
        png_set_status(PNG_DECODE_ERR_ZLIB_UNSUPPORTED); return NULL;
    }
    if ((((uint32_t)cmf << 8) | (uint32_t)flg) % 31u != 0u) {
        png_set_status(PNG_DECODE_ERR_ZLIB_UNSUPPORTED); return NULL;
    }
    if (flg & 0x20u) {
        if (pos + 4u > size) {
            png_set_status(PNG_DECODE_ERR_ZLIB_TRUNCATED); return NULL;
        }
        pos += 4u;
    }

    uint32_t decomp_size = expected_size;
    uint8_t* out = kmalloc(decomp_size);
    if (!out) { png_set_status(PNG_DECODE_ERR_OOM); return NULL; }

    if (zlib_decompress(data + pos, size - pos, out, &decomp_size) != 0) {
        kfree(out);
        png_set_status(PNG_DECODE_ERR_ZLIB_UNSUPPORTED);
        return NULL;
    }
    *out_size = decomp_size;
    return out;
}

static uint8_t png_scale_to_8(uint8_t val, uint8_t bit_depth)
{
    if (bit_depth == 8)  return val;
    if (bit_depth == 16) return val;
    uint32_t max = (1u << bit_depth) - 1u;
    return (uint8_t)((uint32_t)val * 255u / max);
}

static void convert_row_to_rgba(
    const uint8_t* src,
    uint32_t* dst,
    uint32_t width,
    uint8_t color_type,
    uint8_t bit_depth,
    const PNGMeta* meta)
{
    for (uint32_t x = 0; x < width; x++) {
        uint8_t r = 0, g = 0, b = 0, a = 0xFF;

        switch (color_type) {
        case PNG_COLOR_GRAY: {
            uint8_t gray;
            if (bit_depth == 16) {
                uint16_t raw = (uint16_t)(src[x * 2] << 8 | src[x * 2 + 1]);
                gray = (uint8_t)(raw >> 8);
                if (meta->has_trns && raw == meta->trns_gray) a = 0;
            } else if (bit_depth == 8) {
                gray = src[x];
                if (meta->has_trns && gray == (uint8_t)meta->trns_gray) a = 0;
            } else {
                uint32_t bits_per_pix = bit_depth;
                uint32_t pix_per_byte = 8u / bits_per_pix;
                uint32_t byte_idx     = x / pix_per_byte;
                uint32_t bit_shift    = (pix_per_byte - 1u - (x % pix_per_byte)) * bits_per_pix;
                uint8_t  mask         = (uint8_t)((1u << bits_per_pix) - 1u);
                uint8_t  raw          = (src[byte_idx] >> bit_shift) & mask;
                gray = png_scale_to_8(raw, bit_depth);
                if (meta->has_trns && raw == (uint8_t)meta->trns_gray) a = 0;
            }
            r = g = b = gray;
            break;
        }
        case PNG_COLOR_RGB: {
            if (bit_depth == 16) {
                r = src[x * 6 + 0];
                g = src[x * 6 + 2];
                b = src[x * 6 + 4];
                if (meta->has_trns) {
                    uint16_t rv = (uint16_t)(src[x*6]   << 8 | src[x*6+1]);
                    uint16_t gv = (uint16_t)(src[x*6+2] << 8 | src[x*6+3]);
                    uint16_t bv = (uint16_t)(src[x*6+4] << 8 | src[x*6+5]);
                    if (rv == meta->trns_r && gv == meta->trns_g && bv == meta->trns_b) a = 0;
                }
            } else {
                r = src[x * 3 + 0];
                g = src[x * 3 + 1];
                b = src[x * 3 + 2];
                if (meta->has_trns &&
                    r == (uint8_t)meta->trns_r &&
                    g == (uint8_t)meta->trns_g &&
                    b == (uint8_t)meta->trns_b) a = 0;
            }
            break;
        }
        case PNG_COLOR_INDEXED: {
            uint8_t idx;
            if (bit_depth == 8) {
                idx = src[x];
            } else {
                uint32_t pix_per_byte = 8u / (uint32_t)bit_depth;
                uint32_t byte_idx     = x / pix_per_byte;
                uint32_t bit_shift    = (pix_per_byte - 1u - (x % pix_per_byte)) * (uint32_t)bit_depth;
                uint8_t  mask         = (uint8_t)((1u << (uint32_t)bit_depth) - 1u);
                idx = (src[byte_idx] >> bit_shift) & mask;
            }
            if ((uint32_t)idx < meta->palette_count) {
                r = meta->palette[idx * 3 + 0];
                g = meta->palette[idx * 3 + 1];
                b = meta->palette[idx * 3 + 2];
                a = (meta->has_trns && (uint32_t)idx < meta->trns_count)
                    ? meta->trns[idx] : 0xFF;
            }
            break;
        }
        case PNG_COLOR_GRAY_ALPHA: {
            if (bit_depth == 16) {
                r = g = b = src[x * 4 + 0];
                a = src[x * 4 + 2];
            } else {
                r = g = b = src[x * 2 + 0];
                a = src[x * 2 + 1];
            }
            break;
        }
        case PNG_COLOR_RGBA: {
            if (bit_depth == 16) {
                r = src[x * 8 + 0];
                g = src[x * 8 + 2];
                b = src[x * 8 + 4];
                a = src[x * 8 + 6];
            } else {
                r = src[x * 4 + 0];
                g = src[x * 4 + 1];
                b = src[x * 4 + 2];
                a = src[x * 4 + 3];
            }
            break;
        }
        }

        dst[x] = ((uint32_t)r) |
                 ((uint32_t)g << 8)  |
                 ((uint32_t)b << 16) |
                 ((uint32_t)a << 24);
    }
}

uint32_t* png_decode_buffer(
    const uint8_t* buffer,
    uint64_t size,
    uint32_t* out_w,
    uint32_t* out_h)
{
    static const uint8_t sig[8] = {137,80,78,71,13,10,26,10};
    PNGMeta   meta;
    uint8_t*  idat_data   = NULL;
    uint8_t*  decomp      = NULL;
    uint32_t* out         = NULL;
    uint32_t  decomp_size = 0;

    if (out_w) *out_w = 0;
    if (out_h) *out_h = 0;
    png_set_status(PNG_DECODE_OK);

    if (!buffer || !out_w || !out_h) {
        png_set_status(PNG_DECODE_ERR_NULL_ARGUMENT); return NULL;
    }
    if (size < 8u || memcmp(buffer, sig, 8u) != 0) {
        png_set_status(PNG_DECODE_ERR_BAD_SIGNATURE); return NULL;
    }
    if (!png_parse_meta(buffer, size, &meta)) return NULL;
    if (meta.idat_total_size == 0u) {
        png_set_status(PNG_DECODE_ERR_MISSING_IDAT); return NULL;
    }
    if (meta.color_type == PNG_COLOR_INDEXED && !meta.has_plte) {
        png_set_status(PNG_DECODE_ERR_UNSUPPORTED_FORMAT); return NULL;
    }

    uint32_t stride   = png_scanline_bytes(meta.width, meta.color_type, meta.bit_depth);
    uint64_t expected = (uint64_t)(stride + 1u) * (uint64_t)meta.height;
    if (expected == 0u || expected > UINT32_MAX) {
        png_set_status(PNG_DECODE_ERR_SIZE_OVERFLOW); return NULL;
    }

    uint64_t out_bytes;
    if (!mul_u64_checked((uint64_t)meta.width, (uint64_t)meta.height, &out_bytes) ||
        !mul_u64_checked(out_bytes, 4u, &out_bytes) ||
        out_bytes == 0u || out_bytes > UINT32_MAX) {
        png_set_status(PNG_DECODE_ERR_SIZE_OVERFLOW); return NULL;
    }

    idat_data = kmalloc(meta.idat_total_size);
    if (!idat_data) { png_set_status(PNG_DECODE_ERR_OOM); return NULL; }
    if (!png_copy_idat(buffer, size, idat_data, meta.idat_total_size)) {
        kfree(idat_data); return NULL;
    }

    decomp = zlib_decompress_png(idat_data, meta.idat_total_size, (uint32_t)expected, &decomp_size);
    kfree(idat_data);
    if (!decomp) return NULL;

    if ((uint64_t)decomp_size != expected) {
        png_set_status(PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH);
        kfree(decomp); return NULL;
    }

    if (!png_unfilter(decomp, decomp_size, meta.width, meta.height,
                      meta.color_type, meta.bit_depth)) {
        kfree(decomp); return NULL;
    }

    out = kmalloc((uint32_t)out_bytes);
    if (!out) { png_set_status(PNG_DECODE_ERR_OOM); kfree(decomp); return NULL; }

    {
        uint32_t scanline = stride + 1u;
        uint8_t* src = decomp;
        for (uint32_t y = 0; y < meta.height; y++) {
            convert_row_to_rgba(src + 1, out + (uint64_t)y * meta.width,
                                meta.width, meta.color_type, meta.bit_depth, &meta);
            src += scanline;
        }
    }

    kfree(decomp);
    *out_w = meta.width;
    *out_h = meta.height;
    png_set_status(PNG_DECODE_OK);
    return out;
}
