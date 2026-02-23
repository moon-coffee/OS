#ifndef PNG_DECODER_H
#define PNG_DECODER_H

#include <stdint.h>

typedef enum {
    PNG_DECODE_OK = 0,
    PNG_DECODE_ERR_NULL_ARGUMENT,
    PNG_DECODE_ERR_BAD_SIGNATURE,
    PNG_DECODE_ERR_TRUNCATED_CHUNK,
    PNG_DECODE_ERR_INVALID_IHDR,
    PNG_DECODE_ERR_UNSUPPORTED_FORMAT,
    PNG_DECODE_ERR_MISSING_IHDR,
    PNG_DECODE_ERR_MISSING_IDAT,
    PNG_DECODE_ERR_MISSING_IEND,
    PNG_DECODE_ERR_SIZE_OVERFLOW,
    PNG_DECODE_ERR_OOM,
    PNG_DECODE_ERR_ZLIB_UNSUPPORTED,
    PNG_DECODE_ERR_ZLIB_TRUNCATED,
    PNG_DECODE_ERR_ZLIB_LEN_MISMATCH,
    PNG_DECODE_ERR_DECOMP_SIZE_MISMATCH,
    PNG_DECODE_ERR_BAD_FILTER,
} PNGDecodeStatus;

uint32_t* png_decode_buffer(
    const uint8_t* buffer,
    uint64_t size,
    uint32_t* out_w,
    uint32_t* out_h);
PNGDecodeStatus png_decoder_last_status(void);
const char* png_decode_status_string(PNGDecodeStatus status);
const char* png_decoder_last_status_string(void);

#endif