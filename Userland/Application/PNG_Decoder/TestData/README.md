# PNG Decoder Test Data

- `valid_1x1_rgba.png`
  - 1x1 RGBA PNG (正常系)
  - 期待結果: `png_decode_buffer` が成功し、1x1画像を返す
- `invalid_crc_1x1_rgba.png`
  - `IDAT` チャンクCRCを意図的に破壊したPNG (異常系)
  - 期待結果: `png_decode_buffer` が失敗し、`PNG_DECODE_ERR_BAD_CRC` を返す
