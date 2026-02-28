# ImplusOS | 重要事項

## まず初めに
- このリポジトリは将来的に削除または非公開になる可能性があります。
- ハードウェアやソフトウェアへの損害はサポート対象外です。
- 発生した損害は自己責任です。

## 現在の機能セット
- UEFI ブートローダーパス
- プロセスマネージャと syscall ディスパッチ
- FAT32 ファイル I/O syscall バックエンド
- PS/2 キーボード・マウス入力パス
- ウィンドウマネージャ描画 syscall
- PNG デコーダのユーザーランドサンプル
- 表示ドライバ: VirtIO GPU / Intel UHD Graphics 9th / 汎用フレームバッファ

## 現在の制約
- 動作確認は QEMU + OVMF を中心に行っています。
- 実機での動作は保証していません。
- USB / ネットワーク / オーディオドライバは未統合です。

## syscall エラー運用
- カーネル API は `os_status_t` を返します。
- 負の戻り値は失敗を示します。
- ユーザーランドラッパーは戻り値を維持しつつ `os_errno` を更新します。
- 対応表: `Docs/Architecture/Status_Codes.md`

## ドキュメント導線
- アーキテクチャ概要: `Docs/Architecture/Kernel_Architecture.md`
- 設定値ガイド: `Docs/Architecture/Kernel_Config_Guide.md`
- ステータスコード表: `Docs/Architecture/Status_Codes.md`
- API ドキュメント生成: `doxygen Doxyfile`

## ライセンス
- MIT ライセンスに従ってください。
- 配布後のサポートは行いません。
- MIT の範囲で自由に利用・改変・再配布できます。
