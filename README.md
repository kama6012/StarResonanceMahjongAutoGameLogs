# StarResonanceMahjongAutoAna

Star Resonance Mahjongの対局通信から卓状態を復元し、Windows GUIへリアルタイム表示するオープンソースの追跡ツールです。

> [!IMPORTANT]
> 本プロジェクトは非公式であり、ゲームの開発元・運営元とは関係ありません。ゲーム名などの商標は各権利者に帰属します。
> また本リポジトリはAI Slopであり、この一文以外の全コードはフォーク元かCodexから出力されたものです。

## できること

- 自分の手牌（赤牌を区別）と副露を表示
- 4人分の河・副露・点数・席風・立直状態を表示
- 自席・親・現在手番を表示
- 東場の局数・本場・供託・ドラ表示牌を表示
- 復元した卓状態を1ゲーム1ファイルのJSON牌譜として保存
- TCP再送・重複・順序逆転をsequence番号で整列

本ツールは打牌解析、打牌推奨、自動操作、ゲームクライアントの改変を行いません。外部AIや外部APIにも接続しません。

## 必要環境

- Windows 10 / 11（64ビット）
- Python 3.12以降
- [Npcap](https://npcap.com/)
- パケット捕捉に必要な管理者権限

## セットアップ

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 実行

先にゲームを起動してから、管理者権限のターミナルで実行してください。

```bat
.venv\Scripts\python.exe -X utf8 realtime_pipeline.py
```

主なオプションは`--name`、`--iface`、`--records`、`--no-save-records`、`--no-topmost-ui`です。

```bat
.venv\Scripts\python.exe realtime_pipeline.py --help
```

## データとプライバシー

- 復元した牌譜はデフォルトで`records/`へ保存されます。
- 一時パケットデータは`bins/`へ書き込まれ、正常終了時に削除されます。
- 牌譜や生キャプチャには、対局情報やネットワーク情報が含まれる可能性があります。
- `records/`、`bins*/`、`packet/`、`*.bin`、`*.pcap*`はGit管理から除外されています。
- バグ報告へキャプチャを添付する前に、個人情報・IPアドレス・認証情報が含まれていないことを確認してください。

## 技術概要

```text
Npcap捕捉 → TCP sequence整列 → StreamDecoder → MahjongStateTracker
  → TableSnapshot → SessionCoordinator → GUI / JSON牌譜
```

実測済みのTCP 5003番server-to-client通信を対象とし、外側型`0x8002`のZstandardストリームを処理します。4人分の状態と牌ID 0〜135が整合するスナップショットのみ採用します。

通常更新の`MahjongSyncOpMessage`ではfield 4を供託、field 5を本場として復元します。protobufで省略された数値フィールドは既定値の0として扱います。

## テスト

テストは合成データだけを使用し、実際の通信キャプチャを必要としません。

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe -m compileall -q analysis app capture protocol realtime_pipeline.py
```

## 開発用依存関係

```bat
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

本リポジトリは現時点では**ソースコード公開のみ**を対象としています。ローカルで生成した実行ファイルを再配布する場合は、Scapyを含む第三者依存関係のライセンス条件を自身で確認し、遵守してください。

## 利用上の注意

- 利用地域の法令、ゲームの利用規約、第三者のプライバシーを遵守してください。
- 本ツールの利用によって生じたアカウント措置、データ損失、その他の損害について、コントリビューターは責任を負いません。
- プロトコルはゲーム更新で変更され、予告なく動作しなくなる可能性があります。

## コントリビューション

提案や修正は歓迎します。[CONTRIBUTING.md](CONTRIBUTING.md)と[SECURITY.md](SECURITY.md)を参照してください。

## ライセンス

本プロジェクトは[Mozilla Public License 2.0](LICENSE)で提供されます。第三者ライブラリについては[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)を参照してください。
