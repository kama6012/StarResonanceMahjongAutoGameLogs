# Contributing

コントリビューションを歓迎します。

## 開発環境

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

## 変更時の確認

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe -m compileall -q analysis app capture protocol realtime_pipeline.py
```

## プルリクエスト

- 変更目的と動作確認方法を記載してください。
- 既存の責務分離（`capture`、`protocol`、`analysis`、`app`）を維持してください。
- バグ修正やプロトコル変更には、可能な限り合成データによる回帰テストを追加してください。
- 実キャプチャ、牌譜、IPアドレス、プレイヤー情報、認証情報をコミットしないでください。
- ゲームの著作物や第三者コードを、許諾とライセンス表示なしに追加しないでください。

## コーディング方針

- Python 3.12以降を対象とします。
- 公開APIと複雑な処理には型注釈と簡潔なdocstringを付けます。
- GUIスレッドとパケット捕捉スレッドを直接結合せず、既存の境界を利用します。
- 実通信に依存するテストではなく、最小限の合成protobufデータを使用します。