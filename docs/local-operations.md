# ローカル操作ガイド

[README](../README.md) · [開発・検証](development.md) · [ローカル操作](local-operations.md) · [管理受理側](admin.md)

開発版で接続済みのCLIを、操作の目的ごとに説明します。公開リレーの運用手順ではありません。ビルドは[開発・検証](development.md)、実装済み・保留・未実装の区分は[計画書の現在地](implementation-plan.md#11-現在地と次の作業)を参照してください。

以下のコマンドはリポジトリのルートから実行します。`/path/to/...`、ID、世代、確認理由は説明用で、実際の対象と管理者自身の確認内容に置き換えます。実行時データと秘密情報はリポジトリ外で管理してください。

## 操作を選ぶ

| 目的 | 参照先 |
|---|---|
| 設定候補だけを見る | [設定候補](#設定候補) |
| 鍵を作成・確認・保全する | [鍵操作](#鍵操作) |
| 保存領域を初期化・診断する | [保存領域](#保存領域) |
| 新規資料・改訂・派生を作る | [資料の作成と改訂](#資料の作成と改訂) |
| 保存版・分岐・由来を見る | [保存版と履歴の確認](#保存版と履歴の確認) |
| 完成Recordを稼働中の受理側へ送る | [完成Recordの送信](#完成recordの送信) |
| 根拠復旧を確認し、保存層だけを再開する | [保存層の復旧確認と明示再開](#保存層の復旧確認と明示再開) |

## 設定候補

```sh
./target/release/lngnb config show
./target/release/lngnb config show --data-dir /path/to/data
```

`config show`は未保存・未適用の設定候補を表示します。既定のデータ領域候補はカレントディレクトリの`./lngnb-data`で、指定したパスの読込み・作成、設定保存、ネットワーク接続は行いません。既存リレーの状態確認や初期化コマンドではありません。未対応操作・不正引数は終了コード2、出力失敗は1となり、成功とは表示しません。

## 鍵操作

### 作成・読込み確認・パスフレーズ更新

鍵操作は、リポジトリ外に用意した所有者専用0700ディレクトリを明示します。自動作成・権限修正は行いません。前面の制御端末でパスフレーズを非表示入力し、作成・更新時は二度入力します。

```sh
./target/release/lngnb key create --key-dir /path/to/private-keys --name publisher
./target/release/lngnb key check --key-dir /path/to/private-keys --name publisher
./target/release/lngnb key change-passphrase --key-dir /path/to/private-keys --name publisher
```

暗号化鍵ファイルを安全な別の場所にも保管し、パスフレーズは鍵とは別に保全してください。紛失は管理トークンで回復できません。複数資料で鍵を共用すると漏洩時の影響が広がります。鍵の紛失・漏洩・計画交代では新鍵と新Knowledgeへ移行し、同じKnowledgeの発行鍵は変更できません。`check`は現在名の復号・公開鍵一致の確認だけで、残存ファイルの復旧や過去の更新結果の確定ではありません。

### 残存物の読取り診断

```sh
./target/release/lngnb key recovery-status --key-dir /path/to/private-keys
./target/release/lngnb key check-residue --key-dir /path/to/private-keys --residue NAME_FROM_RECOVERY_STATUS
```

残存物は、端末不要の`recovery-status`で名前と上限付き読取り結果を診断できます。読取り完了は形式・認証の成功ではなく、生成形式に合わない予約名は件数だけを示します。`check-residue`には一覧に出た生成形式名を明示し、その暗号文のパスフレーズを端末入力します。認証復号できた鍵IDだけを表示し、元の対象名・新旧・更新確定・削除可否は推測しません。どちらも書換え・採用・削除をせず、終了0は診断処理の終了だけです。

### 別領域への保全

```sh
./target/release/lngnb key preserve-residue --key-dir /path/to/private-keys --residue NAME_FROM_RECOVERY_STATUS --backup-dir /path/to/private-backup --backup-name saved.key
```

`preserve-residue`は、指定した残存暗号文を認証して、別の既存0700ディレクトリの新しい通常名へ同じ暗号文を保全します。保全元の現在名・残存物は残し、保全先の既存ファイルも上書きしません。保全先でもその暗号文のパスフレーズが必要です。過去の更新確定や新旧判定・残存物の整理許可にはならず、保全元の変更停止も解除しません。保全先の永続化確認後に元の暗号文の最終照合等ができなかった場合は終了5となり、両領域の全ファイルを保持して確認します。

### 空いている通常名への復元

```sh
./target/release/lngnb key restore-residue --key-dir /path/to/private-keys --residue NAME_FROM_RECOVERY_STATUS --restore-name restored.key --expect-key-id EXPECTED_KEY_ID
```

`restore-residue`は、選択した残存暗号文を期待鍵IDと照合し、同じ領域の空いている通常名へ同じ暗号文を復元します。期待鍵IDは作成時の控え等と照合して明示してください。元名・新旧を推測せず、既存鍵は置換しません。全残存物と変更停止を維持し、成功しても過去の更新完了や残存物の整理許可にはなりません。復元先の永続化確認後に残存元の最終照合等が未完了・不一致なら終了6となり、全ファイルを保持して確認します。

### 元領域を保持した別領域での操作

元領域を保持したまま鍵操作を続けるには、控え等の期待鍵IDと選択した残存鍵を照合し、残存物のない別の専用領域へ`preserve-residue`で保全します。終了0を確認し、保全先を`key check`で認証して同じ鍵IDを照合した後、以降の`--key-dir`にその領域を明示します。元領域の変更停止は解除しません。コピー先のパスフレーズを変更しても、元領域の暗号文は旧パスフレーズで復号可能なままであり、鍵の失効・漏洩回復にはなりません。確認項目と失敗時の境界は[実装計画書§5.37](implementation-plan.md)に示します。

### 終了コードと中断時の保全

| 終了コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | その他の失敗 |
| 2 | 引数不正 |
| 3 | 保存未確定 |
| 4 | 新鍵の永続化確認済みで、旧暗号文の整理が不確実 |
| 5 | 保全先保存済みで、最終照合等が未完了 |
| 6 | 復元先保存済みで、最終照合等が未完了 |
| 130 | 入力取消し |

3/4/5/6や残存ファイルの通知では現在名・回復用暗号文を保全し、変更を繰り返さず確認してください。残存ファイルは自動採用・削除せず、CLIによる既存鍵の置換・残存物の整理は未実装です。結果出力の失敗は保存の失敗と同じではなく、鍵操作完了後の出力失敗は診断で区別します。SIGKILL/SIGSTOP・端末消失等の復元は保証しません。端末復元失敗時は入力を続けず別の正常な端末を使用し、必要なら元端末で`stty sane`を使います（元設定の完全復元ではありません）。

鍵領域の停止解除・既存鍵の安全な置換・残存物整理のCLIは未実装です。履歴の論理Readyや内部APIの成功を通常変更許可へ読み替えません。内部基盤の範囲は[開発・検証](development.md#鍵管理の内部apiと未接続範囲)にまとめています。

## 保存領域

試作DBはschema 12のみ対応します。schema 1〜11を自動移行・再初期化せず、旧DBは保持したまま別の新規領域で試験します。

保存領域の初期化と状態診断は、対象を明示します。

```sh
./target/release/lngnb data init --data-dir /path/to/new-data
./target/release/lngnb data status --data-dir /path/to/existing-data
```

`data init`は既存の親ディレクトリの下へ所有者専用0700の新しい保存領域を作ります。既存領域は空でも拒否し、上書き・自動移行・再初期化しません。今回の初期化はローカル保存だけで、待受先・投稿モード等の設定保存やリレー起動は未実装です。終了3では初期化の完了を確認できず、作成済み・途中の領域が残る可能性があります。保全して確認し、削除や再初期化を繰り返さないでください。初期化後の出力失敗は終了1で区別し、状態診断の成功だけを初期化失敗からの復旧完了とは扱いません。

`data status`は同じ排他を保持して、起動状態、診断対象の内部世代（`diagnostic_generation`）、Recordの管理用再検査件数、本文状態、保持実体の欠損・破損・孤立・途中ファイル、空き容量を表示します。保存層の共通診断で親不足と本文不足を区別し、診断結果を保存済み評価へ書き戻さず、正常停止印・公開資格を付与しません。保持本文の欠損等を新たに検出すると、既存APIが停止印と履歴を記録します。欠損ファイルを戻しただけでも手動確認待ちは解除しません。正常領域・既に手動待ちの領域への診断だけでは、その論理状態を変更しません。未対応・破損・lock競合・予算不足等では終了1とし、途中件数を成功として表示しません。この停止中診断の予算調整、同期・pin・公開等の製品全状態表示は未実装です。ローカル保存の明示再開には別操作の`data resume-local`を使います。稼働中管理受理側の診断には別操作の`admin status/evaluate`を使い、自動では切り替えません。診断処理の終了0は、資料や保存領域全体の正常・公開可能・復旧完了を意味しません。

## 資料の作成と改訂

### 新規資料

新規資料は、schema 12・正常停止状態のデータ領域と、残存物のない鍵領域を明示して作成します。保存領域は[保存領域節の`data init`](#保存領域)で作成できます。資料作成そのものは領域の新規作成・復旧を行いません。期待鍵IDは事前の`key check`等の控えと照合してください。metadata入力は仕様書A2の項目を持つ決定的CBOR mapです。言語ラベルの小文字化・型の既定値補完は署名前に行い、衝突は拒否します。

```sh
./target/release/lngnb document create --data-dir /path/to/existing-data --key-dir /path/to/private-keys --name publisher --expect-key-id EXPECTED_KEY_ID --payload /path/to/body --metadata /path/to/metadata.cbor
```

本文の既定予算は16 MiB、`--max-payload-bytes N`で0〜67,108,863 bytesへ明示変更できます。metadata上限は262,144 bytesです。`--media-type type/subtype`を省略すると媒体未指定となり、内容や拡張子から推測しません。本文・Record全体のセッション予算と、既存領域の起動検査予算も別途必要です。現在のCLIで既存集合の起動予算は調整できず、超過時は成功にしません。

成功時はKnowledge/Genesis/Revision IDを表示します。本文→Genesis→Revisionは段階ごとに保存するため、終了3では一部または全部の保存済み・未確定の可能性を残します。全領域を保全し、再作成せず確認してください。保存・正常終了後の出力失敗は終了1で区別します。引数不正は2、入力取消しは130、その他の保存前失敗は1です。手動確認待ち・鍵残存物を自動解除せず、作成成功でもpin・公開許可を付けません。新規Recordの管理用評価はdirtyとなり、次回起動検査等で再評価します。

### 同じKnowledgeの改訂

同じKnowledgeを改訂するには、完成CBORのGenesisと親Revisionを明示します。本文・metadata・媒体は毎回指定し、元版から自動継承しません。

```sh
./target/release/lngnb document revise --data-dir /path/to/existing-data --key-dir /path/to/private-keys --name publisher --expect-key-id EXPECTED_KEY_ID --genesis /path/to/genesis.cbor --parent /path/to/parent.cbor --payload /path/to/new-body --metadata /path/to/new-metadata.cbor
```

複数親は`--parent PATH`を繰り返し、最大256件です。親を自動選択せず、親なしの別初版を作る場合だけ`--no-parents`を明示します。両方の併用・指定省略・重複親は拒否します。指定Recordは各2 MiB以下、Genesisと親の入力合計は16 MiBまでです。これはCLIの処理予算であり、小さい予算への超過を署名不正とは扱いません。既存の安全な読取り・秘密端末・期待鍵ID照合・署名APIを共有します。

全起動検査後、同じ排他の下で指定Genesisと全親の保存を確認し、新しい本文→新Revision→正常停止の順で保存します。起点・親を自動取込みせず、保存先にない場合は新本文/Recordを保存せず終了3で保全停止します。稼働中IPCへ切り替えません。引数2・保存前失敗1・入力取消し130・保存未確定3・保存/正常停止後の出力失敗1は作成CLIと共通です。保存成功は全祖先の有効性・評価確定・pin・公開を保証せず、署名済みの元版・鍵・由来を変更しません。全保存版・分岐・由来の確認には`document history`を使います。

### 別Knowledgeへの派生

派生は元Knowledgeの改訂と分け、由来のGenesisとRevisionを組で明示します。

```sh
./target/release/lngnb document derive --data-dir /path/to/existing-data --key-dir /path/to/private-keys --name publisher --expect-key-id EXPECTED_KEY_ID --origin-genesis /path/to/source-genesis.cbor --origin-revision /path/to/source-revision.cbor --payload /path/to/derived-body --metadata /path/to/derived-metadata.cbor
```

`--origin-genesis`、`--origin-revision`の順の組を1〜128組指定します。各組の局所署名と種別・Knowledge・Genesis・発行鍵の直接対応を検査し、重複を拒否します。由来には三IDの完全固定参照を整列して入れ、新しいKnowledgeと親なし初版を派生先の明示鍵で署名します。元発行鍵と派生先鍵の一致、元版の保存先への取込み、元版の本文・全祖先の保持は要求しません。由来は承認や必須依存、自動取得の指示ではありません。

本文・metadata・鍵・保存・失敗保全は作成CLIと共通です。元Record群は各2 MiB・合計16 MiBを確保前に制限し、NOFOLLOW・単一link・属性前後照合・取消しを共有します。元本文・metadata・親・由来を暗黙継承せず、署名済み元Recordや鍵を変更しません。派生先でも保存成功と全祖先評価・pin・公開・復旧完了は別です。

## 保存版と履歴の確認

### 保存版の親・由来

保存版の署名に含まれる親・由来は、Knowledge・Genesis・Revisionの三IDをすべて明示して確認します。鍵や制御端末は不要です。

```sh
./target/release/lngnb document inspect --data-dir /path/to/existing-data --knowledge-id KNOWLEDGE_ID --genesis-id GENESIS_ID --revision-id REVISION_ID
```

同じ排他の下で既存の領域検査・予算と共通の固定版読取りを使い、指定と一致した版の三ID・署名鍵ID・親・由来の宣言を表示します。親のない初版や分岐を自動選択・一本化せず、別版・別Genesisへ代替しません。由来の省略IDは`unspecified`とし、origins未指定（`origins: unspecified`）と明示空（`origins: 0`）を区別します。表示順は署名中の集合順です。本文・metadataは出力せず、参照先の取得・依存評価・pin/公開判定は行いません。

`startup_state`は領域の診断であり、この表示の成功はGenesis/親/由来の外部照合、全祖先有効性、本文保持、評価確定、公開・復旧完了を意味しません。起動cursorを進めず、writer/finishや手動待ち解除を行いません。既存openが保持本文の欠損等を検出した場合は停止印・履歴を記録し、保全します。SQLiteのWAL/SHM等のI/Oはあり得るため、全fileの物理的不変は保証しません。

引数不正は接触前に終了2、未保持・三ID不一致・領域検査/予算/排他の失敗・出力失敗は終了1です。部分結果を成功にせず、稼働中IPC、直接保存、自動修復・再試行、残存物整理へ切り替えません。正常領域と既に手動待ちの領域を確認できますが、表示成功で停止印は解除されません。全保存版・分岐の確認は次の`document history`を使います。

### 保存範囲の全版・分岐・管理用評価

保存範囲の全Revisionと親子宣言・同世代の管理用評価は、KnowledgeとGenesisを明示して確認します。鍵・パスフレーズ・制御端末は不要です。

```sh
./target/release/lngnb document history --data-dir /path/to/existing-data --knowledge-id KNOWLEDGE_ID --genesis-id GENESIS_ID
```

同じ排他/read transactionで共通の保存履歴・評価処理を使い、生Revision ID順に全保存版を表示します。各版の署名鍵、親と参照先の直接対応、scope内でそのIDを親と宣言する子、由来、`record_validation`と理由/関係ID、本文状態と理由を表示します。本文・metadataは出力しません。由来の三形・未指定/空・署名中の集合順を保持し、省略IDは`unspecified`です。`declared_root/merge/branch/tip`は親なし・複数親・複数の宣言上の子・宣言上の子なしを表し、別鍵の宣言も消しません。直接対応は二版の対応だけで、全祖先有効性ではありません。

`valid/pending/invalid`は対象Genesisを仮定した、その世代の非永続管理用診断です。保存先端やvalidだけへ絞らず、世界の完全履歴、評価済み現在候補、公開候補とは呼びません。validも本文保持・pin・公開・復旧完了を保証しません。由来は親履歴・承認・必須依存ではありません。`assessment_committed: false`は新しい評価や根拠を永続確定していないことを示し、`assessment_storage_fault`は評価器が観測した保存障害で全領域健全性の証明ではありません。既知不正の根拠不足もpending/理由を保ったまま診断します。

既存openの検査/予算を省略せず、一覧と評価は別々の全保存走査です。既定は一覧10,000 Record/64 MiB、選択親+由来100,000、一覧SQL callback100,000/60秒。評価も10,000 Record/64 MiB、親辺100,000、本文hash64 MiB。両段階は合計60秒を共有します。さらに出力準備は32 MiB/60秒で制限し、準備完了後に出力します。これらは非保存の操作予算で、保存4設定を追加/変更しません。OS I/O、一件の署名/hash、commit、標準出力の強制中断保証ではありません。

空scopeは`revisions: 0`で成功し、別Genesis/版へ代替しません。pending/invalid/保存障害や手動待ちでも診断を表示できますが、成功は正常停止・健全性・復旧完了を意味しません。引数不正は領域へ接触前に終了2、領域検査・排他・予算・読取り・出力の失敗は終了1。読取り/出力準備失敗では部分結果を出さず、出力途中のI/O失敗は診断と区別して失敗します。出力まで同じ排他を保持し、稼働中IPCへ切り替えません。参照取得、writer/finish、永続評価、起動cursor進行、手動待ち解除は行いません。既存openの異常検出による停止印/履歴とWAL/SHM等のI/Oはあり、全fileの物理的不変は保証しません。

## 完成Recordの送信

送信先の準備と停止方法は[管理受理側ガイド](admin.md#起動と終了)を参照してください。

完成署名Record一件を、既に稼働している同じ領域の管理受理側へ送れます。

```sh
./target/release/lngnb record submit --data-dir /path/to/existing-data --record /path/to/record.cbor
```

入力は2 MiB以下の単一link通常fileで、親を含むsymlinkや特殊fileは拒否します。局所署名検査後、所有者専用の領域・0600 socketと接続先のkernel UID（領域所有者/root）を照合して送ります。最大30秒の通信予算で、受信応答の版・長さ・Record ID・挿入有無を確認します。接続前の失敗は終了1、送信開始後の失敗/不正応答は保守的に終了3（保存確定不明）、確定応答後の結果出力失敗は終了1です。成功は一件のローカルcommit応答だけで、親評価・本文保持・pin・公開・正常停止や復旧完了とは別です。入力と領域を保全し、応答がないまま再作成しないでください。プロセス中断等で結果を返せなかった場合も、既に保存済みの可能性があります。

この送信CLIは管理受理側を起動しません。別の端末で`admin serve`を起動して使用できます。製品リレーの起動CLI・全管理状態のIPC診断は未実装です。管理受理側4項目の保存設定は`admin serve`の起動時に検査・適用します。領域の自動作成、socket削除、自動再送、直接DB保存への切替はしません。秘密鍵・パスフレーズ・本文Blobは送りません。同UID/rootの意図的な差替えや認証後のfd譲渡は防御範囲外です。

## 保存層の復旧確認と明示再開

この節は保存層のローカル書込みだけを扱います。鍵領域の停止解除、一般配信、socket整理、製品全体の復旧完了とは別です。

### 根拠復旧の確認記録

手動確認待ちの保存領域で、根拠復旧の再検査と管理者の確認内容だけを記録する操作は次のとおりです。まず`data status`の`diagnostic_generation`と対象領域を確認し、その世代・復旧内容・まだ確認できていない事項をすべて明示します。

```sh
./target/release/lngnb data recovery-confirm --data-dir /path/to/existing-data --expect-generation N --restored '真正本文を復元しIDを照合' --unconfirmed '公開設定・未確定制限は未確認'
```

停止中の所有者/root専用領域と同じ排他・既存open検査を使い、現在世代の一致と手動待ちを要求します。確認文はそれぞれUTF-8で1〜4096 bytes、空白のみ・NULは拒否します。CLIは申告文を出力しませんが、確認履歴へ原文を保存します。操作者の実効UID・時点・規則版も既存履歴へ記録します。期待世代は非負の十進整数（先頭ゼロ・符号・空白なし）です。引数不正は領域接触前に終了2。古い世代・正常領域・未完了起動検査・保存異常・予算/SQL失敗は確認成功にせず終了1です。

一次Recordと参照本文を既存APIで再検査し、既知不正の各根拠が真正本文/実長と一致した場合だけ、確認履歴と派生評価のdirty化を同じFULL transactionで記録します。既定の領域検査は10,000 Record/64 MiB・10,000 Blob/64 MiB、根拠確認は10,000 Record/64 MiB・100,000親辺・本文hash64 MiB/60秒です。既存SQL検査予算も維持します。保存済みhash来歴への代替・検査省略・自動取込み/削除・修復・IPC切替はありません。OS I/Oや一件の署名/hash・commitの強制中断を保証せず、非保存の予算を保存4設定へ追加しません。

出力の`source_generation`・`recorded_generation`は確認対象と確認記録の世代です。commit後に既存APIが排他を解放するため、出力時の現在世代や独立した再開資格とは呼びません。`checked_evidence`は既知不正の根拠起点数で、0件も全体健全性の証明ではありません。参照外本文・孤立実体・staging・公開設定・未確定制限の全確認、親評価完了・起動完了・復旧完了を意味しません。未確認事項を解消済みと推測せず、既知不正の記録や署名済み一次データを変更しません。

開始履歴を先に確定するため、途中失敗でも世代が進み、開始履歴や確認が保存済みの場合があります。停止印とデータを保全し、古い期待世代で自動再試行しません。記録後の出力失敗は別の診断で終了1とし、記録を取り消したとは表示しません。成功・失敗・通常再起動のいずれでも手動待ちを維持します。writer/finish・明示再開・正常停止・公開資格への接続は行っていません。根拠確認の記録とローカル保存の明示再開は別操作です。

### ローカル保存の明示再開

根拠復旧確認後にローカル保存を明示再開する場合は、確認結果の`source_generation`・`recorded_generation`・`checked_evidence`をすべて指定します。未確定だった制限を確認/再適用し、残る障害がないと判断した理由を原文で指定してください。

```sh
./target/release/lngnb data resume-local --data-dir /path/to/existing-data --source-generation SOURCE_GENERATION --review-generation RECORDED_GENERATION --checked-evidence CHECKED_EVIDENCE --confirm-restrictions-reapplied --confirmation '未確定制限を確認/再適用済み。現在の保存範囲に未解決障害なしと判断した理由'
```

受領値・確認flag・理由の省略/重複は拒否します。数値は符号/空白/先頭ゼロなしの非負十進表記で、世代はsource+2=review、件数はi64範囲内を要求します。理由はUTF-8で1〜4096 bytes、空白のみ/NULは拒否し、CLI/Debugに出しません。履歴には原文を保存します。申告文から未解決事項の解消を自動判断せず、flagと呼出しは管理者自身の明示判断を表します。

同じ所有者/root用領域・排他/open検査から、既存の`resume_local_writes`へ接続します。受領値だけを資格とせず、現在世代と実際の最新確認履歴の操作/規則/旧新状態/申告/件数を照合します。保持台帳の全本文・staging/孤立実体、現在Record/真正本文/既知不正、依存評価と存在する起動/入力/本文/親評価台帳を既存予算で再検査します。未完了/古い台帳、欠損/破損/孤立/一時実体、根拠不足、未確定整理、予算/容量不足を迂回しません。正常な本文未保持・親不足のpendingと、保存障害や明確な不正を区別し、全件validや依存不足解消を成功条件と呼びません。

再開開始履歴を先に記録し、再評価・逆依存・新たな既知不正根拠・再開申告を同じFULL transactionで確定した後、ローカルwriterへ渡します。このCLIは他の保存操作をせず、最後の状態変更として`writer.finish`で正常停止します。現在の署名済みRecord/本文や既知不正を削除/書換えず、一般配信・公開・IPCは再開しません。正常停止の確認後は通常の停止中作成等を別操作で行えますが、以後の起動検査を省略しません。

引数不正は領域接触前終了2。再開/正常停止を確認できない場合は保守的に終了3とし、再開履歴・評価・正常停止が保存済み/未確定の可能性を残します。途中失敗/中断では手動待ちが残り得る一方、正常停止commit後のエラーではcleanが保存済みの場合もあり、一律に未解除/未保存と断言しません。現在状態と履歴を確認し、古い受領値で自動再試行せず、必要な検査/根拠確認をやり直してください。正常停止まで確認後の出力失敗は終了1で区別します。出力のreview/resumed generationは対象確認と再開履歴の世代で、finish後や出力時の現在世代ではありません。

領域/評価/SQLの既定予算（10,000 Record/64 MiB、全保持Blob10,000件/64 MiB、親辺100,000、評価の本文hash64 MiB/60秒）と既存容量予約を共有します。非保存の操作予算を保存4設定へ追加せず、OS I/O・一件の署名/hash・commitの強制中断や恒久的な無破損を保証しません。自動再開/修復/採用/削除、検査省略、直接SQL保存、IPCへの切替はありません。一般配信/公開資格や製品全体の復旧完了とは別で、残る管理接続・鍵残存物整理・鍵領域の停止解除・安全な置換のCLI・socketの不使用判定/整理も引き続き未完了です。
