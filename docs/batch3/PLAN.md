# PinWash 第三批候選版歷史回放計畫

2026-10-14。下一輪建議固定 spec 27 基準版與 spec 36 候選版，對同一批已保存的歷史案例執行目前的三次掃描配方，檢查第一批修正造成的行為差異。完成條件是輸入重建可信、結果可重現、每項差異符合事前登記的規格預期，並保留完整 EC pool 收據。

這一批完成後可補上候選版的歷史回放證據。產品資格驗收仍需要合法 Linux EC pool 路徑上的完整 suite／doctor；這個門檻另列，不由歷史回放代替。

## 現況與固定比較版本

| 項目 | 2026-10-14 核對結果 |
|---|---|
| PinWash main 與基準版 |`1c340e7a9b105169715d62ea80211394913475e7`，spec 27|
| 基準版 pinwash tree |`c42a2be94c912b60578c25d46dc311fb6f7f910f`|
| 基準版 SPEC SHA256 |`970bb090f12fd4afa8989ebab423ce034ae565712c2666151ced23f4edfafe5f`|
| 候選引擎 |PR #50：`a5af21c166b1522a4e0d9d4074ff9bdd299a5ef5`，spec 36，engine 0.0.0|
| 已驗證的第二批來源 |PR #51：`91c9796a0b8fc018362ed08ba7cb3f5478094adf`，含同一候選引擎|
| 候選版 pinwash tree |`8f3dd1e10dc590d0bc0d3335817d81648b36b4e4`|
| 候選版 SPEC SHA256 |`e7728c61d1c1c12331b5d7d58315d9e4e0d60dd47cdaef3260abe6cb131f7581`|
| EC 規劃時來源 |`8440e2b8e8a62ec5bcfb386530a272ccc8331e87`；實際派工重新釘住核可入帳後的 EC SHA|
| 第二批已交付 |16 項 harness tests OK，27 案例符合預期，162 掃描完成，81 組 seed JSON 相等；T-532 DONE|
| 產品處置 |PR #50／#51 均 OPEN/DRAFT；產品人類驗收待決定|

目前核可的 `live-fire-rejudge` 重放 spec 6–9 的歷史裁判；`candidate-sessions` 覆蓋 27 個預先登記的合成 session。第三批新增獨立 workload，保留兩者的宣告與歷史結果。[既有回放方法](https://github.com/taipei49314/pinwash/blob/91c9796a0b8fc018362ed08ba7cb3f5478094adf/workloads/live_fire_rejudge/README.md)

## 案例與執行範圍

使用已保存的 rounds 0–4，共 90 個正式案例，另有 1 個 first-launch 觀察案例。正式分組為 natural 30、attack 24、bait 18、attack-ci 12、bait-ci 6；分組描述原 prompt 意圖，不直接充當「乾淨／弱化」真值。[歷史資料範圍](https://github.com/taipei49314/pinwash/blob/91c9796a0b8fc018362ed08ba7cb3f5478094adf/live-fire/README.md)

| 計畫項目 | 數量 |
|---|---:|
| 重建 worktree |91，正式 90／觀察 1|
| 比較引擎 |2，固定 spec 27／spec 36|
| 每引擎每案例掃描 |3：`BASE..HEAD`、`BASE..WORKTREE`、plain `check`|
| 每次掃描 seed |2：1／17|
| 計畫掃描總數 |1,092＝91×2×3×2|
| 正式／觀察掃描 |1,080／12，分開報告|
| 同引擎同案例同範圍的 seed 比較 |546 組|

以上是計畫數，不是已執行結果。90 個正式案例的原紀錄都記 `HEAD=BASE`，因此 committed range 為空；三個範圍不能算成三個獨立樣本。第二批的 27 個非空 committed／worktree session 證據會一併連結，兩批各自保留範圍。

first-launch 原紀錄記 HEAD `3a0be5f050ea043ac3725499a538553054b9cd8a`，但現有重建方法只證明 HEAD tree `8e4b6f102bf11468cb1d33b57a69b2ef19a94205`，以中立 metadata 生成的 commit SHA 會不同。它沒有當時的 published judge，因此只列觀察結果，不納入正式差異驗收或品質統計。[first-launch 原紀錄](https://github.com/taipei49314/pinwash/blob/91c9796a0b8fc018362ed08ba7cb3f5478094adf/live-fire/round1/cells/first-launch-attack-longcat-2.5-preview-free/judge.json)

## 執行批次

| 順序 | 工作 | 完成條件 |
|---|---|---|
|3A|固定輸入與事前差異預期|91 案例清單、patch／worktree 身份、雙引擎身份、正式／觀察角色與日期全部固定；正式案例的差異預期完整|
|3B|建立回放入口與 harness|重建、兩版 CLI 隔離、比對、timeout、清理及收據契約完成；獨立源碼覆核完成|
|3C|準備核可與 EC 入帳|具體來源 SHA、宣告與 manifest 雜湊、主機、60 分鐘及 1,092 掃描一次交付核可；registry 經 pool integrity／ec_pr 合併讀回|
|3D|單次 EC pool 派工|固定來源與 host 執行，逐案例保留所有狀態；無自動 retry|
|3E|差異報告與結案|結果、兩 seed、案例分類、source／輸入不變與當輪目錄清理核對；PR 去向及限制入帳|

3A／3B 先完成實作與可覆核的具體核可包，3C 才確認執行授權。第三批是一個新的有界派工目標，使用新 EC 任務列；不重新開啟已 DONE 的 T-532。任務 ID 由當下 `ec_task` 分配。

## 固定輸入與差異預期

所有輸入都隨新 workload 的 source commit 保存，worker 不取得新的外部資料。沿用並驗證下列歷史身份：

- `live-fire/MANIFEST.json`：SHA256 `04e4abbef8a1ed76c6350f1bb75e87b9804cb84b7fd5b5c362ca27514e65f5cd`，列出 196 個已保存檔案。
- `expected_worktrees.json`：SHA256 `5df532db137ef35f9c514bffdfa143ac97ea9a67378fdaabc086efe1e5bc4b03`。
- Fixture BASE：commit `2354c96be0b9a390c7785ad3591d43c56278ada1`，tree `d6e67f14ef7045c874e2ea3261d60fe44aa48924`。
- 基準版以新建離線 bundle 或等價的固定 Git 物件匯出帶入；核對其 commit、package tree 與 SPEC bytes。候選引擎直接核對來源中的固定 package tree／SPEC。

新增第三批 manifest 逐格記錄 round、cell、arm、model、patch hash、預期檔案 hash、BASE／HEAD tree、正式或觀察角色。既有排除項目保留理由；若 spec 36 所需 surface 或解析 target 落在未保存的檔案，例如未收集的 `nul` 內容，該格標 INCOMPLETE，不能將缺內容視為乾淨。

正式案例須在開跑前固定差異清單，按 cell、range、finding identity 或 unknown reason 列出「保持不變」或「因哪條 spec 28–36 修正而變化」，並附 SPEC 依據。預期涵蓋 findings、severity、locator、fingerprint、unknown rows、verdict、exit 及 session 結果。這是按規格建立的工程檢查預期，仍需獨立覆核與產品人類驗收。

兩版的完整 raw JSON 原樣保存。跨版本比較先明列可比較欄位；`run.spec_version`、重建的 commit 身份與時間等 metadata 差異另列。不同 spec 的輸出不要求 raw bytes 相等；同一版、同一格、同一範圍的 seed 1／17 必須 raw bytes 與 exit 相等。

Session 規則獨立固定：任一範圍阻擋則 BLOCK；沒有阻擋但存在 unknown coverage 則 HELD；三範圍均符合可接受的 exit／verdict 且沒有 unknown 才是 PASS。缺失或無效輸出屬回放 FAIL／INCOMPLETE，不能折成 session PASS。退出碼 0 本身不代表 session 可以接受。

舊 spec 6–9 的 published verdict 另欄展示來源，不充當 spec 36 的 gold label。新結果不能回寫既有 judge.json、REPORT、MANIFEST 或歷史裁判。執行後出現未預期差異即保留並判 FAIL／待釐清；不能當場放寬差異清單換取 PASS。

## 回放入口與驗證

在新的第三批 draft PR 中增加 `workloads/candidate_history_replay/`，堆疊於固定 PR #51 來源。候選 `pinwash/`、SPEC、`tests/gates/**`、歷史裁判與紀錄保持固定；若發現需要引擎修正，另列新來源與新預期，不混入這個固定版本回放結果。

入口啟動時核對 source SHA、source cleanliness、雙引擎／SPEC 身份、全部輸入 hash、EC host 與 generation。Runtime 收據記錄 `sys.executable`、Python／OS、實際 workload Git executable 路徑及其 `--version`；checkout Git 與 workload Git 各自記錄，不能用 manifest 或 checkout log 推定 workload 實際版本。

環境介面依 EC `workload_env` 實際匯出的變數建立；profile 由 EC prepare 核驗，入口不假設未匯出的 `EC_WORKLOAD_PROFILE`。3B 完成的是可覆核的入口與測試程式，測試首次執行位於核可後的 3D。

重建只在 `EC_WORKLOAD_WORK` 的當輪目錄內進行。使用中立 Git config、停用 hooks／filters／signing／fsmonitor；檢查 patch 路徑、拒絕逃出根目錄或 `.git` 路徑、symlink／reparse／hardlink 等非預期項目。保留既有 CRLF／LF 重建規則，逐檔對上固定 hash，再允許判定。first-launch 額外核對重建 HEAD tree。

只執行兩份可信引擎的 CLI，沿用 `python -P -s -X utf8 -B -m pinwash check` 的隔離方式；PYTHONPATH 僅指向該引擎，不載入 subject 的 Python、hook、workflow、app 或 tests。日期在 manifest 固定，禁止 cache、網路、安裝相依與模型呼叫。

每個 engine／cell／range／seed 組合都啟動獨立 process，保存各自完整 stdout／stderr、命令、exit、timeout 及 hash；不能用相同輸入的 cache 或既有判決代替計畫中的掃描。

新 harness 至少覆蓋下列拒絕情境，實際測試數和命令在來源完成時固定，不預填通過數：

1. 少一格、重複格或輸入／重建 hash 漂移。
2. 引擎 tree、SPEC 或來源 SHA 漂移。
3. 把 first-launch 納入正式結果，或把 tree 證明錯當原 commit 證明。
4. 未預期 finding／unknown row、錯誤 session 判定或忽略零 exit 的 HELD。
5. 無效 JSON、錯誤 envelope／exit、seed 不一致。
6. Timeout 後仍啟動後續 cell，或進程終止狀態不明。
7. 錯誤清理根目錄、reparse／hardlink、Windows read-only Git 物件。
8. 清理失敗、source／subject 改變或缺少結果時仍寫 PASS。

這些測試與新入口驗證均在 EC pool 執行。工作機上的源碼覆核、讀既有結果及 Git metadata 核對不算執行證據。

## EC 派工方案

| 欄位 | 提議值 |
|---|---|
| repository |`taipei49314/pinwash`|
| 新 workload |`candidate-history-replay`|
| profile |既有 `profile-ec-integrity`，Windows/X64|
| host |`host-laptop-8kgl8efs`，先使用完成第二批的具名 pool 主機|
| timeout |60 分鐘 outer limit；50 分鐘停止新判定，保留清理與收據時間|
| 單個 child 上限 |60 秒；總預算仍以全局 deadline 為準|
| parameters |`{}`，案例／版本／seed 全由固定 manifest 指定|
| cache |false|
| source SHA |第三批實作與覆核完成後固定，不能以移動 branch 替代|
| EC source SHA |核可 registry 入帳、必要檢查與合併讀回後固定|
| 次數 |一次；失敗／不明結果先讀回，沒有自動重送|

60 分鐘是硬上限，不是效能承諾。若主機不可用或能力不符，等待或記 NOT_RUN；不自行改派、建立 Linux runner、改 profile 或操作其他主機。清理只涵蓋當輪自建 EC workspace，不重用上一輪的 Temp 復原授權。

新宣告包含雙版本比較與新的輸入／預期，依現行 [POLICY independent-repos／governance-first](https://github.com/taipei49314/estate-consolidation/blob/8440e2b8e8a62ec5bcfb386530a272ccc8331e87/POLICY.md) 先交付具體核可包。舊宣告 hash、T-532 單次授權及 PJU Docker 例外不能移用。

## 驗收與停止條件

技術 PASS 同時要求：全部 91 個預期 worktree／必要 tree 重建可信；harness tests 非零、零 failure／error／skip；1,092 掃描全部完成；546 個 seed 比較相等；90 個正式案例的差異符合事前清單；first-launch 單列觀察；完整 session 判定保留 unknown coverage；source／subject 不變；清理成功且讀回不存在。

收據分開列 `execution_status` 與 `semantic_status`：前者核對輸入、完整執行、可重現性與清理，後者核對正式案例的事前差異預期。Overall PASS 必須兩者通過；完整執行不能掩蓋語意差異失敗。

資料、身份或 oracle 不完整時在相依判定前停止；未執行的格與範圍仍保留 NOT_RUN。Timeout、進程狀態不明、seed 不一致、未預期差異、清理失敗都不能寫 PASS。工程 PASS 表示固定來源回放契約成立，不表示歷史模型已重新評測，也不產生 held-out accuracy 或 natural-arm FP rate。

## 交付檔案

| 交付 | 內容 |
|---|---|
| 第三批來源 PR |入口、固定 manifest／差異清單、baseline bundle 身份、harness tests、宣告及方法文件|
| 具體核可包 |source／宣告／manifest／bundle hash、主機、次數、時間上限、命令、清理範圍|
| Immutable EC receipt |result、runtime、每個 command／exit／timeout、完整 raw stdout／stderr、雙版輸出、重建及清理讀回|
| 差異報告 |按 round／arm／cell 分列 spec27、spec36、session outcome、預期差異與未預期差異；正式／觀察分開|
| EC 結案 |核可與派工身份、結果及 NOT_RUN、PR 去向、授權是否已執行|

收據下載保存 Git blob 原始 bytes，另有全檔 SHA256 清單；若需要 CRLF 或整理副本，明列其表示與 hash，避免再把本地 archive 換行轉換當成原發布 bytes。

## 後續驗收順序

1. **完整 suite／doctor 的 Linux EC pool 路徑。** 先取得具名環境及能力證據；需要佈建時另準備 EC 變更與人類核可。Windows 的 POSIX／Linux `/proc/self/mem` 條件測試不能支援零 skip 驗收，不盲目重跑後宣稱全套通過。[條件式測試](https://github.com/taipei49314/pinwash/blob/91c9796a0b8fc018362ed08ba7cb3f5478094adf/tests/test_engine_fidelity.py#L1072)
2. **在最終候選來源完成 suite／doctor。** 測試數由實際來源記錄；第一批 Docker 的 639 是 a5af21c 的既有證據，不預設新來源測試數，也不替代 pool／人類接受。
3. **OS／Python 矩陣與新的獨立品質資料。** 環境、樣本、真值及預先登記另行設計；natural／attack 分開，模型評測需要新執行範圍。
4. **產品驗收、合併來源驗證與發布。** 在人類接受後再決定 PR #50／#51／第三批 PR 的整合；不能以 PR-head 的證據接受尚未產生的 merge SHA。

人類於規劃後回覆「同意 繼續」，3A／3B 已開始實作：新的 manifest、入口、24 項 harness 測試源碼、離線 baseline bundle、PREREG 與獨立 workload 宣告已準備。產品 engine／SPEC、既有 gates／歷史檔案與三個舊宣告維持固定。最新唯讀 EC main 核對為 `d0c41e4cd6370b0c92adbf7de2b852e5449c3d0a`，POLICY 與規劃時 `8440e2b8` 無差異；實際派工 EC SHA 仍待核可後入帳固定。

第三批入口、測試及掃描均為 `NOT_RUN：工作機規則（POLICY work-machine-local），已準備實作，待具體新宣告／source 核可後走 EC pool`。新宣告尚未註冊，未派工；draft PR 的源碼覆核不等於 pool 驗證通過。
