# Native 妯＄硦娴嬭瘯鎴樺焦锛坈ampaign锛夎繍缁磋鏄?
鏈枃妗ｈ褰?ARTEX 涓?campaign 瀛愮郴缁熺殑鍚敤鏂瑰紡銆佸澶栨帴鍙ｃ€佺敓鍛藉懆鏈熻涔変笌宸茬煡杈圭晫銆俢ampaign 鏄?`native_fuzz` 涓€娆℃€у悓姝ユā绯婃祴璇曚箣涓婄殑**鎸佷箙鍖栫増鏈?*锛氬畠鏈夌姸鎬佹満銆佺绾︺€侀绠楄处鏈€佹鏌ョ偣涓?娓呯悊缁撹锛屽洜姝ゅ彲浠ユ殏鍋溿€佺画璺戙€佸璁′笌瀵硅处銆?
> 缁撹鍏堣锛氬穿婧冧粛鐒跺彧鏄?*鍊欓€?*銆俢ampaign 浜у嚭 `candidate-only` 璇佹嵁锛屽崌绾т负 finding 浠嶉渶
> reviewer 鐙珛閲嶆斁锛堣"璇佹嵁涓庨獙鏀?锛夈€?
## 1. 鍚敤

campaign 榛樿鍏抽棴锛岄渶瑕佸悗绔繘绋嬪甫浠ヤ笅鐜鍙橀噺锛坄deploy.sh` 宸插唴缃級锛?
| 鍙橀噺 | 璇存槑 |
| --- | --- |
| `ARTEX_NATIVE_CAMPAIGN=1` | 鎬诲紑鍏筹紱鍏抽棴鏃朵笉璇昏矾寰勩€佷笉寤虹洰褰曘€佷笉鎷夎捣浠讳綍杩涚▼ |
| `ARTEX_NATIVE_CAMPAIGN_PYTHON` | 缁濆璺緞鐨?python3锛堜笉鑳界粍/浠栦汉鍙啓锛岄渶 root 鎴栧綋鍓嶇敤鎴锋墍鏈夛級 |
| `ARTEX_NATIVE_CAMPAIGN_MODULE_ROOT` | 妯″潡閮ㄧ讲鏍癸紝**鍙兘鍖呭惈 `scripts`**锛屼笖蹇呴』婧愮爜-only锛堟棤 `__pycache__`/`.pyc`/`.so`锛?|
| `ARTEX_NATIVE_CAMPAIGN_DOCKER` | 缁濆璺緞鐨?docker 鍙墽琛屾枃浠?|
| `ARTEX_NATIVE_CAMPAIGN_STAGING_ROOT` | 绉佹湁鐩綍锛?700锛夛紝涓庝笅闈㈢殑 docker 閰嶇疆鐩綍浜掍笉鍖呭惈 |
| `ARTEX_NATIVE_CAMPAIGN_DOCKER_CONFIG` | 绉佹湁涓?*蹇呴』涓虹┖**鐨勭洰褰曪紙0700锛?|

`ARTEX_CAMPAIGN_TRACE=1` 鏄彲閫夎瘖鏂紑鍏筹細鎵撳紑鍚庡悗绔細鍦ㄥ惎鍔ㄦ瘡涓?attempt 鏃惰褰曚竴琛屽惎鍔ㄥ抚鎽樿
锛坈ampaign/attempt/绉嶅瓙鏁?瀛楄妭鏁?鏉ユ簮绫诲瀷锛夛紝浠呭啓鏃ュ織锛屼笉鍐欏叆鍙拌处銆?
## 2. 鎺ュ彛
鍏ㄩ儴闇€瑕佺鐞嗗憳 token锛坄Authorization: Bearer <token>`锛夛細

| 鏂规硶 | 璺緞 | 璇存槑 |
| --- | --- | --- |
| POST | `/api/tasks/{id}/reverse/native/campaign` | 鍔ㄤ綔鍏ュ彛锛宍action` 鈭?`create` `validate` `start` `pause` `cancel` `resume` |
| GET | `/api/tasks/{id}/reverse/native/campaigns` | 鎴樺焦鍒楄〃锛堟父鏍囧垎椤碉細`limit`銆乣before_id`锛?|
| GET | `/api/tasks/{id}/reverse/native/campaigns/{cid}` | 鍗曚釜鎴樺焦鐘舵€?|
| GET | `/api/tasks/{id}/reverse/native/campaigns/{cid}/manifest` | 璇枡娓呭崟 |
| POST | `/api/tasks/{id}/reverse/native/campaigns/{cid}/reconcile` | **杩愮淮瀵硅处**锛氫粎鐢ㄤ簬 final 涓㈠け銆佹棤鍒涘缓灏佸嵃鐨勫皾璇?|

鍒涘缓绀轰緥锛坄create`锛夛細

```json
{
  "action": "create",
  "request_id": "c-<鍞竴>",
  "artifact_id": 26,
  "profile_id": "native-afl-404c",
  "total_budget_ms": 300000,
  "default_attempt_budget_ms": 120000,
  "max_executions": 500000,
  "max_crashes": 8,
  "input_mode": "stdin",
  "argv": [],
  "seeds": [{"sha256": "<64hex>", "data_base64": "<base64>"}]
}
```

绾︽潫锛堢敱鏈嶅姟绔己鍒讹級锛歚total_budget_ms` 鈭?[6000, 86400000]锛涘崟娆″皾璇曢绠?鈭?[6000, 900000] 涓斾笉瓒呰繃
鎬婚绠楋紱`request_id` 骞傜瓑锛堝悓 id 涓嶅悓鍐呭杩斿洖 `idempotency_conflict`锛夛紱浠诲姟蹇呴』鏄?`reverse` 绫诲瀷銆?闈炴殏鍋溿€侀潪缁堟€侊紝涓旇繍琛岀幆澧冪瓥鐣ワ紙profile/artifact锛変笌 native 閰嶇疆 revision 鍧囧凡鎺堟潈銆?
## 3. 鐢熷懡鍛ㄦ湡

```
draft 鈫?queued 鈫?running 鈫?(stopping) 鈫?completed / failed / cancelled
                     鈫?paused            鈫?interrupted锛堣繘绋?绉熺害涓柇锛?```

- `start`锛氭帓闃燂紝鐢?manager 鍦ㄥ敮涓€ worker 妲戒笂棰嗗彇锛坄local-afl-1`锛夛紝`resource_hold=true`
- `pause`锛氬悜 runner 鍙戞殏鍋滀俊鍙凤紱runner 鍋滀笅鍐欏叆銆侀噰闆嗚鏂欍€佸彂鍑烘鏌ョ偣鍒嗗潡锛屽皾璇曡繘鍏?`paused`
- `resume`锛氫粠鏈€鏂版鏌ョ偣璧?*鏂扮殑涓€娆?attempt**锛堥绠楃粨杞紝`charged_budget_ms` 涓嶉噸缃級
- `cancel`锛氱粓姝㈠苟娓呯悊锛沗cleanup_status` 蹇呴』鏄?`verified` 鎵嶇畻骞插噣
- 棰勭畻鑰楀敖鍚?`resume` 杩斿洖 `budget_exhausted`

瑙傛祴寤鸿锛氱敤 `state` + `charged_budget_ms/total_budget_ms` + `latest_checkpoint_id` + `cleanup_status`
鍥涗釜瀛楁鍒ゆ柇涓€娆℃垬褰规槸鍚﹀仴搴枫€?
## 4. 鏆傚仠涓庣画璺戠殑瀹為檯琛屼负

- 鏆傚仠**鍙湪 runner 宸茬湡姝ｅ紑濮嬪啓鍏ヤ箣鍚?*鎵嶆湁妫€鏌ョ偣銆傚惎鍔ㄧ獥鍙ｅ唴锛堝鍣ㄥ垱寤恒€佸伐鍏锋帰娴嬶級鏆傚仠浼氬緱鍒?  `failed/checkpoint_invalid`锛氳繖鏄樉寮忓け璐ワ紝涓嶄細浼€犱竴涓┖妫€鏌ョ偣銆?- 鏆傚仠鏃?runner 浼氬厛鍋滃啓鍏ュ啀鍙栨鏌ョ偣锛涘悗绔负鏆傚仠纭鐣欎簡鏈夌晫绛夊緟锛堥粯璁?8s锛屽彈 cleanup 棰勭畻绾︽潫锛夈€?- 缁窇鏃舵鏌ョ偣浼氭垚涓烘柊 attempt 鐨勭瀛愰泦鍚堛€?*宕╂簝鏍锋湰浼氳鎺掑埌绉嶅瓙鏈熬**锛屼繚璇?showmap 鎺㈡祴浣跨敤鐨?  绗竴鏉¤緭鍏ユ槸鑹€ф牱鏈紙鍚﹀垯鎺㈡祴浼氳 AFL 鍒や负 "rejected the target"锛夈€?- 姣忔 attempt 鐨?ended 鐘舵€併€侀绠楃數鑽枫€佹竻鐞嗕笁鍏冪粍閮戒細鍐欏叆
  `native_campaign_attempts` 涓庤 attempt 鐨勮瘉鎹枃浠躲€?
## 5. 璇佹嵁涓庨獙鏀?
- 璇佹嵁钀界洏锛歚data/tasks/<task>/reverse/campaigns/<cid>/evidence/<attempt>-<sha>.json`锛宍authority=candidate-only`
- 鍙拌处琛細`native_campaigns`銆乣native_campaign_attempts`銆乣native_campaign_checkpoints`銆?  `native_campaign_evidence`銆乣native_campaign_events`
- 宕╂簝鍊欓€夊崌绾ц矾寰勪笌涓€娆℃€?fuzz 鐩稿悓锛歚native_case create` 鈫?reviewer `native_case replay` 鈫?  `native_review` 缁戝畾 鈫?`native_publish_finding`

## 6. 瀵硅处锛堝凡鐭ヨ竟鐣岋級

鍒涘缓灏佸嵃锛坈reation seal锛夌洰鍓嶅彧鍦?finalize 闃舵钀藉簱銆傚鏋?runner 鐨?final 甯т涪澶变笖鍙戠敓鍦ㄥ皝鍗颁箣鍓嶏紝
鏁版嵁搴撲細淇濈暀 `resource_hold=true` + `cleanup_status=unknown`锛屾鏃?*涓嶈兘鐢?* sealed cleanup 璺緞
缁撶畻锛堟病鏈夊皝鍗帮級銆傝繖浼氭妸鍞竴 worker 妲藉崰浣忥紝鐩村埌杩愮淮鏄惧紡瀵硅处锛?
```
POST /api/tasks/{id}/reverse/native/campaigns/{cid}/reconcile
```

瀵硅处鍋氱殑浜嬶細

1. 鎵惧埌璇ユ垬褰逛笅鍞竴銆屾寔妲戒笖娓呯悊鏈煡銆嶇殑灏濊瘯锛?2. 鏍￠獙鍏惰祫婧愯鍒掗噷鐨勬瘡涓鍣ㄥ湪 docker 涓?*閮藉凡涓嶅瓨鍦?*锛屼笖鏆傚瓨鐩綍宸插垹闄わ紱
3. 閫氳繃鍚庢墠閲婃斁妲戒綅銆佹妸灏濊瘯涓庢垬褰规爣涓?`cleanup=verified`锛屽苟鍐欏叆
   `cleanup.retry` / `cleanup.verified` 浜嬩欢銆?
瀹冧笉鍒涘缓璧勬簮銆佷笉鎺ョ鎵€鏈夋潈銆佷笉鏀瑰彉鐘舵€佹満鍘嗗彶锛涢噸澶嶈皟鐢ㄨ繑鍥?`state_conflict`銆傚璐︽垚鍔熷悗璋冨害绔嬪嵆
鎭㈠锛屾棤闇€閲嶅惎銆?
> 鍚庣画璁″垝锛氭妸灏佸嵃鏀逛负 attempt 鍚姩纭鍚庣珛鍗宠惤搴擄紝浠庢牴涓婃秷闄よ繖涓€绐楀彛锛涘綊妗ｆ壒娆?> 锛坄task_archives` v6 + campaign 褰掓。琛?瀹堝崼锛変粛寰呯Щ妞嶃€?
## 7. 鎺掗殰娓呭崟

| 鐜拌薄 | 鎺掓煡 |
| --- | --- |
| HTTP 404 / not_found | 浠诲姟涓嶆槸 reverse锛屾垨 campaign 涓嶅睘浜庤浠诲姟 |
| `environment_incompatible` | 鐜鍙橀噺缂哄け/璺緞涓嶅悎瑙勶紙蹇呴』缁濆璺緞銆佺鏈夌洰褰曘€佺┖ docker 閰嶇疆鐩綍锛?|
| `authorization_revoked: task unavailable` | 浠诲姟宸叉殏鍋滄垨缁堟€侊紱鍏?`resume` 浠诲姟 |
| `checkpoint_invalid` | 鏆傚仠钀藉湪"灏氭湭寮€濮嬪啓鍏?鐨勭獥鍙ｏ紱鎴栨鏌ョ偣閲囬泦澶辫触 |
| `runner_wait_failed` + `final_lost` | runner 鏈湪绐楀彛鍐呭畬鎴愬惎鍔紱鐪?`[native campaign] ... runner errors` 鏃ュ織涓?`reconcile` |
| 璋冨害鍋滄憜锛坮esidual attempt ids锛?| 瀛樺湪鎸佹Ы灏濊瘯锛涚‘璁よ祫婧愬凡娑堝け鍚?`reconcile` |
| `budget_exhausted` | 鎬婚绠楃敤灏斤紝闇€鏂板缓鎴樺焦 |
## 8. Agent 工具（native_campaign）

`native_fuzz` 是**一次性同步**模糊测试（保留为 fallback）；`native_campaign` 是持久化战役的入口，
只挂给 `reverse_dynamic` 角色，且仅当服务端配置了 campaign 运行时才会出现（未配置时调用会明确
报错并提示改用 `native_fuzz`）。

| action | 必填 | 说明 |
| --- | --- | --- |
| `start` | `artifact_id` `profile_id` `seeds` | 创建并排队一个战役；其余字段有界默认值（总预算 300s、单次尝试 120s、`max_executions` 100000、`max_crashes` 8、`input_mode` stdin） |
| `status` | `campaign_id` | 返回状态机、预算电荷、检查点、清理结论 |
| `list` | — | 最近战役（默认 20，上限 50） |
| `pause` / `resume` / `cancel` | `campaign_id` `expected_state_version` | 乐观并发控制；版本不符返回 `state_conflict` |

约定：

- 同一个意图内重复调用 `start` 是幂等的（请求 id 由 task/intent/exploration 派生），不会产生第二个战役；
- 轮询 `status` 的频率不应快于 10 秒一次；
- 工具的返回值同样标记 `candidate_only=true`，崩溃候选升级路径与一次性 fuzz 完全一致。

## 9. 归档与恢复（v6）

任务归档格式版本为 **6**。v6 快照除原有表外，固定纳入 9 张 campaign 表：

`native_campaigns`、`native_campaign_attempts`、`native_campaign_objects`、
`native_campaign_corpus_manifests`、`native_campaign_corpus_entries`、
`native_campaign_checkpoints`、`native_campaign_evidence`、`native_campaign_requests`、
`native_campaign_events`。

归档流程（服务端）：

1. `POST /api/tasks/{id}/archive`；任务必须已暂停、无运行中的 Agent，且**没有持槽/未结算的
   campaign attempt**（campaign 独立占用唯一 worker 槽，仅暂停任务不足以归档）。
2. 暂存 payload（`files/tasks/<id>` 整棵任务目录 + `traffic/` + `evidence/`），随后执行
   `verifyNativeCampaignArchiveFiles`：对快照里每个 campaign object / evidence 引用校验
   **路径安全、长度上限、sha256**；暂存内容不匹配即失败，绝不压缩进包。
3. `compactNativeCampaignArchiveTx` 在同一事务内把 `phase` 置为 `database_compacting`、
   `format_version=6`、`compaction_txid=txid_current()`，删除已归档的 campaign 行；库内触发器
   （evidence / events / corpus entries 等）仅在此事务内放行删除，其余路径一律拒绝。
4. 完成后 `phase=ready`、`compaction_txid=NULL`。

恢复流程：

1. 解包后再次执行 `verifyNativeCampaignArchiveFiles`（只信任刚解出来的 payload）。
2. `validateNativeCampaignArchiveScope` 校验完整图谱（指针、唯一性、预算/检查点一致性）。
3. 行恢复后为每个 campaign 写入 `campaign.archive_restored` 事件；该事件使
   `start`/`resume`/`cancel` 之外的执行路径返回 `archive_restore_not_executable`，即**已恢复的
   战役只能读数，不能执行**。

兼容性：`format_version < 6` 的历史包仍可恢复；但历史包中若出现 campaign 表，会被
`validateNativeCampaignArchiveScope` 判为非法（老版本不会产生这些表）。

运维小工具：`go run tools-archive-list.go <package.tar.zst> [filter]` 可列出包内条目，用于确认
campaign 证据文件是否随包保留。
