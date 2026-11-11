# 成员会话复用原任务组件的验证记录

日期：2026-11-11。本次更新 main，不创建或移动 tag。

## 改动

- 原任务和成员任务共用 `TaskSessionLayout`、`SessionSidebar`、`TaskSessionPanel`、`TokenMetrics`；原界面的会话分组、状态图标、编号、设备标识、单行标题、滚动容器和响应式布局只有一份实现。
- 成员会话直接进入上述布局，移除额外“任务会话”卡片与三行会话卡片。分支会话也进入同一列表，使用 `#B编号` 区分，仍通过分支原有命令接口发送指导。
- 成员消息使用原 `Transcript` / `Markdown`，处理标题、加粗、列表、代码块、表格和引用。消息来自原有脱敏接口；不会请求主端原始活动详情。成员/设备来源和引导交付状态保留。
- 补齐系统审计会话，仅返回当前任务中模型切换、故障转移的摘要。模型名称与可用状态通过任务范围内的原接口读取。
- 保留两秒补取、按编号去重、历史分页、执行端编号与 epoch、原发送授权。主 Agent 与 Planner 的成员入口仍只读，管理操作仍受原权限限制；本次没有数据库迁移或 Node 协议变更。

## 自动验证

使用独立 PostgreSQL，`ARTEX_PG_DSN` 指向测试库；不连接业务库运行测试。

```sh
go test -race ./server ./db \
  -run 'TestTeamTaskNative|TestTeamMessage|TestTeamSystemSession|TestTeamRunningWorker|TestTeamSharedSessions' \
  -count=1 -v -timeout 5m

cd web
node --test src/components/team-branch-messages-state.test.mjs
npm run build:static -- --webpack
```

- 后端 6 项顶层定向测试通过，覆盖系统审计摘要隔离与分页、消息权限、Worker 准入状态、任务范围及原消息去重/封口链路；原任务资料接口子用例同时通过。浏览器夹具默认跳过，另行启用。
- 分支前端 3 项状态测试通过，覆盖按分支取事件、撤回过程权限时清空缓存和禁止继续翻页、事件过滤及重放去重。
- 完整前端编译、TypeScript 检查及静态页面导出通过。

## 浏览器验收

使用 `TestTeamTaskNativeBrowserPreview`，在同一份合成任务上分别打开主端和成员入口。预览只绑定回环地址，未配置模型，不运行真实工具或外部目标。

- 浏览器实测两侧会话栏均宽 288px、高 512px；主 Agent 会话行均高 32px，行样式类相同，桌面页面无横向溢出。
- 成员页面可见主 Agent、Planner、系统审计、Workers、任务总计与会话用量。Markdown 的加粗、列表、代码块、表格均生成对应 DOM；没有直接显示原始加粗标记。
- Planner 的 107 条合成消息首屏取最近 100 条；点击“更早历史”补齐余下 7 条并保留当前会话。
- 系统会话显示合成模型切换摘要，未展示夹具里的私有详情。
- 只读成员查看运行中 Worker 时没有发送框；切换到有执行权限的成员后，可通过原样输入区发送合成引导，并在自动补取后看到消息，无需退出任务。
- 浏览器错误日志为空。此次 UI 对照验证了主任务的共享会话与本机 Worker 引导；分支消息状态有前端回归覆盖，未在此浏览器夹具执行真实分支工作，亦不代表两台物理设备的网络验收。

操作说明见 [团队共享消息](team-shared-messages.md)。
