# 逆向 Android 与浏览器交互

本文说明逆向任务如何在授权的 Android 或浏览器环境中执行多步交互，并把每一步观察保存到当前任务证据中。人只需在任务“分析档案”的“运行时观察”区域选择环境、材料和时间上限，再让 Agent 按目标完成操作；不需要自己调用工具。

## 使用流程

1. 建立逆向任务并上传待分析材料。
2. 在“分析档案 → 运行时观察”中暂停任务，启用运行时观察，选择可用实验环境与可运行材料，设置单段时间上限并保存。已有授权值会保留；只有明确保存新值才会更改。
3. 恢复任务，并说明要回答的行为问题及期望观察。Agent 按问题选择静态定位或动态观察；已有明确入口时可直接执行 Android 操作或浏览器场景，保存证据并安排独立 Reviewer。
4. 在运行时观察记录、工作流进度或结论中查看结果和证据引用。明确支持或反证的结论由 Reviewer 自动标记为 `accepted` 或 `rejected`；证据不足、相互冲突或环境无法复现的结论标记为 `unresolved`，并说明待人工复审的问题。

授权同时限定任务、材料、环境及时长。环境出现在列表中只代表配置存在，不代表设备在线或某个页面可以访问。

## 运行时上限

运行时观察授权可设置 100 毫秒至 900 秒的最大时长。旧有授权值不会在升级时被重置。这个值是单段观察的授权上限；任务截止时间、Agent/Worker 执行预算或取消操作可能更早结束它。

`reverse_observe_runtime` 用于一次性观察，时长最多 60 秒。需要保持应用状态、连续点击并关联调用时，Agent 使用 `reverse_runtime_session`：一次启动会创建一个有界 Frida 会话，后续步骤继续使用该会话，直到停止或结束。会话归当前任务和 Worker 使用，不能被另一任务接管。任务结束、取消、会话超时或 Worker 退出时会触发清理；Android 设备按 ADB 配置互斥，同一时刻只能由一个持续观察占用。

## 管理员配置实验环境

运行环境由管理员在 `ARTEX_REVERSE_RUNTIME_PROFILES` 指向的 JSON 文件中配置。以下是格式示例；将占位路径、设备序列号和允许来源替换为本机已安装的环境。此示例仅展示配置形状，不表示这些环境已经安装或可用。

```json
[
  {
    "id": "android-lab",
    "name": "Android 实验设备",
    "platform": "android",
    "command": "/opt/artex/frida-venv/bin/python",
    "args": ["/opt/artex/scripts/reverse_runtime.py"],
    "settings": {
      "adb": "/opt/android-sdk/platform-tools/adb",
      "adb_port": 5037,
      "adb_serial": "emulator-5554",
      "aapt": "/opt/android-sdk/build-tools/35.0.0/aapt",
      "allow_package_install": true,
      "remote": { "address": "127.0.0.1:27042" },
      "remote_is_lab": true,
      "java_bridge_module": "/opt/artex/node_modules/frida-java-bridge/index.js"
    }
  },
  {
    "id": "browser-lab",
    "name": "隔离浏览器",
    "platform": "browser",
    "settings": {
      "executable_path": "/opt/chromium/chrome-headless-shell",
      "allowed_origins": ["http://127.0.0.1:8080"],
      "library_path": "/opt/chromium/lib:/usr/local/lib",
      "secrets": [
        {
          "secret_id": "fixture-login",
          "environment_variable": "ARTEX_FIXTURE_LOGIN"
        }
      ]
    }
  }
]
```

Android 配置需要指向本机 Frida Python 环境、ADB、设备及所需 Android 工具。浏览器配置使用已安装的 Chromium 可执行文件；`allowed_origins` 是该 profile 允许作为场景起始页或显式导航目标的来源。`library_path` 是可选的绝对库路径列表；Linux 示例以冒号分隔。

浏览器密码等值不要写入 profile、场景动作或任务材料。`settings.secrets` 只保存密钥编号与服务进程环境变量名的映射；场景动作引用 `secret_id`，由 REA 从配置的环境变量取值并对捕获内容做脱敏。示例中的变量名只是占位配置。

## Android 连续交互

Agent 为当前材料与包名启动会话后，可在同一 `session_id` 下启动应用、读取 UI 树和截图、点击、输入文本、按键或滑动；`read` 获取最新调用记录，`wait` 等待有限时间后读取一次。每一步都会生成独立的运行证据；截图以文件和摘要保存。

下面展示 Agent 可能按顺序执行的命令形状。它们代表多次会话操作，不是一次批量提交；坐标会由 Agent 根据当时的截图与 UI 树确定，`session_id` 使用启动结果返回的值。

```json
[
  { "action": "android_launch", "session_id": "<start 返回的 session_id>" },
  { "action": "android_snapshot", "session_id": "<同一 session_id>" },
  { "action": "android_tap", "session_id": "<同一 session_id>", "x": 220, "y": 180 },
  { "action": "android_input", "session_id": "<同一 session_id>", "text": "fixture value" },
  { "action": "android_key", "session_id": "<同一 session_id>", "key": "KEYCODE_ENTER" },
  { "action": "android_snapshot", "session_id": "<同一 session_id>" },
  { "action": "stop", "session_id": "<同一 session_id>" }
]
```

会话的启动信息还包含当前授权的材料、Android profile、包名、Frida 观察脚本和持续时长。Agent 会结合静态分析选择要观察的方法，并核对执行前后的画面、调用与材料 SHA256。示例坐标只说明参数形式，不能直接用于不同分辨率或布局。

## 浏览器多步场景

`reverse_browser_scenario` 在一次工具调用内将原生 REA 6.8.0 场景动作按顺序执行。支持 `goto`、`fill`、`click`、`press`、`select_option`、`check`、`uncheck`、`wait_for`、`wait_for_timeout` 和 `request` 等动作；动作使用 REA 的 `step_id`、`action`、`locator` 等原生字段。每次调用都通过 profile 中的可执行文件以自有 launch 模式启动新的浏览器上下文，不附加渗透任务正在使用的浏览器。下一次调用会获得新上下文，不复用上一次的页面登录状态或浏览器存储。

下面是动作与捕获选项的结构示例。通常由 Agent 根据问题与静态定位生成；页面来源和显式 `goto` 目标必须属于所选 profile 的 `allowed_origins`。

```json
{
  "artifact_id": 42,
  "profile_id": "browser-lab",
  "start_url": "http://127.0.0.1:8080/fixture.html",
  "duration_ms": 120000,
  "actions": [
    {
      "step_id": "enter-value",
      "action": "fill",
      "locator": { "kind": "test_id", "value": "value" },
      "value": { "source": "literal", "value": " fixture demo " }
    },
    {
      "step_id": "submit",
      "action": "click",
      "locator": { "kind": "test_id", "value": "submit" }
    },
    {
      "step_id": "settle",
      "action": "wait_for_timeout",
      "duration_ms": 300
    }
  ],
  "capture": {
    "after_each_step": ["url"],
    "at_end": ["dom", "screenshot"],
    "events": ["network", "console", "page-errors"],
    "network": {
      "request_body": true,
      "response_body": true,
      "header_values": false
    }
  }
}
```

若场景需要 profile 中配置的密码，动作只引用编号，不内嵌值：

```json
{
  "step_id": "enter-password",
  "action": "fill",
  "locator": { "kind": "test_id", "value": "password" },
  "value": { "source": "secret", "secret_id": "fixture-login" }
}
```

场景结果会与当前任务、意图、材料 SHA256 和运行记录关联，保存原始 REA 结果及所选页面、网络、控制台等证据。页面中发出的其他请求是否能访问仍受实验环境和网络配置影响；`allowed_origins` 用于校验场景显式指定的起始与导航 URL。

## 角色边界与能力范围

动态执行者只在任务 runtime policy 已授权的材料和环境中操作；静态角色负责定位入口与解释结构，动态角色进行最小必要交互，独立 Reviewer 重读原始证据并给出接受、拒绝或未决结果。一个结论只有在满足对应证据标准并由独立 Reviewer 接受后，才可用于证明目标。

本轮交互范围针对 Android 与浏览器场景。浏览器场景不等同于完整 Electron 桌面控制；不据此推断所有 Windows/Linux 调试器均已配置，也不代表 Appium 已安装。具体 profile、页面、设备、材料和模型执行预算均需分别检查。
