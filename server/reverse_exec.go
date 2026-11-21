package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// sandboxExecReadOnly is the command set a software-audit worker may run without a
// target runtime. Everything here only reads bytes; nothing builds, installs or
// touches the network.
var sandboxExecReadOnly = map[string]bool{
	"readelf": true, "objdump": true, "strings": true, "nm": true, "file": true,
	"xxd": true, "sha256sum": true, "grep": true, "head": true, "tail": true, "wc": true, "sort": true,
}

// sandboxExecScripts adds interpreters. They can do anything a process can, so they
// stay out of the reviewer role and out of the static role's dynamic path.
var sandboxExecScripts = map[string]bool{"python3": true}

// sandboxExecLimits bounds one call. The tool is deliberately not a shell: argv is
// executed directly, so `;`, `|`, `$()` and redirection are ordinary arguments and
// cannot chain commands.
const (
	sandboxExecMaxArgv    = 32
	sandboxExecMaxArgLen  = 8192
	sandboxExecMaxArgBytes = 32768
	sandboxExecMaxOutput  = 1 << 20
	sandboxExecDefaultMux = 60
	sandboxExecMaxTimeout = 600
)

// reverseExecTool exposes a bounded, whitelisted command runner to the software
// workflow. Software exploration needs to execute read-only analysis commands
// (objdump/readelf/python audit scripts) that the disassembly and REA tools do not
// cover; without it the workers can only look, never compute. Every call is
// recorded as an evidence file so a conclusion can point at what was actually run.
func reverseExecTool(task *db.Task, info agent.RunInfo, dir, role string) actool.CoreTool {
	schema := reverseObject(map[string]any{
		"argv":       map[string]any{"type": "array", "items": reverseString(), "minItems": 1, "maxItems": sandboxExecMaxArgv},
		"purpose":    reverseString(),
		"timeout_ms": reverseInt(),
	}, "argv")
	return reverseTool("sandbox_exec",
		"在任务工作目录内执行一条白名单命令（不经过 shell，不能用管道/重定向串联）。用于运行只读分析工具与审计脚本（readelf/objdump/strings/nm/file/xxd/sha256sum/python3）。每次调用都会写一份执行证据文件，结论可引用 result_path。不能联网、不能写材料目录、不能执行未登记的命令。",
		schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var req struct {
				Argv      []string `json:"argv"`
				Purpose   string   `json:"purpose"`
				TimeoutMS int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				return actool.Errorf("sandbox_exec 参数必须是 JSON 对象"), nil
			}
			if len(req.Argv) == 0 {
				return actool.Errorf("sandbox_exec 需要非空的 argv"), nil
			}
			name := filepath.Base(req.Argv[0])
			// Commands are resolved through PATH by name only: a path-qualified argv[0]
			// would let the caller pick any binary outside the whitelist entry it looks like.
			if strings.ContainsAny(req.Argv[0], `/\`) {
				return actool.Errorf("sandbox_exec 只接受命令名（按 PATH 解析），不接受路径形式"), nil
			}
			if !sandboxExecCommandAllowed(name, role) {
				return actool.Errorf(fmt.Sprintf("命令 %q 不在当前角色的白名单内；可用：%s", name, sandboxExecAllowedList(role))), nil
			}
			totalArgBytes := 0
			for _, arg := range req.Argv {
				totalArgBytes += len(arg)
				if len(arg) > sandboxExecMaxArgLen || strings.ContainsRune(arg, 0) {
					return actool.Errorf(fmt.Sprintf("参数过长或包含 NUL：单参数上限 %d 字节", sandboxExecMaxArgLen)), nil
				}
			}
			if totalArgBytes > sandboxExecMaxArgBytes {
				return actool.Errorf(fmt.Sprintf("参数合计 %d 字节，超过单次上限 %d 字节；请把较长的脚本写成文件后再执行", totalArgBytes, sandboxExecMaxArgBytes)), nil
			}
			if task == nil || dir == "" {
				return actool.Errorf("sandbox_exec 缺少任务工作目录"), nil
			}
			timeout := req.TimeoutMS
			if timeout <= 0 {
				timeout = sandboxExecDefaultMux * 1000
			}
			if timeout > sandboxExecMaxTimeout*1000 {
				timeout = sandboxExecMaxTimeout * 1000
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
			defer cancel()
			started := time.Now()
			cmd := exec.CommandContext(runCtx, req.Argv[0], req.Argv[1:]...)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "LANG=C.UTF-8"}
			limited := &execLimitWriter{limit: sandboxExecMaxOutput}
			cmd.Stdout, cmd.Stderr = limited, limited
			runErr := cmd.Run()
			elapsed := time.Since(started)
			exitCode := 0
			timedOut := false
			if runErr != nil {
				if runCtx.Err() == context.DeadlineExceeded {
					timedOut = true
					exitCode = -1
				} else if ee, ok := runErr.(*exec.ExitError); ok {
					exitCode = ee.ExitCode()
				} else {
					return actool.Errorf(fmt.Sprintf("执行失败：%v", runErr)), nil
				}
			}
			out := limited.Bytes()
			sum := sha256.Sum256(out)
			record := map[string]any{
				"operation":   "sandbox_exec",
				"authority":   "static-inspection",
				"role":        role,
				"purpose":     req.Purpose,
				"argv":        req.Argv,
				"exit_code":   exitCode,
				"timed_out":   timedOut,
				"elapsed_ms":  elapsed.Milliseconds(),
				"output_sha":  hex.EncodeToString(sum[:]),
				"truncated":   limited.Truncated(),
				"output_tail": tailString(out, 8000),
				"task_id":     task.ID,
				"intent_id":   info.IntentID,
				"recorded_at": time.Now().UTC().Format(time.RFC3339),
			}
			execDir := filepath.Join(dir, "exec")
			if err := os.MkdirAll(execDir, 0o755); err != nil {
				return actool.Errorf(fmt.Sprintf("无法创建执行证据目录：%v", err)), nil
			}
			path := filepath.Join(execDir, fmt.Sprintf("%d-%d.json", time.Now().UnixNano(), info.IntentID))
			encoded, _ := json.MarshalIndent(record, "", "  ")
			if err := os.WriteFile(path, encoded, 0o644); err != nil {
				return actool.Errorf(fmt.Sprintf("无法写入执行证据：%v", err)), nil
			}
			if timedOut {
				return reverseJSON(map[string]any{"result_path": path, "timed_out": true, "timeout_ms": timeout, "hint": "缩短输入或拆分命令后重试"}), nil
			}
			return reverseJSON(map[string]any{
				"result_path":  path,
				"exit_code":    exitCode,
				"truncated":    limited.Truncated(),
				"output":       tailString(out, 8000),
				"output_sha":   hex.EncodeToString(sum[:]),
				"elapsed_ms":   elapsed.Milliseconds(),
				"read_only":    true,
				"next_hint":    "需要完整输出时按 result_path 读取；结论引用该路径作为执行证据。",
			}), nil
		})
}

func sandboxExecCommandAllowed(name, role string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return false
	}
	if sandboxExecReadOnly[name] {
		return true
	}
	if sandboxExecScripts[name] {
		return role == "reverse_static" || role == "reverse_dynamic" || role == "worker"
	}
	return false
}

func sandboxExecAllowedList(role string) string {
	names := make([]string, 0, len(sandboxExecReadOnly)+1)
	for n := range sandboxExecReadOnly {
		names = append(names, n)
	}
	if role != "reverse_reviewer" {
		for n := range sandboxExecScripts {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

// execLimitWriter buffers up to limit bytes and counts the rest, so a runaway tool
// cannot exhaust memory while we still report that output was cut.
type execLimitWriter struct {
	limit     int
	buf       []byte
	total     int
	truncated bool
}

func (w *execLimitWriter) Write(p []byte) (int, error) {
	w.total += len(p)
	if len(w.buf) < w.limit {
		remain := w.limit - len(w.buf)
		if len(p) <= remain {
			w.buf = append(w.buf, p...)
		} else {
			w.buf = append(w.buf, p[:remain]...)
			w.truncated = true
		}
	} else {
		w.truncated = true
	}
	return len(p), nil
}

func (w *execLimitWriter) Bytes() []byte { return w.buf }
func (w *execLimitWriter) Truncated() bool {
	return w.truncated
}

func tailString(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[len(b)-n:])
}
