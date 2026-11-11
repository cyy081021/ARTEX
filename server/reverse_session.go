package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Android UI and package installation are device-global. Serialize owned runs
// on the configured device, including legacy one-shot observations.
var reverseDeviceLeases sync.Map

func acquireReverseDevice(p reverseRuntimeProfile) (func(), error) {
	if p.Platform != "android" {
		return func() {}, nil
	}
	key := fmt.Sprintf("%v/%v/%v", p.Settings["adb"], p.Settings["adb_port"], p.Settings["adb_serial"])
	if _, busy := reverseDeviceLeases.LoadOrStore(key, true); busy {
		return nil, errors.New("该 Android 设备正在进行另一段观察，请等待当前会话结束")
	}
	return func() { reverseDeviceLeases.Delete(key) }, nil
}

type reverseSessionFrame struct {
	RequestID   string         `json:"request_id"`
	Kind        string         `json:"kind"`
	Observation map[string]any `json:"observation"`
}

// A session belongs to exactly one worker invocation. No external identifier
// can attach it to another task or intent. All output is persisted before it is
// made visible to the model; terminal cleanup is recorded even without a caller.
type reverseSession struct {
	mu           sync.Mutex
	writeMu      sync.Mutex
	id           string
	runID        int64
	profile      reverseRuntimeProfile
	artifact     *db.ReverseArtifact
	script       string
	dir, workDir string
	command      *exec.Cmd
	in           io.WriteCloser
	done         chan struct{}
	pending      map[string]chan map[string]any
	last         map[string]any
	terminal     bool
	finish       func(string, string, string) error
	release      func()
}

func (s *reverseSession) write(v any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return json.NewEncoder(s.in).Encode(v)
}

func (s *reverseSession) persist(frame reverseSessionFrame) (map[string]any, error) {
	observation := frame.Observation
	if observation == nil {
		return nil, errors.New("运行器缺少观察结果")
	}
	if screenshot, ok := observation["screenshot_base64"].(string); ok && screenshot != "" {
		if len(screenshot) > 6<<20 {
			return nil, errors.New("截图超出保存上限")
		}
		data, err := base64.StdEncoding.DecodeString(screenshot)
		if err != nil || len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
			return nil, errors.New("运行器截图不是有效 PNG")
		}
		file, err := os.CreateTemp(s.dir, "runtime-screen-*.png")
		if err != nil {
			return nil, err
		}
		_ = file.Chmod(0600)
		_, err = file.Write(data)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("运行时截图保存失败")
		}
		rel, _ := filepath.Rel(s.workDir, file.Name())
		digest := sha256.Sum256(data)
		observation["screenshot"] = map[string]any{"path": filepath.ToSlash(rel), "sha256": hex.EncodeToString(digest[:]), "bytes": len(data)}
		delete(observation, "screenshot_base64")
	}
	var runErr error
	if frame.Kind == "final" {
		runErr = reverseRuntimeObservationError(observation, s.profile.Platform, s.artifact.SHA256, s.script)
		if observation["reason"] == "detached" {
			runErr = errors.New("Frida 观察意外断开，最终清理证据已保存")
		}
	} else {
		hash := sha256.Sum256([]byte(s.script))
		if observation["platform"] != s.profile.Platform || observation["artifact_sha256"] != s.artifact.SHA256 || observation["script_sha256"] != hex.EncodeToString(hash[:]) {
			runErr = errors.New("观察结果的材料、平台或脚本标识不匹配")
		}
		if observation["error"] != nil {
			runErr = errors.New("交互步骤未完成，详见原始证据")
		}
	}
	if failures, ok := observation["errors"].([]any); ok && len(failures) > 0 {
		runErr = errors.New("运行时观察报告错误，详见原始证据")
	}
	record := map[string]any{"isError": runErr != nil, "structuredContent": map[string]any{
		"operation": "reverse_runtime_session", "session_id": s.id, "run_id": s.runID, "phase": frame.Kind, "request_id": frame.RequestID,
		"provider":          map[string]any{"name": "Frida", "version": observation["version"]},
		"subject":           map[string]any{"digest": map[string]any{"sha256": s.artifact.SHA256}, "name": s.artifact.Name},
		"normalized_result": observation, "confidence": "observed", "authority": "controlled-replay",
	}}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.dir, "runtime-session-*.json")
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0600)
	_, err = f.Write(encoded)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return nil, errors.New("运行时证据保存失败")
	}
	rel, _ := filepath.Rel(s.workDir, f.Name())
	status, message := "running", ""
	if frame.Kind == "final" {
		status = "completed"
		if observation["reason"] == "cancelled" || observation["cancelled"] == true {
			status = "cancelled"
		}
	}
	if runErr != nil {
		status, message = "failed", runErr.Error()
	}
	return map[string]any{"session_id": s.id, "run_id": s.runID, "phase": frame.Kind, "status": status, "result_path": filepath.ToSlash(rel), "bytes": len(encoded), "preview": reaPreview(encoded), "message": message, "is_error": runErr != nil}, nil
}

func (s *reverseSession) read(out io.Reader) {
	defer close(s.done)
	defer s.release()
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 64<<10), 9<<20)
	var final map[string]any
	var readErr error
	for scanner.Scan() {
		var frame reverseSessionFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil || (frame.Kind != "ready" && frame.Kind != "step" && frame.Kind != "snapshot" && frame.Kind != "final") {
			readErr = errors.New("运行器返回无效会话协议")
			break
		}
		result, err := s.persist(frame)
		if err != nil {
			readErr = err
			break
		}
		s.mu.Lock()
		s.last = result
		ch := s.pending[frame.RequestID]
		if frame.Kind == "final" {
			s.terminal, final = true, result
		}
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- result:
			default:
			}
		}
		if frame.Kind == "final" {
			break
		}
	}
	if readErr == nil {
		readErr = scanner.Err()
	}
	if final == nil {
		_ = s.write(map[string]any{"cancel": true})
		_ = s.in.Close()
	}
	// A malformed/noisy runner must not leave its owned process alive forever.
	stop := time.AfterFunc(45*time.Second, func() { _ = s.command.Process.Kill() })
	_, _ = io.Copy(io.Discard, out)
	waitErr := s.command.Wait()
	stop.Stop()
	if final == nil || waitErr != nil {
		if readErr == nil {
			readErr = errors.New("运行器退出，未确认最终清理")
		}
		if final == nil {
			final, _ = s.persist(reverseSessionFrame{Kind: "final", RequestID: "final", Observation: map[string]any{"error": readErr.Error(), "errors": []any{readErr.Error()}, "cleanup": map[string]any{}, "reason": "error"}})
		}
		if final == nil {
			final = map[string]any{"session_id": s.id, "run_id": s.runID, "status": "failed", "phase": "final", "is_error": true, "result_path": ""}
		}
		copyResult := make(map[string]any, len(final))
		for k, v := range final {
			copyResult[k] = v
		}
		final = copyResult
		final["status"], final["is_error"], final["message"] = "failed", true, readErr.Error()
	}
	s.mu.Lock()
	s.terminal, s.last = true, final
	s.mu.Unlock()
	if err := s.finish(final["status"].(string), reverseSessionString(final["result_path"]), reverseSessionString(final["message"])); err != nil {
		copyResult := make(map[string]any, len(final))
		for k, v := range final {
			copyResult[k] = v
		}
		final = copyResult
		final["status"], final["is_error"], final["db_status_saved"] = "failed", true, false
		message := "最终运行状态写入数据库失败；本地证据已保留"
		if prior := reverseSessionString(final["message"]); prior != "" {
			message = prior + "；" + message
		}
		final["message"] = message
	}
	s.mu.Lock()
	s.terminal, s.last = true, final
	s.mu.Unlock()
}

func (s *reverseSession) request(ctx context.Context, command map[string]any) (map[string]any, error) {
	forCommand := func(result map[string]any) map[string]any {
		if result["phase"] == "final" && command["action"] != "read" && command["action"] != "stop" {
			copyResult := make(map[string]any, len(result))
			for k, v := range result {
				copyResult[k] = v
			}
			copyResult["is_error"], copyResult["command_completed"], copyResult["message"] = true, false, "会话已经结束，本次交互步骤未确认执行；请读取结束证据后决定是否新建会话"
			return copyResult
		}
		return result
	}
	id := newReverseSessionID()
	command["request_id"] = id
	ch := make(chan map[string]any, 1)
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		<-s.done
		s.mu.Lock()
		result := s.last
		s.mu.Unlock()
		return forCommand(result), nil
	}
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock() }()
	if err := s.write(command); err != nil {
		return nil, err
	}
	select {
	case result := <-ch:
		if result["phase"] == "final" {
			<-s.done
			s.mu.Lock()
			defer s.mu.Unlock()
			return forCommand(s.last), nil
		}
		return result, nil
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return forCommand(s.last), nil
	case <-ctx.Done():
		s.close()
		return nil, ctx.Err()
	}
}

func (s *reverseSession) close() {
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.write(map[string]any{"cancel": true})
	_ = s.in.Close()
	select {
	case <-s.done:
	case <-time.After(45 * time.Second):
		_ = s.command.Process.Kill()
		<-s.done
	}
}

func newReverseSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
func reverseSessionString(v any) string { s, _ := v.(string); return s }

type reverseSessionManager struct {
	mu       sync.Mutex
	closed   bool
	ctx      context.Context
	pg       *db.DB
	task     *db.Task
	info     agent.RunInfo
	workDir  string
	sessions map[string]*reverseSession
}

func (m *reverseSessionManager) close() {
	m.mu.Lock()
	m.closed = true
	sessions := make([]*reverseSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
}

func (m *reverseSessionManager) start(ctx context.Context, a map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return nil, errors.New("工作单已结束")
	}
	for _, s := range m.sessions {
		select {
		case <-s.done:
		default:
			return nil, errors.New("本工作单已有持续观察，请先结束当前会话")
		}
	}
	if len(m.sessions) >= 16 {
		return nil, errors.New("本工作单持续会话数量已达上限")
	}
	artifactID, _ := a["artifact_id"].(float64)
	duration, _ := a["duration_ms"].(float64)
	script := reverseSessionString(a["script"])
	if strings.TrimSpace(script) == "" || len(script) > 128<<10 || duration < 100 || duration > 900000 {
		return nil, errors.New("请提供有效脚本和 100–900000ms 的会话上限")
	}
	profiles, err := reverseRuntimeProfiles()
	if err != nil {
		return nil, err
	}
	var profile *reverseRuntimeProfile
	for i := range profiles {
		if profiles[i].ID == reverseSessionString(a["profile_id"]) {
			profile = &profiles[i]
			break
		}
	}
	if profile == nil || profile.Platform != "android" {
		return nil, errors.New("持续会话请选择 Android 运行环境；浏览器使用 reverse_browser_scenario，Windows/Linux 使用 reverse_observe_runtime")
	}
	artifact, err := m.pg.GetReverseArtifact(m.task.ID, int64(artifactID))
	if err != nil || artifact == nil {
		return nil, errors.New("材料不存在")
	}
	prefix := filepath.Join("tasks", strconv.FormatInt(m.task.ID, 10), "reverse")
	artifact.Path, err = reverseLocalPath(m.workDir, artifact.Path, filepath.Join(prefix, "artifacts"))
	if err != nil {
		return nil, err
	}
	if err = verifyArtifact(artifact); err != nil {
		return nil, err
	}
	release, err := acquireReverseDevice(*profile)
	if err != nil {
		return nil, err
	}
	runID, err := m.pg.BeginReverseRuntimeRun(ctx, m.task.ID, artifact.ID, m.info.IntentID, profile.ID, int(duration))
	if err != nil {
		release()
		return nil, err
	}
	finish := func(status, path, message string) error {
		return m.pg.FinishReverseRuntimeRun(runID, status, path, message)
	}
	fail := func(err error) (map[string]any, error) {
		release()
		if dbErr := finish("failed", "", err.Error()); dbErr != nil {
			return nil, fmt.Errorf("%w；运行状态写入数据库失败：%v", err, dbErr)
		}
		return nil, err
	}
	dir := filepath.Join(m.workDir, prefix, "results")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return fail(err)
	}
	cmd := exec.Command(profile.Command, profile.Args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return fail(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return fail(err)
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		_ = in.Close()
		return fail(errors.New("运行器无法启动"))
	}
	s := &reverseSession{id: newReverseSessionID(), runID: runID, profile: *profile, artifact: artifact, script: script, dir: dir, workDir: m.workDir, command: cmd, in: in, done: make(chan struct{}), pending: map[string]chan map[string]any{}, finish: finish, release: release}
	ready := make(chan map[string]any, 1)
	s.pending["start"] = ready
	m.sessions[s.id] = s
	go s.read(out)
	mapped := artifact.Path
	for _, mapping := range profile.PathMappings {
		from := strings.TrimRight(mapping.From, "/\\")
		if strings.HasPrefix(filepath.ToSlash(mapped), from+"/") {
			mapped = mapping.To + strings.TrimPrefix(filepath.ToSlash(mapped), from)
			break
		}
	}
	request := map[string]any{"operation": "session", "profile": profile.Settings, "artifact_path": mapped, "sha256": artifact.SHA256, "script": script, "duration_ms": int(duration), "argv": a["argv"], "package_name": a["package_name"]}
	if err = s.write(request); err != nil {
		s.close()
		return nil, err
	}
	go func() {
		select {
		case <-m.ctx.Done():
			s.close()
		case <-time.After(time.Duration(duration)*time.Millisecond + 120*time.Second):
			s.close()
		case <-s.done:
		}
	}()
	select {
	case result := <-ready:
		if result["is_error"] == true {
			s.close()
		}
		return result, nil
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.last, nil
	case <-ctx.Done():
		s.close()
		return nil, ctx.Err()
	}
}

func (m *reverseSessionManager) tool() actool.CoreTool {
	properties := map[string]any{"action": map[string]any{"type": "string", "enum": []string{"start", "read", "stop", "wait", "android_snapshot", "android_tap", "android_input", "android_key", "android_swipe", "android_launch"}}, "session_id": reverseString(), "artifact_id": reverseInt(), "profile_id": reverseString(), "script": reverseString(), "package_name": reverseString(), "duration_ms": reverseInt(), "argv": map[string]any{"type": "array", "items": reverseString()}, "text": reverseString(), "key": reverseString()}
	for _, key := range []string{"x", "y", "x1", "y1", "x2", "y2", "ms"} {
		properties[key] = reverseInt()
	}
	return reverseTool("reverse_runtime_session", "持续观察同一材料：start 启动一次 Frida 会话（材料/环境/脚本/总时限），后续用 session_id 进行 Android 截图与 UI 树、点击、输入、按键、滑动或读取调用记录，stop 显式清理。退出工作单、取消或到期也会清理；每步保存完整证据。会话仅属于本工作单。", reverseObject(properties, "action"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var a map[string]any
		if err := json.Unmarshal(raw, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var result map[string]any
		var err error
		if a["action"] == "start" {
			result, err = m.start(ctx, a)
		} else {
			m.mu.Lock()
			s := m.sessions[reverseSessionString(a["session_id"])]
			m.mu.Unlock()
			if s == nil {
				return actool.Errorf("会话不属于当前工作单或不存在"), nil
			}
			delete(a, "session_id")
			result, err = s.request(ctx, a)
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		response := reverseJSON(result)
		response.IsError = result["is_error"] == true
		return response, nil
	})
}
