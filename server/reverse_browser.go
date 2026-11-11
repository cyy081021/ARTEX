package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const reverseBrowserToolName = "capture_browser_scenario"

// Optional private runtime libraries are configured by the operator, never
// supplied in an agent call. They affect only this owned browser/REA process.
func reverseBrowserEnvironment(p reverseRuntimeProfile) ([]string, error) {
	value, ok := p.Settings["library_path"]
	if !ok {
		return nil, nil
	}
	path, ok := value.(string)
	if !ok {
		return nil, errors.New("browser library_path must be a path list")
	}
	for _, part := range filepath.SplitList(path) {
		if !filepath.IsAbs(part) {
			return nil, errors.New("browser library paths must be absolute")
		}
	}
	if old := os.Getenv("LD_LIBRARY_PATH"); old != "" {
		path += string(os.PathListSeparator) + old
	}
	return []string{"LD_LIBRARY_PATH=" + path}, nil
}

type reverseBrowserScenarioInput struct {
	ArtifactID int64             `json:"artifact_id"`
	ProfileID  string            `json:"profile_id"`
	StartURL   string            `json:"start_url"`
	Actions    []json.RawMessage `json:"actions"`
	DurationMS int               `json:"duration_ms"`
	Capture    json.RawMessage   `json:"capture,omitempty"`
}

func decodeReverseBrowserInput(raw []byte) (reverseBrowserScenarioInput, error) {
	var input reverseBrowserScenarioInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return input, errors.New("multiple JSON values")
		}
		return input, err
	}
	return input, nil
}

func reverseBrowserOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return "", errors.New("start_url must be an absolute HTTP(S) URL without credentials or fragment")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

func reverseBrowserAllowedOrigins(profile reverseRuntimeProfile) (map[string]bool, error) {
	values, ok := profile.Settings["allowed_origins"].([]any)
	if !ok {
		if strings, typed := profile.Settings["allowed_origins"].([]string); typed {
			values = make([]any, len(strings))
			for i := range strings {
				values[i] = strings[i]
			}
			ok = true
		}
	}
	if !ok || len(values) == 0 || len(values) > 32 {
		return nil, errors.New("browser profile must declare allowed_origins")
	}
	allowed := make(map[string]bool, len(values))
	for _, value := range values {
		origin, ok := value.(string)
		if !ok {
			return nil, errors.New("browser profile allowed_origins contains an invalid value")
		}
		parsed, err := reverseBrowserOrigin(origin)
		if err != nil {
			return nil, errors.New("browser profile allowed_origins must contain HTTP(S) origins")
		}
		u, _ := url.Parse(origin)
		if parsed != origin || strings.Contains(u.Host, "*") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return nil, errors.New("browser profile allowed_origins entries must be origins, without paths or queries")
		}
		allowed[parsed] = true
	}
	return allowed, nil
}

func reverseBrowserCheckTarget(raw string, allowed map[string]bool) error {
	origin, err := reverseBrowserOrigin(raw)
	if err != nil {
		return err
	}
	if !allowed[origin] {
		return fmt.Errorf("browser URL origin %q is outside this profile's allowed_origins", origin)
	}
	return nil
}

var reverseBrowserActionKinds = map[string]bool{
	"click": true, "fill": true, "press": true, "select_option": true,
	"check": true, "uncheck": true, "wait_for": true, "request": true,
	"wait_for_timeout": true, "goto": true,
}

func reverseBrowserValidateActions(actions []json.RawMessage, startURL string, allowed map[string]bool) error {
	if len(actions) == 0 || len(actions) > 64 {
		return errors.New("actions must contain between 1 and 64 steps")
	}
	if err := reverseBrowserCheckTarget(startURL, allowed); err != nil {
		return err
	}
	startOrigin, _ := reverseBrowserOrigin(startURL)
	seen := map[string]bool{}
	for i, raw := range actions {
		var action struct {
			StepID      string          `json:"step_id"`
			Action      string          `json:"action"`
			Destination json.RawMessage `json:"destination"`
			Path        string          `json:"path"`
		}
		if err := json.Unmarshal(raw, &action); err != nil || len(raw) == 0 || strings.TrimSpace(string(raw))[0] != '{' {
			return fmt.Errorf("actions[%d] must be an action object", i)
		}
		if strings.TrimSpace(action.StepID) == "" || len(action.StepID) > 128 || seen[action.StepID] {
			return fmt.Errorf("actions[%d].step_id must be unique and non-empty", i)
		}
		seen[action.StepID] = true
		if !reverseBrowserActionKinds[action.Action] {
			return fmt.Errorf("actions[%d].action is not supported", i)
		}
		switch action.Action {
		case "goto":
			var destination struct {
				URL string `json:"url"`
			}
			if len(action.Destination) == 0 || json.Unmarshal(action.Destination, &destination) != nil || destination.URL == "" {
				return fmt.Errorf("actions[%d].destination.url is required", i)
			}
			if err := reverseBrowserCheckTarget(destination.URL, allowed); err != nil {
				return fmt.Errorf("actions[%d].destination: %w", i, err)
			}
		case "request":
			if action.Path == "" || strings.HasPrefix(action.Path, "//") || strings.Contains(action.Path, "\\") {
				return fmt.Errorf("actions[%d].path must be a path on the start origin", i)
			}
			base, _ := url.Parse(startURL)
			ref, err := url.Parse(action.Path)
			if err != nil || ref.IsAbs() || ref.Host != "" || !strings.HasPrefix(action.Path, "/") {
				return fmt.Errorf("actions[%d].path must be an absolute path on the start origin", i)
			}
			resolved := base.ResolveReference(ref)
			if strings.ToLower(resolved.Scheme)+"://"+strings.ToLower(resolved.Host) != startOrigin {
				return fmt.Errorf("actions[%d].path resolves outside the start origin", i)
			}
		}
	}
	return nil
}

func reverseBrowserDoctor(ctx context.Context, p reverseRuntimeProfile) (map[string]any, error) {
	if p.Platform != "browser" {
		return nil, errors.New("runtime profile is not a browser profile")
	}
	executable, ok := p.Settings["executable_path"].(string)
	if !ok || !filepath.IsAbs(executable) {
		return nil, errors.New("browser profile executable_path must be absolute")
	}
	info, err := os.Stat(executable)
	if err != nil || info.IsDir() {
		return nil, errors.New("browser executable is unavailable")
	}
	if _, err = reverseBrowserAllowedOrigins(p); err != nil {
		return nil, err
	}
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	env, err := reverseBrowserEnvironment(p)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(versionCtx, executable, "--version")
	command.Env = append(os.Environ(), env...)
	version, err := command.Output()
	if err != nil || len(strings.TrimSpace(string(version))) == 0 {
		return nil, errors.New("browser executable version check failed")
	}
	dir, err := os.MkdirTemp("", "artex-browser-doctor-")
	if err != nil {
		return nil, errors.New("cannot create isolated REA doctor directory")
	}
	defer os.RemoveAll(dir)
	client, err := newREASessionWithEnvironment(ctx, dir, nil, env)
	if err != nil {
		return nil, errors.New("cannot start REA browser doctor session")
	}
	defer client.Close()
	tools, err := client.Tools(ctx)
	if err != nil {
		return nil, errors.New("cannot read REA browser tool catalog")
	}
	for _, tool := range tools {
		if tool.Name == reverseBrowserToolName {
			return map[string]any{"id": p.ID, "name": p.Name, "platform": "browser", "available": true, "engine": "REA browser", "version": client.Version, "browser_version": strings.TrimSpace(string(version)), "limits": "Browser executable and REA tool catalog verified; no page was launched or accepted."}, nil
		}
	}
	return nil, errors.New("REA capture_browser_scenario is unavailable")
}

func reverseBrowserDecodeResult(raw json.RawMessage) (any, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return string(raw), errors.New("REA returned invalid JSON")
	}
	var isError bool
	_ = json.Unmarshal(envelope["isError"], &isError)
	if isError {
		return json.RawMessage(raw), errors.New("REA browser scenario failed")
	}
	if value, ok := envelope["structuredContent"]; ok {
		if string(value) == "null" {
			delete(envelope, "structuredContent")
		} else {
			return json.RawMessage(value), nil
		}
	}
	var content []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(envelope["content"], &content); err == nil {
		for _, item := range content {
			var nested any
			if json.Unmarshal([]byte(item.Text), &nested) == nil {
				return nested, nil
			}
			if strings.TrimSpace(item.Text) != "" {
				return nil, errors.New("REA returned a non-JSON browser result")
			}
		}
	}
	return nil, errors.New("REA returned no browser result")
}

func saveReverseBrowserEvidence(workDir, taskDir string, record any) (string, int, string, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", 0, "", err
	}
	resultDir := filepath.Join(taskDir, "results")
	if err = os.MkdirAll(resultDir, 0700); err != nil {
		return "", 0, "", err
	}
	file, err := os.CreateTemp(resultDir, "browser-*.json")
	if err != nil {
		return "", 0, "", err
	}
	_ = file.Chmod(0600)
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if writeErr != nil {
		return "", len(encoded), "", writeErr
	}
	if closeErr != nil {
		return "", len(encoded), "", closeErr
	}
	rel, err := filepath.Rel(workDir, file.Name())
	if err != nil {
		return "", len(encoded), "", err
	}
	digest := sha256.Sum256(encoded)
	return filepath.ToSlash(rel), len(encoded), fmt.Sprintf("%x", digest[:]), nil
}

func reverseBrowserTool(pg *db.DB, task *db.Task, info agent.RunInfo, workDir string) actool.CoreTool {
	return reverseTool("reverse_browser_scenario", "在当前逆向任务授权的浏览器环境中启动独立 Chromium 上下文，按有界动作观察已授权页面并保存完整网络、控制台和页面证据。仅 launch 模式；目标源必须属于 profile.allowed_origins。", reverseObject(map[string]any{
		"artifact_id": reverseInt(), "profile_id": reverseString(), "start_url": reverseString(),
		"actions":     map[string]any{"type": "array", "description": `REA动作序列，每步需唯一step_id和action。fill示例：{"step_id":"input","action":"fill","locator":{"kind":"css","selector":"#name"},"value":{"source":"literal","value":"sample"}}；click使用同样locator；wait_for需state visible/hidden；goto需destination:{url:"..."},wait_until:"domcontentloaded"；wait_for_timeout需duration_ms。locator还支持test_id/value与role/role/name。密码使用profile已配置的{source:"secret",secret_id:"..."}，不在提示词填密码。`, "items": map[string]any{"type": "object"}},
		"duration_ms": reverseInt(), "capture": map[string]any{"type": "object"},
	}, "artifact_id", "profile_id", "start_url", "actions", "duration_ms"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if len(in) > 128*1024 {
			return actool.Errorf("browser scenario input exceeds 128 KiB"), nil
		}
		a, err := decodeReverseBrowserInput(in)
		if err != nil {
			return actool.Errorf("invalid browser scenario input"), nil
		}
		if task == nil || task.Kind != "reverse" || a.ArtifactID <= 0 || a.ProfileID == "" || a.DurationMS < 100 || a.DurationMS > 900000 {
			return actool.Errorf("invalid browser scenario task, material, profile, or duration"), nil
		}
		var capture map[string]any
		if a.Capture != nil && len(a.Capture) > 0 && json.Unmarshal(a.Capture, &capture) != nil {
			return actool.Errorf("capture must be an object"), nil
		}
		if capture == nil {
			capture = map[string]any{"after_each_step": []string{"url"}, "at_end": []string{"dom", "screenshot"}, "events": []string{"network", "console", "page-errors"}, "network": map[string]any{"request_body": true, "response_body": true, "header_values": false}}
		}
		profiles, err := reverseRuntimeProfiles()
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var profile *reverseRuntimeProfile
		for i := range profiles {
			if profiles[i].ID == a.ProfileID {
				profile = &profiles[i]
				break
			}
		}
		if profile == nil || profile.Platform != "browser" {
			return actool.Errorf("browser runtime profile is not configured"), nil
		}
		executable, ok := profile.Settings["executable_path"].(string)
		if !ok || !filepath.IsAbs(executable) {
			return actool.Errorf("browser profile executable_path must be absolute"), nil
		}
		allowed, err := reverseBrowserAllowedOrigins(*profile)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err = reverseBrowserValidateActions(a.Actions, a.StartURL, allowed); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		inputBytes, _ := json.Marshal(a)
		if len(inputBytes) > 128*1024 {
			return actool.Errorf("browser scenario input exceeds 128 KiB"), nil
		}
		artifact, err := pg.GetReverseArtifact(task.ID, a.ArtifactID)
		if err != nil || artifact == nil {
			return actool.Errorf("material does not belong to this reverse task"), nil
		}
		prefix := filepath.Join("tasks", strconv.FormatInt(task.ID, 10), "reverse")
		artifact.Path, err = reverseLocalPath(workDir, artifact.Path, filepath.Join(prefix, "artifacts"))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err = verifyArtifact(artifact); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		runID, err := pg.BeginReverseRuntimeRun(ctx, task.ID, a.ArtifactID, info.IntentID, a.ProfileID, a.DurationMS)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		status, resultPath, message := "failed", "", "browser scenario did not complete"
		defer func() { _ = pg.FinishReverseRuntimeRun(runID, status, resultPath, message) }()

		taskDir := filepath.Join(workDir, prefix)
		sessionDir, err := os.MkdirTemp(taskDir, "browser-session-")
		if err != nil {
			message = "cannot create isolated REA session directory"
			return actool.Errorf(message), nil
		}
		defer os.RemoveAll(sessionDir)
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.DurationMS)*time.Millisecond+10*time.Second)
		defer cancel()
		env, err := reverseBrowserEnvironment(*profile)
		if err != nil {
			message = err.Error()
			return actool.Errorf(message), nil
		}
		client, err := newREASessionWithEnvironment(runCtx, sessionDir, nil, env)
		if err != nil {
			message = "cannot start isolated REA session"
			return actool.Errorf(message), nil
		}
		defer client.Close()
		catalog, err := client.Tools(runCtx)
		if err != nil {
			message = "cannot read REA browser tool catalog"
			return actool.Errorf(message), nil
		}
		found := false
		for _, tool := range catalog {
			if tool.Name == reverseBrowserToolName {
				found = true
				break
			}
		}
		if !found {
			message = "REA capture_browser_scenario is unavailable"
			return actool.Errorf(message), nil
		}
		browser := map[string]any{"mode": "launch", "executable_path": executable, "headless": true}
		startURL := map[string]any{"url": a.StartURL, "query": []any{}}
		reaInput := map[string]any{"browser": browser, "start_url": startURL, "actions": a.Actions, "command_timeout_ms": a.DurationMS}
		// Secret values come only from administrator-configured environment
		// references. REA validates references and redacts resolved values.
		if secrets := profile.Settings["secrets"]; secrets != nil {
			reaInput["secrets"] = secrets
		}
		if capture != nil {
			reaInput["capture"] = capture
		}
		callCtx, callCancel := context.WithTimeout(runCtx, time.Duration(a.DurationMS)*time.Millisecond)
		defer callCancel()
		raw, callErr := client.Call(callCtx, reverseBrowserToolName, reaInput)
		if callErr != nil {
			message = "REA browser scenario call failed"
			status = "failed"
			if callCtx.Err() != nil || ctx.Err() != nil {
				status = "cancelled"
			}
			if len(raw) > 0 && json.Valid(raw) {
				record := map[string]any{"isError": true, "structuredContent": map[string]any{"operation": "reverse_browser_scenario", "task_id": task.ID, "intent_id": info.IntentID, "run_id": runID, "profile_id": a.ProfileID, "subject": map[string]any{"digest": map[string]any{"sha256": artifact.SHA256}, "name": artifact.Name}, "error": message, "raw_result": json.RawMessage(raw)}}
				if path, _, _, saveErr := saveReverseBrowserEvidence(workDir, taskDir, record); saveErr == nil {
					resultPath = path
				}
			}
			response := reverseJSON(map[string]any{"run_id": runID, "status": status, "result_path": resultPath, "message": message})
			response.IsError = true
			return response, nil
		}
		normalized, decodeErr := reverseBrowserDecodeResult(json.RawMessage(raw))
		if decodeErr != nil {
			message = decodeErr.Error()
			record := map[string]any{"isError": true, "structuredContent": map[string]any{"operation": "reverse_browser_scenario", "provider": map[string]any{"name": "REA", "version": client.Version}, "task_id": task.ID, "intent_id": info.IntentID, "subject": map[string]any{"digest": map[string]any{"sha256": artifact.SHA256}, "name": artifact.Name}, "run_id": runID, "profile_id": a.ProfileID, "error": message, "raw_result": json.RawMessage(raw)}}
			if path, _, _, saveErr := saveReverseBrowserEvidence(workDir, taskDir, record); saveErr == nil {
				resultPath = path
			}
			response := reverseJSON(map[string]any{"run_id": runID, "status": "failed", "result_path": resultPath, "message": message})
			response.IsError = true
			return response, nil
		}
		artifactDigest := artifact.SHA256
		record := map[string]any{"isError": false, "structuredContent": map[string]any{
			"operation": "reverse_browser_scenario", "provider": map[string]any{"name": "REA", "version": client.Version},
			"subject": map[string]any{"digest": map[string]any{"sha256": artifactDigest}, "name": artifact.Name},
			"task_id": task.ID, "intent_id": info.IntentID, "run_id": runID, "profile_id": a.ProfileID, "allowed_origins": allowed, "normalized_result": normalized, "raw_result": json.RawMessage(raw),
			"confidence": "observed", "authority": "authorized-browser-profile",
			"limitations": []string{"材料 SHA256 关联研究对象，不代表页面与上传材料逐字节相同。", "网络正文是浏览器接口提供的内容，不能替代原始网络抓包。"},
		}}
		resultPath, evidenceBytes, evidenceDigest, err := saveReverseBrowserEvidence(workDir, taskDir, record)
		if err != nil {
			message = "cannot persist complete browser evidence"
			return actool.Errorf(message), nil
		}
		status, message = "completed", ""
		encoded, _ := json.Marshal(record)
		return reverseJSON(map[string]any{"run_id": runID, "status": status, "result_path": resultPath, "bytes": evidenceBytes, "sha256": evidenceDigest, "preview": reaPreview(json.RawMessage(encoded))}), nil
	})
}
