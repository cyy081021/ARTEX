package dossier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var repoURL = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?$`)
var gitHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ReadPublicRepository obtains inert archive bytes from fixed HTTPS providers.
// No checkout, hooks, submodules, build script or package manager runs.
func ReadPublicRepository(ctx context.Context, origin, ref string) (File, string, error) {
	m := repoURL.FindStringSubmatch(origin)
	if m == nil {
		return File{}, "", errors.New("公共仓库请填写 GitHub 仓库主页，其他仓库可上传源码快照")
	}
	owner, repo := m[1], strings.TrimSuffix(m[2], ".git")
	if owner == "." || owner == ".." || repo == "" || repo == "." || repo == ".." {
		return File{}, "", errors.New("仓库名称无效")
	}
	if ref == "" {
		ref = "HEAD"
	}
	if len(ref) > 256 || strings.Contains(ref, "..") {
		return File{}, "", errors.New("版本标识无效")
	}
	client := http.Client{Timeout: 35 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	read := func(address string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("公共仓库读取失败，可上传本地快照")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("仓库返回 HTTP %d，可上传本地快照", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if int64(len(data)) > limit {
			return nil, errors.New("仓库资料过大")
		}
		return data, err
	}
	meta, err := read("https://api.github.com/repos/"+owner+"/"+repo+"/commits/"+url.PathEscape(ref), 2<<20)
	if err != nil {
		return File{}, "", err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(meta, &commit) != nil || !gitHash.MatchString(commit.SHA) {
		return File{}, "", errors.New("无法确定仓库提交")
	}
	data, err := read("https://codeload.github.com/"+owner+"/"+repo+"/zip/"+commit.SHA, MaxBytes)
	return File{Name: repo + "-" + commit.SHA + ".zip", Kind: "source_archive", Prefix: repo + "-" + commit.SHA, Data: data}, commit.SHA, err
}
