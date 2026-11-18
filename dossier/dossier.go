package dossier

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	Open     = "open_source_software"
	Closed   = "closed_source_software"
	MaxBytes = 32 << 20
	MaxFiles = 4096
)

type File struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Data    []byte `json:"data"`
	Hash    string `json:"sha256,omitempty"`
	Parent  string `json:"parent,omitempty"`
	Prefix  string `json:"zip_prefix,omitempty"` // optional wrapper directory of a provider-created source archive
	Subject string `json:"subject,omitempty"`    // snapshot or release digest declared by a supplied evidence file
	Format  string `json:"format,omitempty"`
}
type Note struct {
	State   string `json:"state"`
	Text    string `json:"text"`
	File    string `json:"file,omitempty"`
	Hash    string `json:"sha256,omitempty"`
	Line    int    `json:"line,omitempty"`
	Subject string `json:"subject,omitempty"`
}
type Bundle struct {
	Scenario string `json:"scenario"`
	Name     string `json:"name"`
	Goal     string `json:"goal"`
	Origin   string `json:"origin,omitempty"`
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Platform string `json:"platform,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	Files    []File `json:"files"`
	Notes    []Note `json:"notes"`
}

func Digest(p []byte) string { h := sha256.Sum256(p); return hex.EncodeToString(h[:]) }
func validName(s string) bool {
	return s != "." && len(s) <= 1024 && fs.ValidPath(s) && !strings.ContainsAny(s, "\\:\x00\r\n")
}
func format(data []byte) string {
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		if f, e := elf.NewFile(bytes.NewReader(data)); e == nil {
			return "ELF / " + f.Machine.String()
		}
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		if f, e := pe.NewFile(bytes.NewReader(data)); e == nil {
			return fmt.Sprintf("PE / 0x%04x", f.Machine)
		}
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return "ZIP"
	}
	if utf8.Valid(data) && !bytes.ContainsRune(data, 0) {
		return "文本"
	}
	return "二进制"
}

// Expand reads regular ZIP members in memory at intake and when verifying an archive.
func Expand(f File, remaining int) ([]File, error) {
	if !validName(f.Name) || len(f.Data) > remaining {
		return nil, errors.New("材料路径或大小无效")
	}
	out := []File{f}
	if f.Kind != "source_archive" && !(f.Kind == "package" && bytes.HasPrefix(f.Data, []byte("PK\x03\x04"))) {
		return out, nil
	}
	z, err := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
	if err != nil {
		return nil, errors.New("无法读取 ZIP")
	}
	if len(z.File) > MaxFiles {
		return nil, errors.New("ZIP 条目过多")
	}
	parent := Digest(f.Data)
	seen := map[string]bool{}
	remaining -= len(f.Data)
	for _, entry := range z.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if !entry.Mode().IsRegular() || !validName(entry.Name) || seen[entry.Name] {
			return nil, errors.New("ZIP 中存在不支持或重复的路径")
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > uint64(remaining) {
			return nil, errors.New("解包后大小超过上限")
		}
		r, e := entry.Open()
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(r, int64(remaining)+1))
		r.Close()
		if e != nil || len(data) > remaining {
			return nil, errors.New("ZIP 条目校验失败或超过上限")
		}
		remaining -= len(data)
		k := "component"
		if f.Kind == "source_archive" {
			k = "source"
		}
		name := entry.Name
		if f.Prefix != "" {
			top, relative, ok := strings.Cut(name, "/")
			if f.Kind != "source_archive" || !ok || !strings.EqualFold(top, f.Prefix) {
				return nil, errors.New("源码包顶层目录不一致")
			}
			name = relative
		}
		out = append(out, File{Name: name, Kind: k, Data: data, Parent: parent})
	}
	return out, nil
}
func (b *Bundle) Normalize() error {
	if b.Scenario != Open && b.Scenario != Closed {
		return errors.New("软件场景无效")
	}
	b.Name = strings.TrimSpace(b.Name)
	b.Goal = strings.TrimSpace(b.Goal)
	if b.Name == "" || b.Goal == "" || len(b.Name) > 512 || len(b.Goal) > 16000 || len(b.Origin) > 2048 || len(b.Version) > 256 || len(b.Commit) > 128 || len(b.Platform) > 256 {
		return errors.New("请填写有效的对象与目的")
	}
	if len(b.Files) > MaxFiles || len(b.Notes) > 2000 {
		return errors.New("档案条目过多")
	}
	total := 0
	subjects := map[string]bool{}
	parents := map[[2]string]bool{}
	paths := map[string]bool{}
	sources := []string{}
	unique := map[[4]string]string{}
	clean := make([]File, 0, len(b.Files))
	refs := map[[2]string][]File{}
	for i := range b.Files {
		f := b.Files[i]
		if !validName(f.Name) || f.Name != path.Clean(f.Name) {
			return errors.New("无效材料路径")
		}
		switch f.Kind {
		case "source", "source_archive", "package", "component", "evidence":
		default:
			return errors.New("材料类型无效")
		}
		if f.Prefix != "" && (f.Kind != "source_archive" || !validName(f.Prefix) || strings.Contains(f.Prefix, "/")) {
			return errors.New("源码包的顶层目录无效")
		}
		if b.Scenario == Closed && (f.Kind == "source" || f.Kind == "source_archive") {
			return errors.New("闭源档案不接受源码快照")
		}
		h := Digest(f.Data)
		if f.Hash != "" && f.Hash != h {
			return errors.New("材料 SHA-256 不匹配")
		}
		f.Hash = h
		id := [4]string{f.Kind, f.Name, f.Hash, f.Parent}
		if prev, found := unique[id]; found {
			if prev != f.Subject {
				return errors.New("同一份材料的版本声明冲突")
			}
			continue
		}
		total += len(f.Data)
		if total > MaxBytes {
			return errors.New("档案材料总量超过 32 MiB")
		}
		if f.Subject != "" {
			raw, err := hex.DecodeString(f.Subject)
			if f.Kind != "evidence" || err != nil || len(raw) != sha256.Size {
				return errors.New("证据所声明的对象必须为 SHA-256")
			}
		}
		unique[id] = f.Subject
		if f.Kind == "source" {
			if paths[f.Name] {
				return errors.New("同一快照包含同路径不同内容")
			}
			paths[f.Name] = true
			sources = append(sources, f.Name+"\x00"+h+"\n")
		}
		if f.Kind == "package" || f.Kind == "source_archive" {
			parents[[2]string{h, f.Kind}] = true
			subjects[h] = true
		}
		f.Format = format(f.Data)
		key := [2]string{f.Name, h}
		refs[key] = append(refs[key], f)
		clean = append(clean, f)
	}
	for _, f := range clean {
		if f.Kind == "component" && !parents[[2]string{f.Parent, "package"}] {
			return errors.New("组件缺少父发行包")
		}
		if f.Parent != "" && !(f.Kind == "component" || (f.Kind == "source" && parents[[2]string{f.Parent, "source_archive"}])) {
			return errors.New("材料父子关系无效")
		}
	}
	b.Files = clean
	sort.Strings(sources)
	snapshot := ""
	if len(sources) > 0 {
		snapshot = Digest([]byte(strings.Join(sources, "")))
		subjects[snapshot] = true
	}
	if b.Snapshot != "" && b.Snapshot != snapshot {
		return errors.New("快照摘要不匹配")
	}
	b.Snapshot = snapshot
	if b.Notes == nil {
		b.Notes = []Note{}
	}
	for _, n := range b.Notes {
		switch n.State {
		case "source", "observed", "contradiction", "unresolved":
		default:
			return errors.New("观察类型无效")
		}
		if strings.TrimSpace(n.Text) == "" || len(n.Text) > 16000 || n.Line < 0 {
			return errors.New("观察内容或位置无效")
		}
		if n.Subject != "" && !subjects[n.Subject] {
			return errors.New("观察指向未知快照或包")
		}
		matches, ok := refs[[2]string{n.File, n.Hash}]
		if !ok && (n.State != "unresolved" || n.File != "" || n.Hash != "" || n.Line != 0) {
			return errors.New("观察缺少本档案的有效材料引用")
		}
		if n.Subject != "" && ok {
			match := false
			for _, m := range matches {
				required := m.Subject
				switch m.Kind {
				case "source":
					required = b.Snapshot
				case "package", "source_archive":
					required = m.Hash
				case "component":
					required = m.Parent
				}
				if required == n.Subject {
					match = true
					break
				}
			}
			if !match {
				return errors.New("材料与所选版本不匹配或尚未绑定")
			}
		}
		if n.Line > 0 {
			data := matches[0].Data
			if !utf8.Valid(data) || bytes.ContainsRune(data, 0) || n.Line > bytes.Count(data, []byte("\n"))+1 {
				return errors.New("行号超出文本材料范围")
			}
		}
	}
	return nil
}
