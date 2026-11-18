package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"regexp"

	"github.com/Autumn-27/artex/dossier"
	"github.com/google/uuid"
)

const maxDossierRequest = 56 << 20
const dossierArchiveFormat = "artex-software-dossier/v1"

var dossierID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type softwareCreate struct {
	dossier.Bundle
	ID              string `json:"id"`
	FetchRepository bool   `json:"fetch_repository"`
}
type softwareRecord struct {
	ID       string         `json:"id"`
	Revision int64          `json:"revision"`
	Dossier  dossier.Bundle `json:"dossier"`
}
type softwareArchive struct {
	Format string         `json:"format"`
	Record softwareRecord `json:"record"`
	SHA256 string         `json:"sha256"`
}

func (s *Server) softwareDossierRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/software-dossiers/environment", func(w http.ResponseWriter, _ *http.Request) {
		visible := map[string]bool{}
		for _, name := range []string{"rea", "docker", "gdb", "afl-fuzz"} {
			_, err := exec.LookPath(name)
			visible[name] = err == nil
		}
		writeJSON(w, 200, visible)
	})
	mux.HandleFunc("GET /api/software-dossiers", s.listSoftwareDossiers)
	mux.HandleFunc("GET /api/software-dossiers/{id}", s.getSoftwareDossier)
	mux.HandleFunc("PATCH /api/software-dossiers/{id}", s.appendSoftwareEvidence)
	mux.HandleFunc("GET /api/software-dossiers/{id}/archive", s.getSoftwareArchive)
	mux.HandleFunc("POST /api/software-dossiers/restore", s.restoreSoftwareArchive)
}
func decodeDossier(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxDossierRequest)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "档案数据格式或大小无效")
		return false
	}
	return true
}
func (s *Server) createSoftwareDossier(w http.ResponseWriter, r *http.Request, scenario string, in *softwareCreate) {
	if in == nil || (scenario != dossier.Open && scenario != dossier.Closed) {
		writeErr(w, 400, "软件档案场景或材料无效")
		return
	}
	b := in.Bundle
	b.Scenario = scenario
	files := b.Files
	if in.FetchRepository {
		if scenario != dossier.Open {
			writeErr(w, 400, "仅开源软件场景支持公共仓库")
			return
		}
		for _, extra := range files {
			if extra.Kind != "package" && extra.Kind != "evidence" {
				writeErr(w, 400, "仓库快照可附带发行包或审阅证据")
				return
			}
		}
		f, sha, err := dossier.ReadPublicRepository(r.Context(), b.Origin, b.Version)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		files = append([]dossier.File{f}, files...)
		b.Commit = sha
	}
	b.Files = nil
	remaining := dossier.MaxBytes
	for _, f := range files {
		if f.Parent != "" || f.Kind == "component" {
			writeErr(w, 400, "派生材料须由归档生成")
			return
		}
		expanded, err := dossier.Expand(f, remaining)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		for _, e := range expanded {
			remaining -= len(e.Data)
		}
		b.Files = append(b.Files, expanded...)
		if len(b.Files) > dossier.MaxFiles {
			writeErr(w, 400, "材料数过多")
			return
		}
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	s.insertSoftwareRecord(w, r, softwareRecord{ID: id, Revision: 1, Dossier: b})
}
func (s *Server) insertSoftwareRecord(w http.ResponseWriter, r *http.Request, rec softwareRecord) {
	if !dossierID.MatchString(rec.ID) || rec.Revision < 1 {
		writeErr(w, 400, "无效档案标识或修订号")
		return
	}
	if err := rec.Dossier.Normalize(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	hasPrimary := false
	for _, f := range rec.Dossier.Files {
		if (rec.Dossier.Scenario == dossier.Open && f.Kind == "source") || (rec.Dossier.Scenario == dossier.Closed && f.Kind == "package") {
			hasPrimary = true
			break
		}
	}
	if !hasPrimary {
		writeErr(w, 400, "缺少源码文件或发行包")
		return
	}
	raw, err := json.Marshal(rec.Dossier)
	if err != nil {
		writeErr(w, 400, "档案编码失败")
		return
	}
	if len(raw) > maxDossierRequest-4096 {
		writeErr(w, 413, "档案超过可恢复的归档上限")
		return
	}
	res, err := s.m.pg.ExecContext(r.Context(), "INSERT INTO software_dossiers(id,revision,body) VALUES($1,$2,$3::jsonb) ON CONFLICT(id) DO NOTHING", rec.ID, rec.Revision, string(raw))
	if err != nil {
		writeErr(w, 500, "档案保存失败")
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		writeErr(w, 500, "档案保存结果未知")
		return
	}
	if n == 0 {
		var same bool
		err = s.m.pg.QueryRowContext(r.Context(), "SELECT revision=$2 AND body=$3::jsonb FROM software_dossiers WHERE id=$1", rec.ID, rec.Revision, string(raw)).Scan(&same)
		if err != nil || !same {
			writeErr(w, 409, "标识已有不同版本，请重新打开档案")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"id": rec.ID, "revision": rec.Revision, "scenario": rec.Dossier.Scenario})
}
func (s *Server) listSoftwareDossiers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.QueryContext(r.Context(), "SELECT id,body->>'name',body->>'scenario',revision FROM software_dossiers ORDER BY created_at DESC,id")
	if err != nil {
		writeErr(w, 500, "无法读取软件档案")
		return
	}
	defer rows.Close()
	type entry struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Scenario string `json:"scenario"`
		Revision int64  `json:"revision"`
	}
	items := []entry{}
	for rows.Next() {
		var e entry
		if err = rows.Scan(&e.ID, &e.Name, &e.Scenario, &e.Revision); err != nil {
			writeErr(w, 500, "无法读取档案信息")
			return
		}
		items = append(items, e)
	}
	if rows.Err() != nil {
		writeErr(w, 500, "档案列表未读完")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) readSoftwareRecord(w http.ResponseWriter, r *http.Request) (softwareRecord, bool) {
	rec := softwareRecord{ID: r.PathValue("id")}
	if !dossierID.MatchString(rec.ID) {
		writeErr(w, 400, "档案标识无效")
		return rec, false
	}
	var data []byte
	err := s.m.pg.QueryRowContext(r.Context(), "SELECT revision,body FROM software_dossiers WHERE id=$1", rec.ID).Scan(&rec.Revision, &data)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "未找到软件档案")
		return rec, false
	}
	if err != nil || json.Unmarshal(data, &rec.Dossier) != nil {
		writeErr(w, 500, "档案读取失败")
		return rec, false
	}
	return rec, true
}
func (s *Server) getSoftwareDossier(w http.ResponseWriter, r *http.Request) {
	if rec, ok := s.readSoftwareRecord(w, r); ok {
		writeJSON(w, 200, rec)
	}
}
func (s *Server) appendSoftwareEvidence(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Revision int64          `json:"revision"`
		Files    []dossier.File `json:"files"`
		Notes    []dossier.Note `json:"notes"`
	}
	if !decodeDossier(w, r, &p) {
		return
	}
	rec, ok := s.readSoftwareRecord(w, r)
	if !ok {
		return
	}
	if p.Revision != rec.Revision {
		writeErr(w, 409, "档案已更新，请刷新")
		return
	}
	if len(p.Files)+len(p.Notes) == 0 {
		writeErr(w, 400, "没有新材料或观察")
		return
	}
	for _, f := range p.Files {
		if f.Kind != "evidence" || f.Parent != "" {
			writeErr(w, 400, "此入口只接受补充证据")
			return
		}
	}
	rec.Dossier.Files = append(rec.Dossier.Files, p.Files...)
	rec.Dossier.Notes = append(rec.Dossier.Notes, p.Notes...)
	if err := rec.Dossier.Normalize(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, err := json.Marshal(rec.Dossier)
	if err != nil {
		writeErr(w, 500, "记录编码失败")
		return
	}
	if len(raw) > maxDossierRequest-4096 {
		writeErr(w, 413, "档案超过可恢复的归档上限")
		return
	}
	res, err := s.m.pg.ExecContext(r.Context(), "UPDATE software_dossiers SET body=$1::jsonb,revision=revision+1 WHERE id=$2 AND revision=$3", string(raw), rec.ID, rec.Revision)
	if err != nil {
		writeErr(w, 500, "补充材料保存失败")
		return
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		writeErr(w, 409, "并发更新，请刷新后再保存")
		return
	}
	rec.Revision++
	writeJSON(w, 200, rec)
}
func (s *Server) getSoftwareArchive(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.readSoftwareRecord(w, r)
	if !ok {
		return
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		writeErr(w, 500, "档案编码失败")
		return
	}
	writeJSON(w, 200, softwareArchive{Format: dossierArchiveFormat, Record: rec, SHA256: dossier.Digest(raw)})
}
func (s *Server) restoreSoftwareArchive(w http.ResponseWriter, r *http.Request) {
	var archive softwareArchive
	if !decodeDossier(w, r, &archive) {
		return
	}
	raw, err := json.Marshal(archive.Record)
	if err != nil || archive.Format != dossierArchiveFormat || dossier.Digest(raw) != archive.SHA256 {
		writeErr(w, 400, "归档格式或校验和不匹配")
		return
	}
	if err := archive.Record.Dossier.Normalize(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := archive.Record.Dossier.VerifyChildren(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.insertSoftwareRecord(w, r, archive.Record)
}
