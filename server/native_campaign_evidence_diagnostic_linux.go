//go:build linux

package server

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "regexp"
 "strconv"
 "strings"
 "time"
 "github.com/Autumn-27/artex/db"
)

type evidenceDiagnosticItem struct { Key, Status string }
type evidenceDiagnosticReport struct {
 Status string
 ObservedAt time.Time
 Items []evidenceDiagnosticItem
}
var evidenceDiagnosticName = regexp.MustCompile(`^([1-9][0-9]*)-([0-9a-f]{64})\.json$`)

// diagnoseEvidenceFiles has no production callers. It only observes a supplied
// read snapshot and bounded files. Candidate NEVER means safe to delete.
// It does not lock publishers, mutate metadata/files, or invoke an executor.
func diagnoseEvidenceFiles(ctx context.Context, root string, s *db.EvidenceDiagnosticSnapshot) evidenceDiagnosticReport {
 r:=evidenceDiagnosticReport{Status:"unknown"}
 if s==nil || s.TaskID<=0 || s.CampaignID<=0 || s.ObservedAt.IsZero(){return r};r.ObservedAt=s.ObservedAt
 if !s.Eligible{r.Status="ineligible";return r}
 if s.Attempts==nil||s.Paths==nil||s.Hashes==nil||len(s.Attempts)>1024||len(s.Paths)>1024||len(s.Hashes)>1024{return r}
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 base,err:=nativeCampaignStorageRoot(root);if err!=nil{return r};defer base.Close()
 prefix:=fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence",s.TaskID,s.CampaignID)
 dir,err:=(nativeCampaignCAS{}).openDirs(int(base.Fd()),strings.Split(prefix,"/"),false,false,true)
 if err!=nil{return r};defer dir.Close()
 entries,err:=dir.ReadDir(257);if err!=nil&&err!=io.EOF{return r};if len(entries)>256{return r}
 items:=make([]evidenceDiagnosticItem,0,len(entries));total:=0
 for _,entry:=range entries{
  if ctx.Err()!=nil{return r}
  m:=evidenceDiagnosticName.FindStringSubmatch(entry.Name());if m==nil{return r}
  id,err:=strconv.ParseInt(m[1],10,64);if err!=nil||!s.Attempts[id]{return r}
  remaining:=(16<<20)-total;if remaining<=0{return r};limit:=512<<10;if remaining<limit{limit=remaining}
  raw,err:=nativeCampaignReadBoundedFile(ctx,dir,entry.Name(),int64(limit),false);if err!=nil{return r}
  total+=len(raw);if total>16<<20{return r}
  sum:=sha256.Sum256(raw);if hex.EncodeToString(sum[:])!=m[2]{return r}
  // Decode and canonical re-encode the exact writer envelope. This rejects
  // duplicate/unknown envelope fields and noncanonical scalar encodings without a
  // second general JSON parser. Observation stays opaque, never returned.
  var envelope struct{ Content struct{
   Operation string `json:"operation"`; Authority string `json:"authority"`
   Task int64 `json:"task_id"`; Campaign int64 `json:"campaign_id"`; Attempt int64 `json:"attempt_id"`
   Kind string `json:"kind"`; Observation json.RawMessage `json:"normalized_result"`
  } `json:"structuredContent"` }
  if json.Unmarshal(raw,&envelope)!=nil{return r};c:=envelope.Content
  if c.Operation!="native_campaign"||c.Authority!="candidate-only"||c.Kind!="attempt_final"||c.Task!=s.TaskID||c.Campaign!=s.CampaignID||c.Attempt!=id{return r}
  var obs map[string]json.RawMessage
  if json.Unmarshal(c.Observation,&obs)!=nil||obs==nil{return r}
  canonical,err:=json.Marshal(map[string]any{"structuredContent":map[string]any{"operation":c.Operation,"authority":c.Authority,"task_id":c.Task,"campaign_id":c.Campaign,"attempt_id":c.Attempt,"kind":c.Kind,"normalized_result":c.Observation}})
  if err!=nil||string(canonical)!=string(raw){return r}
  key:=prefix+"/"+entry.Name();status:="snapshot_unreferenced"
  if s.Paths[key]||s.Hashes[m[2]]{status="referenced"}
  items=append(items,evidenceDiagnosticItem{Key:key,Status:status})
 }
 if ctx.Err()!=nil{return r};r.Status="observed";r.Items=items;return r
}
