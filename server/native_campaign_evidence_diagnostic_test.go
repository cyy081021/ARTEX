//go:build linux

package server
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "github.com/Autumn-27/artex/db"
)
func TestEvidenceDiagnosticReadOnly(t *testing.T){
 for _,mode:=range []string{"candidate","prepared_path","prepared_hash","ineligible","unknown_name","wrong_hash","symlink","parent_symlink","wrong_identity","duplicate_envelope","entry_limit","file_limit","total_limit","cancelled"}{t.Run(mode,func(t *testing.T){
  root:=t.TempDir();prefix:="tasks/1/reverse/campaigns/2/evidence";dir:=filepath.Join(root,prefix)
  if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
  raw,err:=json.Marshal(map[string]any{"structuredContent":map[string]any{"operation":"native_campaign","authority":"candidate-only","task_id":1,"campaign_id":2,"attempt_id":3,"kind":"attempt_final","normalized_result":map[string]any{"note":"inert fixture"}}});if err!=nil{t.Fatal(err)}
  if mode=="wrong_identity"{raw=[]byte(strings.Replace(string(raw),`"task_id":1`,`"task_id":9`,1))}
  if mode=="duplicate_envelope"{raw=[]byte(strings.Replace(string(raw),`"task_id":1`,`"task_id":1,"task_id":1`,1))}
  sum:=sha256.Sum256(raw);hash:=hex.EncodeToString(sum[:]);key:=prefix+"/3-"+hash+".json";path:=filepath.Join(root,key)
  if err=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
  snap:=&db.EvidenceDiagnosticSnapshot{TaskID:1,CampaignID:2,ObservedAt:time.Now(),Eligible:true,Attempts:map[int64]bool{3:true},Paths:map[string]bool{},Hashes:map[string]bool{}}
  want:="unknown"
  switch mode{
  case "candidate":want="observed"
  case "prepared_path":snap.Paths[key]=true;want="observed"
  case "prepared_hash":snap.Hashes[hash]=true;want="observed"
  case "ineligible":snap.Eligible=false;want="ineligible"
  case "unknown_name":if err=os.WriteFile(filepath.Join(dir,"unknown"),[]byte("x"),0600);err!=nil{t.Fatal(err)}
  case "wrong_hash":if err=os.WriteFile(path,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
  case "symlink":outside:=filepath.Join(root,"referent.json");if err=os.Rename(path,outside);err!=nil{t.Fatal(err)};if err=os.Symlink(outside,path);err!=nil{t.Fatal(err)}
  case "parent_symlink":if err=os.Rename(dir,dir+".saved");err!=nil{t.Fatal(err)};if err=os.Symlink(dir+".saved",dir);err!=nil{t.Fatal(err)}
  case "entry_limit","file_limit","total_limit":
   count,size:=256,1
   if mode=="file_limit"{count,size=1,513<<10}
   if mode=="total_limit"{count,size=66,255<<10}
   for i:=0;i<count;i++{
    extra,e:=json.Marshal(map[string]any{"structuredContent":map[string]any{"operation":"native_campaign","authority":"candidate-only","task_id":1,"campaign_id":2,"attempt_id":3,"kind":"attempt_final","normalized_result":map[string]any{"note":fmt.Sprintf("%d-%s",i,strings.Repeat("x",size))}}});if e!=nil{t.Fatal(e)}
    digest:=sha256.Sum256(extra);name:=fmt.Sprintf("3-%x.json",digest)
    if err=os.WriteFile(filepath.Join(dir,name),extra,0600);err!=nil{t.Fatal(err)}
   }
  }
  ctx,cancel:=context.WithCancel(context.Background());defer cancel();if mode=="cancelled"{cancel()}
  before,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
  got:=diagnoseEvidenceFiles(ctx,root,snap)
  if got.Status!=want{t.Fatalf("status %s want %s",got.Status,want)}
  if want!="observed"&&len(got.Items)!=0{t.Fatal("partial candidate leak")}
  if want=="observed"{status:="snapshot_unreferenced";if mode!="candidate"{status="referenced"};if len(got.Items)!=1||got.Items[0].Key!=key||got.Items[0].Status!=status{t.Fatalf("unexpected report %+v",got)}}
  after,err:=os.ReadFile(path);if err!=nil||string(before)!=string(after){t.Fatal("diagnostic changed file")}
 })}
}
