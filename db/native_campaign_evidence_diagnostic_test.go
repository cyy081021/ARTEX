package db
import("context";"encoding/json";"fmt";"testing")
func TestEvidenceDiagnosticSnapshot(t *testing.T){
 d,err:=Open(fuzzTestDSN(t));if err!=nil{t.Fatal(err)};defer d.Close()
 for _,mode:=range []string{"prepared","active","hold","restored","archived","deleted","archive_failed","wrong_scope"}{t.Run(mode,func(t *testing.T){
 task,artifact:=newNativeCampaignTask(t,d,"diagnostic-"+mode)
 c:=newNativeCampaign(t,d,task,artifact,"diagnostic-"+mode)
 _,run:=newNativeCampaignRun(t,d,task,artifact,"running")
 a:=newNativeCampaignAttempt(t,d,task,c,run,1)
 if mode!="active" {if _,err=d.Exec(`UPDATE native_campaign_attempts SET state='failed',ended_at=clock_timestamp(),cleanup_status='verified',resource_hold=false,hold_reason=NULL WHERE id=$1`,a.ID);err!=nil{t.Fatal(err)}}
 if mode=="hold"{if _,err=d.Exec(`UPDATE native_campaign_attempts SET cleanup_status='unknown',resource_hold=true,hold_reason='cleanup_unknown' WHERE id=$1`,a.ID);err!=nil{t.Fatal(err)}}
 if mode=="restored"{if _,err=d.Exec(`INSERT INTO native_campaign_events(task_id,campaign_id,kind,payload) VALUES($1,$2,'campaign.archive_restored','{}')`,task.ID,c.ID);err!=nil{t.Fatal(err)}}
 if mode=="archived"{if _,err=d.Exec(`UPDATE tasks SET archived_at=clock_timestamp() WHERE id=$1`,task.ID);err!=nil{t.Fatal(err)}}
 if mode=="deleted"{if _,err=d.Exec(`UPDATE tasks SET deleted_at=clock_timestamp() WHERE id=$1`,task.ID);err!=nil{t.Fatal(err)}}
 if mode=="archive_failed"{if _,err=d.Exec(`INSERT INTO task_archives(task_id,state) VALUES($1,'archive_failed')`,task.ID);err!=nil{t.Fatal(err)}}
 key:=fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/prepared.json",task.ID,c.ID);hash:=nativeCampaignHash("diagnostic")
 if mode=="prepared"{if _,err=d.CreateNativeCampaignEvidence(context.Background(),NativeCampaignEvidenceInput{TaskID:task.ID,CampaignID:c.ID,AttemptID:a.ID,Kind:"attempt_final",ResultPath:key,SHA256:hash,Observation:json.RawMessage(`{}`)});err!=nil{t.Fatal(err)}}
 id:=c.ID;if mode=="wrong_scope"{id+=1000000}
 s,err:=d.ReadEvidenceDiagnosticSnapshot(context.Background(),task.ID,id)
 if mode=="wrong_scope"{if err==nil{t.Fatal("wrong scope accepted")};return};if err!=nil{t.Fatal(err)}
 if s.Eligible!=(mode=="prepared"){t.Fatalf("eligibility %+v",s)}
 if mode=="prepared"&&(!s.Paths[key]||!s.Hashes[hash]||!s.Attempts[a.ID]){t.Fatal("unpublished reference lost")}
 })}
}
