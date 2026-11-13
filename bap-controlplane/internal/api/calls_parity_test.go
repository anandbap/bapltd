package api

import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"

 "bap-controlplane/internal/audit"
)

func TestSharedCallsParityFixture(t *testing.T) {
 raw,err:=os.ReadFile(filepath.Join("..","..","..","tests","fixtures","calls_parity.json"));if err!=nil{t.Fatal(err)}
 var fixture struct { Events []audit.Event `json:"events"`; Expected map[string]int `json:"expected"` }
 if err:=json.Unmarshal(raw,&fixture);err!=nil{t.Fatal(err)}
 s:=summarizeSessionCalls(fixture.Events)
 actual:=map[string]int{"total_actions":s.TotalActions,"allowed":s.Allowed,"failed":s.Failed,"allowed_limited":s.AllowedLimited,"blocked":s.Blocked,"unclassified":s.Unclassified,"raw_events":s.RawEvents}
 for key,want:=range fixture.Expected {if actual[key]!=want{t.Errorf("%s = %d, want %d",key,actual[key],want)}}
}
