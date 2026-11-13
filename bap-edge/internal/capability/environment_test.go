package capability

import (
 "strings"
 "testing"
)

func TestNativeChildEnvironmentIsExplicit(t *testing.T) {
 t.Setenv("BAP_SYNTHETIC_SECRET","fixture-secret")
 t.Setenv("BAP_SYNTHETIC_VISIBLE","fixture-value")
 p:=New(t.TempDir());p.EnvAllow=[]string{"BAP_SYNTHETIC_VISIBLE","BAP_SYNTHETIC_SECRET"}
 values:=EnvValues(p)
 if len(values)!=1||values[0]!="BAP_SYNTHETIC_VISIBLE=fixture-value"{t.Fatalf("environment inherited undeclared or credential-looking fields: %v",values)}
 p.EnvAllow=nil
 if len(EnvValues(p))!=0{t.Fatal("empty environment inherited host values")}
}

func TestSeatbeltDoesNotAllowArbitraryLoopbackDestinations(t *testing.T) {
 p:=New(t.TempDir());p.ProxyAddr="unix:/tmp/bap-proxy.sock"
 profile,err:=SeatbeltProfile(p);if err!=nil{t.Fatal(err)}
 if strings.Contains(profile,"localhost:*")||!strings.Contains(profile,"localhost:3128"){t.Fatalf("proxy spec permits arbitrary loopback destinations: %s",profile)}
}
