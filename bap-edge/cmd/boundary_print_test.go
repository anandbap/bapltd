package cmd

import "testing"

func TestAppContainerPrintNeverLaunchesTheCommand(t *testing.T) {
 t.Setenv("BAP_STATE_DIR",t.TempDir())
 // This executable cannot be launched successfully. Printing must work on all
 // hosts, without creating an AppContainer, changing ACLs or running a child.
 if err:=RunRun([]string{"--provider","appcontainer","--print","--","bap-print-must-not-execute-missing-binary"});err!=nil{t.Fatalf("print tried to launch a process: %v",err)}
}
