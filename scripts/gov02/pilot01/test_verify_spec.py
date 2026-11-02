"""Negative tests for the exact expected Linux scanner container mount set."""
import json
import pathlib
import tempfile
import unittest
from verify_spec import verify

class ScanSpecTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=pathlib.Path(self.temp.name)
        self.i=root/"in";self.o=root/"out";self.c=root/"config"
        for p in (self.i,self.o,self.c):p.mkdir()
        def mount(path,target,ro):
            v={"Type":"bind","Source":str(path.resolve()),"Target":target}
            if ro:v["ReadOnly"]=True
            return v
        self.spec={"Config":{"User":"65532:65532","Entrypoint":["/gitleaks"],"Cmd":["dir","/input"],"Env":["PATH=/usr/local/bin"]},
                   "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":True,"Privileged":False,
                                 "PidsLimit":32,"Memory":134217728,"MemorySwap":134217728,
                                 "NanoCpus":500000000,"CapDrop":["ALL"],
                                 "SecurityOpt":["no-new-privileges:true"],"Binds":None,
                                 "Mounts":[mount(self.i,"/input",True),mount(self.o,"/output",False),
                                           mount(self.c,"/config",True)]}}
        self.path=root/"inspect.json"
    def check(self):
        self.path.write_text(json.dumps([self.spec]),encoding="utf-8")
        verify(str(self.path),str(self.i),str(self.o),"none",str(self.c),"/gitleaks","dir","/input")
    def test_exact_three_mounts_pass(self):
        self.check()
    def test_missing_config_mount_fails(self):
        self.spec["HostConfig"]["Mounts"].pop()
        with self.assertRaisesRegex(ValueError,"MOUNT_COUNT"):self.check()
    def test_writable_input_refused(self):
        self.spec["HostConfig"]["Mounts"][0].pop("ReadOnly")
        with self.assertRaisesRegex(ValueError,"MOUNT_READONLY_MISMATCH"):self.check()
    def test_writable_config_refused(self):
        self.spec["HostConfig"]["Mounts"][2].pop("ReadOnly")
        with self.assertRaisesRegex(ValueError,"MOUNT_READONLY_MISMATCH"):self.check()
    def test_unapproved_bind_refused(self):
        self.spec["HostConfig"]["Binds"]=["/var/run/docker.sock:/var/run/docker.sock"]
        with self.assertRaisesRegex(ValueError,"UNEXPECTED_BINDS"):self.check()
    def test_network_bridge_refused(self):
        self.spec["HostConfig"]["NetworkMode"]="bridge"
        with self.assertRaisesRegex(ValueError,"NETWORK"):self.check()
    def test_mutated_argv_refused(self):
        self.spec["Config"]["Cmd"]=["git","."]
        with self.assertRaisesRegex(ValueError,"CMD"):self.check()
if __name__=="__main__":unittest.main()
