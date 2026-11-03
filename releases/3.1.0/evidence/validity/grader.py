#!/usr/bin/env python3
"""Frozen independent CLI evidence. Stdlib, credential-free Git fixtures, no network.
Exit 0 all invariants pass; 1 named invariant false; 99 fixture setup unavailable.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shlex, shutil, subprocess, sys, tempfile, time, tomllib, traceback
from pathlib import Path
sys.dont_write_bytecode = True
class Unavailable(RuntimeError): pass

def need(condition, message):
    if not condition: raise AssertionError(message)

def digest(data): return hashlib.sha256(data).hexdigest()

CHECK = '''import json, os, sys, time, subprocess
from pathlib import Path
mode = sys.argv[1]
phase = os.environ["VERIFY_TREE"]
value = Path("app.txt").read_text().strip()
if mode == "import" and phase == "base": import nonexistent_validity_dependency
if mode == "setup" and phase == "base": raise RuntimeError("fixture setup exception")
if mode == "timeout" and phase == "candidate": time.sleep(2)
if mode == "missing" and phase == "candidate": sys.exit(0)
if mode == "ordinary1" and phase == "base": sys.exit(1)
rows = [{"id":"NEW_BEHAVIOR", "status":"pass" if value == "new" else "fail", "detail":"observed="+value}, {"id":"COMPLETE_OBSERVATION", "status":"pass", "detail":json.dumps({"cwd":os.getcwd(),"root":os.environ["VERIFY_ROOT"]})}]
if mode == "unexpected_base" and phase == "base": rows[1]["status"]="fail"
if mode == "wrong" and phase == "candidate": rows[0]["id"]="UNDECLARED"
if mode == "duplicate" and phase == "candidate": rows.append(dict(rows[0]))
if mode == "incomplete" and phase == "candidate": rows=rows[:1]
if mode == "skip" and phase == "candidate": rows=[]
if mode == "mutate" and phase == "candidate": Path("app.txt").write_text("tampered")
if mode == "mutate_base" and phase == "base": Path("app.txt").write_text("tampered")
if mode == "commit_during" and phase == "candidate":
    Path("app.txt").write_text("tampered")
    subprocess.run(["git","add","app.txt"],check=True)
    subprocess.run(["git","commit","-m","during-check"],check=True)
if mode == "untracked_during" and phase == "candidate": Path("surprise.txt").write_text("generated")
result={"protocol":1,"check":"desired observable","phase":phase,"run_id":os.environ["VERIFY_RUN_ID"],"assertions":rows}
if mode == "wrong_phase" and phase == "candidate": result["phase"]="base"
if mode == "wrong_check" and phase == "candidate": result["check"]="another check"
if mode == "wrong_token" and phase == "candidate": result["run_id"]="stale-token"
if mode == "extra_key" and phase == "candidate": result["forged"]=True
if mode == "unknown_status" and phase == "candidate": rows[0]["status"]="skipped"
if mode == "invalid_detail" and phase == "candidate": rows[0]["detail"]=42
if mode == "malformed" and phase == "candidate": Path(os.environ["VERIFY_RESULT_JSON"]).write_text("{broken")
else: Path(os.environ["VERIFY_RESULT_JSON"]).write_text(json.dumps(result))
if mode == "99" and phase == "candidate": sys.exit(99)
if mode == "exit_mismatch" and phase == "candidate": sys.exit(1)
sys.exit(1 if any(r["status"]=="fail" for r in rows) else 0)
'''

class Suite:
    def __init__(self, verifier, root):
        self.verifier=verifier.resolve(); self.root=root; self.rows=[]; self.details=None
        git=shutil.which("git")
        if not git: raise Unavailable("Git unavailable")
        home=root/"home"; home.mkdir()
        self.env={"PATH":os.pathsep.join([str(Path(git).parent),str(Path(sys.executable).parent),"/usr/bin","/bin"]),"HOME":str(home),"TMPDIR":str(root),"LANG":"C","PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_SYSTEM":os.devnull,"GIT_TERMINAL_PROMPT":"0","GIT_ALLOW_PROTOCOL":"","GIT_ASKPASS":"/usr/bin/false","GIT_AUTHOR_NAME":"Frozen Evidence","GIT_AUTHOR_EMAIL":"evidence@example.test","GIT_COMMITTER_NAME":"Frozen Evidence","GIT_COMMITTER_EMAIL":"evidence@example.test"}
    def proc(self, argv, cwd, setup=False, timeout=20):
        start=time.monotonic()
        try: p=subprocess.run([str(a) for a in argv],cwd=cwd,env=self.env,text=True,capture_output=True,timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e: raise Unavailable("fixture subprocess: "+str(e)) from e
        d={"argv":[str(a) for a in argv],"exit":p.returncode,"stdout":p.stdout,"stderr":p.stderr,"seconds":round(time.monotonic()-start,4)}
        if self.details is not None: self.details.setdefault("processes",[]).append(d)
        if setup and p.returncode: raise Unavailable("fixture setup failed: "+p.stderr[-600:])
        return d
    def git(self,repo,*args): return self.proc(["git",*args],repo,True)["stdout"].strip()
    def put(self,repo,name,value):
        p=repo/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(value)
    def commit(self,repo):
        self.git(repo,"add","-A"); self.git(repo,"commit","--allow-empty","-m","fixture"); return self.git(repo,"rev-parse","HEAD")
    def fixture(self,name,mode="normal",version=2,base_value="old",spec_edit=None):
        repo=self.root/name; repo.mkdir(); self.git(repo,"init","-b","main"); self.git(repo,"config","core.hooksPath",os.devnull)
        self.put(repo,"app.txt",base_value); self.put(repo,"checks/check.py",CHECK); (repo/"checks/check.py").chmod(0o755); self.put(repo,"support/helper.py","# frozen declared helper\n")
        common='id="validity-fixture"\nproject="synthetic"\ngoal="app exposes new behavior"\n[scope]\ninclude=["app.txt","runner.py","helper.py","support/*"]\nprotected=[]\ntest_files=[]\n[[checks]]\nname="desired observable"\nkind="acceptance"\ntimeout=1\nevidence=["checks/*"]\n'
        if version==2:
            spec='spec_version=2\n'+common+'argv='+json.dumps([sys.executable,"checks/check.py",mode])+'\nentry="checks/check.py"\nchain=["checks/check.py","support/helper.py"]\nassertions=["NEW_BEHAVIOR","COMPLETE_OBSERVATION"]\nbaseline_failures=["NEW_BEHAVIOR"]\n'
        else:
            self.put(repo,"checks/check.py","from pathlib import Path\nimport sys\nsys.exit(0 if Path('app.txt').read_text().strip()=='new' else 1)\n")
            spec='spec_version=1\n'+common+'cmd='+json.dumps(shlex.quote(sys.executable)+" checks/check.py")+'\n'
        if spec_edit: spec=spec_edit(spec)
        self.put(repo,"tasks/check.toml",spec); base=self.commit(repo); self.git(repo,"switch","-c","candidate")
        self.put(repo,"app.txt","new"); candidate=self.commit(repo)
        return repo,base,candidate
    def invoke(self,repo,base,baseline=False):
        log=self.root/(repo.name+("-baseline" if baseline else "-candidate")+".jsonl")
        argv=[sys.executable,self.verifier,"tasks/check.toml","--repo",repo,"--base",base,"--log",log]
        if baseline: argv.append("--baseline")
        d=self.proc(argv,repo)
        records=[]
        if log.exists():
            try: records=[json.loads(line) for line in log.read_text().splitlines()]
            except (ValueError,OSError) as e: raise AssertionError("invalid verifier JSONL: "+str(e))
        d["records"]=records
        return d
    def positive(self,name):
        repo,base,candidate=self.fixture(name)
        b=self.invoke(repo,base,True); c=self.invoke(repo,base)
        need(b["exit"]==0 and "BASELINE_READY" in b["stdout"],"MEANINGFUL_RED: positive base must be READY; got "+str(b["exit"]))
        need(c["exit"]==0 and "SUPPORTED" in c["stdout"],"POSITIVE_GREEN: valid candidate must be SUPPORTED; got "+str(c["exit"]))
        return repo,base,candidate,b,c
    def binding(self,repo,commit):
        rows=[]
        for line in self.git(repo,"ls-tree","-r",commit).splitlines():
            meta,path=line.split("\t",1); mode,kind,oid=meta.split()
            need(kind=="blob","fixture contains unexpected non-blob")
            # Git's stdout decode is sufficient here: every fixture is UTF-8 source.
            raw=self.proc(["git","cat-file","blob",oid],repo,True)["stdout"].encode()
            rows.append({"path":path,"mode":mode,"sha256":digest(raw)})
        rows.sort(key=lambda r:r["path"])
        return {"commit":commit,"tree":self.git(repo,"rev-parse",commit+"^{tree}"),"manifest_sha256":digest(json.dumps(rows,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())}
    def case(self,name,fn):
        self.details={"id":name}
        try: fn(); self.details["status"]="pass"
        except AssertionError as e: self.details.update(status="fail",error=str(e))
        except Unavailable as e: self.details.update(status="unavailable",error=str(e))
        except Exception as e: self.details.update(status="unavailable",error=type(e).__name__+": "+str(e),traceback=traceback.format_exc())
        self.rows.append(self.details); print(self.details["status"].upper(),name,flush=True); self.details=None
    def meaningful(self):
        repo,base,_,_,_=self.positive("positive")
        self.put(repo,"app.txt","old"); self.commit(repo)
        bad=self.invoke(repo,base)
        need(bad["exit"]==1 and "CONTRADICTED" in bad["stdout"],"MEANINGFUL_CANDIDATE_FAILURE: valid unmet assertion must contradict, not setup error or support")
    def check_binding(self):
        repo,base,candidate,b,c=self.positive("binding")
        need(len(c["records"])==1,"SOURCE_BINDING: completion record missing")
        rec=c["records"][0]
        need(rec.get("assurance")=="schema2-evidence-validity","SOURCE_BINDING: missing hardened assurance")
        binding=rec.get("source_binding",{})
        for phase,commit in [("base",base),("candidate",candidate)]: need(binding.get(phase)==self.binding(repo,commit),"SOURCE_BINDING: wrong "+phase+" exact manifest/commit/tree")
        for flag in ["candidate_snapshot","clean_before","unchanged_after"]: need(binding.get(flag) is True,"SOURCE_BINDING: missing "+flag)
        need(len(b["records"])==1 and b["records"][0].get("verdict")=="baseline_ready","BASELINE_RECEIPT: missing ready record")
        for phase in ["base","candidate"]:
            rows=rec.get(phase+"_checks",[])
            need(len(rows)==1 and rows[0].get("assertion_result",{}).get("phase")==phase,"ASSERTION_RECEIPT: validated complete assertion_result absent")
            result=rows[0]["assertion_result"]
            observation=json.loads(next(r["detail"] for r in result["assertions"] if r["id"]=="COMPLETE_OBSERVATION"))
            need(observation["cwd"]==observation["root"] and Path(observation["cwd"]).resolve()!=repo.resolve(),"SNAPSHOT_EXECUTION: checks ran in caller tree or incorrect root")
    def negative(self,name,mode,expected=2,edit=None):
        self.positive(name+"-control")
        repo,base,_=self.fixture(name,mode,spec_edit=edit)
        c=self.invoke(repo,base)
        need(c["exit"]==expected,"EVIDENCE_REJECTION: "+name+" expected "+str(expected)+", got "+str(c["exit"]))
        need("SUPPORTED" not in c["stdout"],"EVIDENCE_REJECTION: false SUPPORTED")
    def dirty(self,untracked=False):
        self.positive("dirty-control" if not untracked else "untracked-control")
        repo,base,_=self.fixture("dirty" if not untracked else "untracked")
        self.put(repo,"surprise.txt" if untracked else "app.txt","dirty")
        before=self.git(repo,"status","--porcelain")
        c=self.invoke(repo,base)
        need(c["exit"]==2,"CLEAN_INPUT: dirty/untracked input must be UNVERIFIABLE")
        need(self.git(repo,"status","--porcelain")==before,"PRESERVE_INPUT: verifier changed caller files")
    def protected(self,name,path):
        self.positive(name+"-control")
        repo,base,_=self.fixture(name); self.put(repo,path,"# skipped runner/helper\n"); self.commit(repo)
        c=self.invoke(repo,base)
        need(c["exit"]==1,"PROTECTED_CHAIN: changed "+path+" must contradict")
    def badspec(self,name,edit,symlink=False):
        self.positive(name+"-control")
        repo,base,_=self.fixture(name,spec_edit=edit)
        if symlink:
            self.git(repo,"switch","main"); (repo/"checks/check.py").unlink(); (repo/"checks/check.py").symlink_to("../support/helper.py"); base=self.commit(repo)
            self.git(repo,"switch","candidate"); self.git(repo,"merge",base,"--no-edit")
        c=self.invoke(repo,base)
        need(c["exit"]==3,"CHAIN_SPEC: unsafe/incomplete declaration must be SPEC_ERROR")
    def legacy(self):
        repo,base,_=self.fixture("legacy",version=1)
        c=self.invoke(repo,base)
        need(c["exit"]==0,"LEGACY: schema1 behavior changed")
        need("legacy-schema1" in c["stdout"] and c["records"][0].get("assurance")=="legacy-schema1","LEGACY: assurance must be visible and recorded")
    def templates(self):
        root=self.verifier.parent
        template=tomllib.loads((root/"task.template.toml").read_text())
        need(template.get("spec_version")==2,"ADOPTION: default template must use schema2")
        need(all("argv" in c and "cmd" not in c and all(k in c for k in ["entry","chain","assertions","baseline_failures"]) for c in template.get("checks",[])),"ADOPTION: every example must declare protocol/chain")
        for file in ["AGENTS.template.md","README.md","FRONTIER.md"]:
            text=(root/file).read_text(); need("schema 2" in text.lower() and "legacy" in text.lower(),"ADOPTION: "+file+" missing explicit schema/legacy boundary")
        repo=self.root/"adoption"; repo.mkdir(); self.git(repo,"init","-b","main")
        self.put(repo,"AGENTS.md","preserve existing instructions")
        p=self.proc([sys.executable,root/"adopt.py",repo,"--project","fixture-project"],repo)
        need(p["exit"]==0,"ADOPTION: existing CLI unavailable")
        need(tomllib.loads((repo/"tasks/task.template.toml").read_text())["spec_version"]==2,"ADOPTION: generated schema1")
        need((repo/"AGENTS.md").read_text()=="preserve existing instructions","ADOPTION: overwrote owner instructions")
        self.put(repo,"tasks/task.template.toml","owner file")
        p=self.proc([sys.executable,root/"adopt.py",repo,"--project","fixture-project"],repo)
        need(p["exit"]==0 and (repo/"tasks/task.template.toml").read_text()=="owner file","ADOPTION: silently rewrote existing spec")
    def historical(self):
        for name,kind in [("mutable_runner","runner"),("import_error_red","import")]:
            repo,base,_=self.fixture("historical-"+name,version=1,base_value="new" if kind=="import" else "old")
            self.git(repo,"switch","main")
            if kind=="runner":
                self.put(repo,"runner.py","import runpy\nrunpy.run_path('checks/check.py',run_name='__main__')\n")
            else: self.put(repo,"checks/check.py","import sys, os\nsys.path.insert(0,os.getcwd())\nimport helper\nfrom pathlib import Path\nimport sys\nsys.exit(0 if Path('app.txt').read_text().strip()=='new' else 1)\n")
            spec=(repo/"tasks/check.toml").read_text()
            if kind=="runner": spec=spec.replace("checks/check.py\"","runner.py\"")
            self.put(repo,"tasks/check.toml",spec); base=self.commit(repo)
            self.git(repo,"switch","-c","historical-change")
            if kind=="runner": self.put(repo,"runner.py","raise SystemExit(0)\n")
            else: self.put(repo,"helper.py","# setup repaired\n")
            self.commit(repo)
            before=self.git(repo,"show",base+":app.txt"); after=(repo/"app.txt").read_text().strip()
            b=self.invoke(repo,base,True); c=self.invoke(repo,base)
            need(b["exit"]==0 and c["exit"]==0,"HISTORICAL_REPRODUCTION: 3.0.1 false support not reproduced")
            need(before==after,"HISTORICAL_REPRODUCTION: application behavior changed")
            self.details.setdefault("counterexamples",[]).append({"name":name,"base":base,"app_before":before,"app_after":after,"baseline":b,"completion":c})
    def run(self,mode):
        if mode=="historical": self.case("SEALED_301_FALSE_SUPPORTS",self.historical); return
        if mode in ("all","core"):
            self.case("MEANINGFUL_RED_GREEN",self.meaningful)
            self.case("EXACT_SOURCE_AND_ASSERTION_BINDING",self.check_binding)
            self.case("LEGACY_ASSURANCE",self.legacy)
            self.case("SCHEMA2_ADOPTION",self.templates)
            self.case("RELEASE_VERSION",lambda:need(self.proc([sys.executable,self.verifier,"--version"],self.root)["stdout"].strip()=="3.1.0" and (self.verifier.parent/"VERSION").read_text().strip()=="3.1.0","RELEASE_VERSION: expected3.1.0"))
        if mode in ("all","negative"):
            for m in ["import","setup","ordinary1","missing","malformed","wrong","duplicate","incomplete","skip","wrong_phase","wrong_check","wrong_token","extra_key","unknown_status","invalid_detail","exit_mismatch","99","timeout","unexpected_base","mutate","mutate_base","commit_during","untracked_during"]:
                self.case("REJECT_"+m.upper(),lambda m=m:self.negative(m,m))
            self.case("DIRTY_INPUT",self.dirty); self.case("UNTRACKED_INPUT",lambda:self.dirty(True))
            self.case("PROTECTED_ENTRY",lambda:self.protected("protected-entry","checks/check.py"))
            self.case("PROTECTED_HELPER",lambda:self.protected("protected-helper","support/helper.py"))
            edits={"entry_outside_evidence":lambda s:s.replace('evidence=["checks/*"]','evidence=["support/*"]'),"entry_absolute":lambda s:s.replace('entry="checks/check.py"','entry="/tmp/check.py"'),"chain_absolute":lambda s:s.replace('"support/helper.py"]','"/tmp/helper.py"]'),"entry_escape":lambda s:s.replace('entry="checks/check.py"','entry="../checks/check.py"'),"chain_escape":lambda s:s.replace('"support/helper.py"]','"../helper.py"]'),"entry_not_in_argv":lambda s:s.replace('entry="checks/check.py"','entry="support/helper.py"'),"cmd_indirection":lambda s:s+'cmd="python runner.py"\n',"missing_chain":lambda s:s.replace('chain=["checks/check.py","support/helper.py"]','chain=[]'),"interpreter_c":lambda s:s.replace('argv='+json.dumps([sys.executable,"checks/check.py","normal"]),'argv='+json.dumps([sys.executable,"-c","raise SystemExit(0)","checks/check.py"])),"interpreter_m":lambda s:s.replace('argv='+json.dumps([sys.executable,"checks/check.py","normal"]),'argv='+json.dumps([sys.executable,"-m","checks.check","checks/check.py"])),"setup_indirection":lambda s:s+'\n[worktree]\nsetup="python runner.py"\n',"service_indirection":lambda s:s+'\n[service]\nstart="python runner.py"\n',"nondeclared_failure":lambda s:s.replace('baseline_failures=["NEW_BEHAVIOR"]','baseline_failures=["NO_SUCH_ASSERTION"]')}
            for name,edit in edits.items(): self.case("SPEC_"+name.upper(),lambda name=name,edit=edit:self.badspec(name,edit))
            self.case("SPEC_SYMLINK_ENTRY",lambda:self.badspec("symlink-entry",lambda s:s,True))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--verifier",required=True,type=Path); ap.add_argument("--receipt",required=True,type=Path); ap.add_argument("--mode",choices=["all","core","negative","historical"],default="all"); a=ap.parse_args()
    rows=[]
    try:
        with tempfile.TemporaryDirectory(prefix="validity-grader-") as tmp:
            suite=Suite(a.verifier,Path(tmp)); suite.run(a.mode); rows=suite.rows
    except (Unavailable,OSError) as e: rows.append({"id":"GRADER_SETUP","status":"unavailable","error":str(e)})
    receipt={"protocol":1,"grader_sha256":digest(Path(__file__).read_bytes()),"verifier_sha256":digest(a.verifier.read_bytes()) if a.verifier.exists() else None,"mode":a.mode,"cases":rows,"counts":{status:sum(r["status"]==status for r in rows) for status in ["pass","fail","unavailable"]},"scope":"deterministic synthetic source-only fixtures; no networks, providers, sandbox, review attestation or exhaustive dynamic-chain guarantee"}
    a.receipt.parent.mkdir(parents=True,exist_ok=True); a.receipt.write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(receipt["counts"])); print("receipt",a.receipt.resolve())
    return 99 if receipt["counts"]["unavailable"] else 1 if receipt["counts"]["fail"] else 0
if __name__=="__main__": sys.exit(main())
