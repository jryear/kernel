#!/usr/bin/env python3
"""Version2 append-only independent correction; version1 source remains frozen."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
sys.dont_write_bytecode=True
V1_PATH=Path(__file__).resolve().parents[1]/'grader.py'
load=importlib.util.spec_from_file_location('frozen_validity_v1',V1_PATH)
v1=importlib.util.module_from_spec(load); load.loader.exec_module(v1)
need=v1.need
SEQUENCE='''import json,os,sys
from pathlib import Path
mode=sys.argv[1]; phase=os.environ["VERIFY_TREE"]
name={"stage":"stage regression","observe":"desired observable","restore":"restore regression"}[mode]
id={"stage":"STAGE","observe":"NEW_BEHAVIOR","restore":"RESTORE"}[mode]
status="pass"
if mode=="stage" and phase=="candidate": Path("app.txt").write_text("new")
if mode=="observe": status="pass" if Path("app.txt").read_text()=="new" else "fail"
if mode=="restore" and phase=="candidate": Path("app.txt").write_text("old")
result={"protocol":1,"check":name,"phase":phase,"run_id":os.environ["VERIFY_RUN_ID"],"assertions":[{"id":id,"status":status,"detail":"sequence fixture"}]}
Path(os.environ["VERIFY_RESULT_JSON"]).write_text(json.dumps(result))
sys.exit(0 if status=="pass" else 1)
'''
SECONDARY='''import json,os,sys
from pathlib import Path
mode,kind=sys.argv[1:3]; phase=os.environ["VERIFY_TREE"]
if phase=="candidate" and mode=="missing": sys.exit(0)
result={"protocol":1,"check":"secondary "+kind,"phase":phase,"run_id":os.environ["VERIFY_RUN_ID"],"assertions":[{"id":"SECONDARY_BOUNDARY","status":"pass","detail":"secondary observed"}]}
if phase=="base" and mode=="wrong_expected_base": result["assertions"][0]["status"]="fail"
Path(os.environ["VERIFY_RESULT_JSON"]).write_text("{broken" if phase=="candidate" and mode=="invalid" else json.dumps(result))
sys.exit(1 if any(row["status"]=="fail" for row in result["assertions"]) else 0)
'''

class Suite(v1.Suite):
    def rawgit(self,repo,*args):
        try: p=subprocess.run(['git',*args],cwd=repo,env=self.env,capture_output=True,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as e: raise v1.Unavailable('raw Git oracle unavailable: '+str(e)) from e
        if p.returncode: raise v1.Unavailable('raw Git oracle failure: '+p.stderr.decode('utf-8','replace'))
        return p.stdout
    def binding(self,repo,commit):
        rows=[]
        for raw in self.rawgit(repo,'ls-tree','-rz',commit).split(b'\0'):
            if not raw: continue
            meta,path=raw.split(b'\t',1); mode,kind,oid=meta.decode('ascii').split()
            need(kind=='blob','BYTE_SAFE_ORACLE: unsupported nonblob fixture')
            rows.append({'path':path.decode('utf-8'),'mode':mode,'sha256':v1.digest(self.rawgit(repo,'cat-file','blob',oid))})
        rows.sort(key=lambda row:row['path'])
        return {'commit':commit,'tree':self.git(repo,'rev-parse',commit+'^{tree}'),'manifest_sha256':v1.digest(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8'))}
    def assert_supported(self,repo,base):
        b=self.invoke(repo,base,True); c=self.invoke(repo,base)
        need(b['exit']==0 and c['exit']==0,'V2_POSITIVE_CONTROL: valid protocol must be READY/SUPPORTED')
        return b,c
    def rewrite_base(self,repo,base,mutate):
        self.git(repo,'switch','main'); mutate(); base=self.commit(repo)
        self.git(repo,'switch','candidate'); self.git(repo,'merge',base,'--no-edit')
        return base
    def sequence(self):
        self.positive('sequence-control')
        repo,base,_=self.fixture('three-check-sequence')
        def mutate():
            self.put(repo,'checks/sequence.py',SEQUENCE)
            text=(repo/'tasks/check.toml').read_text(); head=text.split('[[checks]]')[0]; parts=[]
            for mode,kind,name,ids,failures in [('stage','regression','stage regression',['STAGE'],[]),('observe','acceptance','desired observable',['NEW_BEHAVIOR'],['NEW_BEHAVIOR']),('restore','regression','restore regression',['RESTORE'],[])]:
                parts.append('[[checks]]\nname='+json.dumps(name)+'\nkind='+json.dumps(kind)+'\ntimeout=1\nargv='+json.dumps([sys.executable,'checks/sequence.py',mode])+'\nentry="checks/sequence.py"\nchain=["checks/sequence.py"]\nevidence=["checks/*"]\nassertions='+json.dumps(ids)+'\nbaseline_failures='+json.dumps(failures)+'\n')
            self.put(repo,'tasks/check.toml',head+'\n'.join(parts))
        base=self.rewrite_base(repo,base,mutate)
        self.put(repo,'app.txt','old'); self.commit(repo)
        baseline=self.invoke(repo,base,True); candidate=self.invoke(repo,base)
        need(baseline['exit']==0,'PER_CHECK_INTEGRITY: valid unmoved baseline should be ready')
        need(candidate['exit']==2,'PER_CHECK_INTEGRITY: edit/use/restore between checks must be UNVERIFIABLE')
        need((repo/'app.txt').read_text()=='old','PER_CHECK_INTEGRITY: caller content changed')
    def argv_position(self):
        self.positive('entry-position-control')
        for name,argv in [('wrong-position',[sys.executable,'runner.py','checks/check.py']),('wrong-after-delimiter',[sys.executable,'--','runner.py','checks/check.py']),('misplaced-delimiter',[sys.executable,'runner.py','--','checks/check.py']),('repeated-delimiter',[sys.executable,'--','--','checks/check.py'])]:
            repo,base,_=self.fixture(name,spec_edit=lambda text,argv=argv:text.replace(json.dumps([sys.executable,'checks/check.py','normal']),json.dumps(argv)))
            base=self.rewrite_base(repo,base,lambda:self.put(repo,'runner.py','raise SystemExit(0)\n'))
            got=self.invoke(repo,base)
            need(got['exit']==3,'ENTRY_POSITION: '+name+' must be SPEC_ERROR')
    def delimiter(self):
        repo,base,_=self.fixture('valid-delimiter',spec_edit=lambda text:text.replace(json.dumps([sys.executable,'checks/check.py','normal']),json.dumps([sys.executable,'--','checks/check.py','normal'])))
        self.assert_supported(repo,base)
    def binary_binding(self):
        repo,base,_=self.fixture('binary-manifest')
        def mutate():
            (repo/'binary.png').write_bytes(b'\x89PNG\r\n\x1a\n\xff\x00\x80binary')
            (repo/'crlf.txt').write_bytes(b'first\r\nsecond\r\n')
            (repo/'space café.txt').write_bytes('UTF8 π\n'.encode())
        base=self.rewrite_base(repo,base,mutate); b,c=self.assert_supported(repo,base)
        need(len(c['records'])==1,'BYTE_SAFE_BINDING: missing completion record')
        binding=c['records'][0].get('source_binding',{})
        for phase,commit in [('base',base),('candidate',self.git(repo,'rev-parse','HEAD'))]:
            need(binding.get(phase)==self.binding(repo,commit),'BYTE_SAFE_BINDING: binary/CRLF/UTF8 exact manifest differs for '+phase)
    def executable_drift(self):
        self.positive('mode-drift-control')
        repo,base,_=self.fixture('mode-drift'); self.git(repo,'config','core.filemode','false')
        def mutate():
            source=(repo/'checks/check.py').read_text(); source=source.replace('result={','if phase=="candidate": Path("app.txt").chmod(0o755)\nresult={')
            self.put(repo,'checks/check.py',source)
        base=self.rewrite_base(repo,base,mutate); got=self.invoke(repo,base)
        need(got['exit']==2,'MODE_IDENTITY: source executable-mode mutation must invalidate evidence')
    def secondary(self,kind):
        for mode in ['normal','missing','invalid','helper','wrong_expected_base']:
            repo,base,_=self.fixture('secondary-'+kind+'-'+mode)
            def mutate():
                self.put(repo,'checks/secondary.py',SECONDARY); self.put(repo,'support/secondary.py','# secondary helper\n')
                extra='\n[[checks]]\nname="secondary '+kind+'"\nkind="'+kind+'"\ntimeout=1\nargv='+json.dumps([sys.executable,'checks/secondary.py',mode,kind])+'\nentry="checks/secondary.py"\nchain=["checks/secondary.py","support/secondary.py"]\nevidence=["checks/*"]\nassertions=["SECONDARY_BOUNDARY"]\nbaseline_failures=[]\n'
                self.put(repo,'tasks/check.toml',(repo/'tasks/check.toml').read_text()+extra)
            base=self.rewrite_base(repo,base,mutate)
            if mode=='normal': self.assert_supported(repo,base)
            elif mode=='wrong_expected_base':
                got=self.invoke(repo,base,True)
                need(got['exit']==2,'EVERY_KIND_BASELINE: '+kind+' unexpected failed IDs must reject actual baseline')
            else:
                if mode=='helper': self.put(repo,'support/secondary.py','# bypass changed\n'); self.commit(repo)
                got=self.invoke(repo,base); expected=1 if mode=='helper' else 2
                need(got['exit']==expected,'EVERY_KIND_PROTOCOL: '+kind+' '+mode+' expected '+str(expected))
    def baseline_invalid(self,mode):
        self.positive('baseline-'+mode+'-control')
        repo,base,_=self.fixture('baseline-'+mode,mode)
        got=self.invoke(repo,base,True)
        need(got['exit']==2 and 'BASELINE_NOT_READY' in got['stdout'],'ACTUAL_BASELINE: '+mode+' must be NOT_READY')
    def wrong_expected(self):
        self.positive('wrong-expected-control')
        repo,base,_=self.fixture('wrong-expected',spec_edit=lambda text:text.replace('baseline_failures=["NEW_BEHAVIOR"]','baseline_failures=["COMPLETE_OBSERVATION"]'))
        got=self.invoke(repo,base,True)
        need(got['exit']==2,'BASELINE_FAILED_IDS: different valid expected failure set must be NOT_READY')
    def legacy_baseline(self):
        repo,base,_=self.fixture('legacy-baseline',version=1); got=self.invoke(repo,base,True)
        need(got['exit']==0 and 'legacy-schema1' in got['stdout'],'LEGACY_BASELINE: visible assurance label missing or mechanical behavior changed')
    def additions(self):
        cases=[('B1_PER_CHECK_INTEGRITY',self.sequence),('B2_DIRECT_ENTRY_POSITION',self.argv_position),('B2_DELIMITER_POSITIVE',self.delimiter),('B3_BYTE_SAFE_MANIFEST',self.binary_binding),('B3_EXECUTABLE_MODE_MUTATION',self.executable_drift),('B4_REGRESSION_PROTOCOL',lambda:self.secondary('regression')),('B4_ADVERSARIAL_PROTOCOL',lambda:self.secondary('adversarial')),('B4_BASELINE_IMPORT',lambda:self.baseline_invalid('import')),('B4_BASELINE_SETUP',lambda:self.baseline_invalid('setup')),('B4_BASELINE_UNEXPECTED_FAILURE',lambda:self.baseline_invalid('unexpected_base')),('B4_BASELINE_WRONG_EXPECTED_FAILURE',self.wrong_expected),('B4_LEGACY_BASELINE_LABEL',self.legacy_baseline)]
        for name,fn in cases: self.case(name,fn)

def main():
    p=argparse.ArgumentParser(); p.add_argument('--verifier',required=True,type=Path); p.add_argument('--receipt',required=True,type=Path); a=p.parse_args(); rows=[]
    try:
        with tempfile.TemporaryDirectory(prefix='validity-v2-grader-') as tmp:
            suite=Suite(a.verifier,Path(tmp)); suite.additions(); rows=suite.rows
    except (v1.Unavailable,OSError) as e: rows.append({'id':'GRADER_SETUP','status':'unavailable','error':str(e)})
    result={'protocol':1,'rubric_version':2,'grader_sha256':v1.digest(Path(__file__).read_bytes()),'frozen_v1_grader_sha256':v1.digest(V1_PATH.read_bytes()),'verifier_sha256':v1.digest(a.verifier.read_bytes()),'cases':rows,'counts':{status:sum(r['status']==status for r in rows) for status in ['pass','fail','unavailable']},'scope':'four frozen-v1 source-review rubric corrections; not new application findings or hostile-code sandbox'}
    a.receipt.parent.mkdir(parents=True,exist_ok=True); a.receipt.write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result['counts'])); print('receipt',a.receipt.resolve())
    return 99 if result['counts']['unavailable'] else 1 if result['counts']['fail'] else 0
if __name__=='__main__': sys.exit(main())
