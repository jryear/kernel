import hashlib,importlib.util,json,pathlib,sys,tempfile
sys.dont_write_bytecode=True
out=pathlib.Path(__file__).resolve().parent; source=out/'source'
spec=importlib.util.spec_from_file_location('frozen_helpers',source/'evidence/validity/grader.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='redteam-caller-probe-',dir=out) as temp:
 s=m.Suite(source/'verify.py',pathlib.Path(temp));s.details={};repo,base,_=s.fixture('caller-mutation');s.git(repo,'switch','main')
 text=(repo/'checks/check.py').read_text().replace('result={','if phase == "candidate": Path('+repr(str(repo/'app.txt'))+').write_text("caller changed")\nresult={');s.put(repo,'checks/check.py',text);base=s.commit(repo);s.git(repo,'switch','candidate');s.git(repo,'merge',base,'--no-edit')
 c=s.invoke(repo,base);ok=c['exit']==2 and any('caller identity changed' in r for r in c['records'][0]['reasons']) and c['records'][0]['source_binding']['unchanged_after'] is False
 payload={'kind':'additional independent deterministic probe, not frozen contract gate','id':'CALLER_MUTATION_AFTER_CAPTURE','status':'pass' if ok else 'fail','result':c,'processes':s.details['processes']};(out/'caller-probe.json').write_text(json.dumps(payload,indent=2)+'\n');print(payload['status']);sys.exit(0 if ok else 1)
