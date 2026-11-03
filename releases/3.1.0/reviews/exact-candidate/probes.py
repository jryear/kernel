import hashlib,importlib.util,json,pathlib,sys,tempfile
sys.dont_write_bytecode=True
out=pathlib.Path(__file__).resolve().parent; source=out/'source'
spec=importlib.util.spec_from_file_location('independent_frozen_helpers',source/'evidence/validity/grader.py'); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory(prefix='redteam-kernel-probes-',dir=out) as temp:
 s=mod.Suite(source/'verify.py',pathlib.Path(temp)); result=[]
 def base_edit(repo,base,edit):
  s.git(repo,'switch','main');edit();base=s.commit(repo);s.git(repo,'switch','candidate');s.git(repo,'merge',base,'--no-edit');return base
 def record(name,fn):
  s.details={'name':name}
  try: fn();s.details['status']='pass'
  except Exception as e:s.details.update(status='fail',error=type(e).__name__+': '+str(e))
  result.append(s.details);s.details=None
 def direct():
  repo,base,_=s.fixture('direct-bare')
  def edit():
   s.put(repo,'check','#!'+sys.executable+'\n'+mod.CHECK);(repo/'check').chmod(0o755)
   text=(repo/'tasks/check.toml').read_text().replace('argv='+json.dumps([sys.executable,'checks/check.py','normal']),'argv='+json.dumps(['check','normal'])).replace('entry="checks/check.py"','entry="check"').replace('chain=["checks/check.py","support/helper.py"]','chain=["check","support/helper.py"]').replace('evidence=["checks/*"]','evidence=["check"]');s.put(repo,'tasks/check.toml',text)
  base=base_edit(repo,base,edit);b=s.invoke(repo,base,True);c=s.invoke(repo,base);assert b['exit']==c['exit']==0,(b,c)
  binding=c['records'][0]['verifier_package_binding'];digests={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ['verify.py','kernel_runtime.py','kernel_report.py']};assert binding['components']==digests;assert binding['manifest_sha256']==hashlib.sha256(json.dumps(digests,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  s.details['observed_package_binding']=binding
 def runtime_alias():
  repo,base,_=s.fixture('runtime-alias');alias=pathlib.Path(temp)/'python3';alias.symlink_to(repo/'runner.py')
  def edit():
   s.put(repo,'runner.py','#!'+sys.executable+'\nraise SystemExit(0)\n');(repo/'runner.py').chmod(0o755)
   text=(repo/'tasks/check.toml').read_text().replace(json.dumps([sys.executable,'checks/check.py','normal']),json.dumps([str(alias),'checks/check.py','normal']));s.put(repo,'tasks/check.toml',text)
  base=base_edit(repo,base,edit);c=s.invoke(repo,base);assert c['exit']==3,c
 def malformed_result(mode):
  repo,base,_=s.fixture('receipt-'+mode)
  def edit():
   text=(repo/'checks/check.py').read_text()
   if mode=='boolean_protocol': text=text.replace('result={','result={').replace('if mode == "wrong_phase"','if phase == "candidate": result["protocol"]=True\nif mode == "wrong_phase"')
   elif mode=='duplicate_key':text=text.replace('else: Path(os.environ["VERIFY_RESULT_JSON"]).write_text(json.dumps(result))','else: Path(os.environ["VERIFY_RESULT_JSON"]).write_text((\'{"protocol":1,\'+json.dumps(result)[1:]) if phase=="candidate" else json.dumps(result))')
   elif mode=='symlink':text=text.replace('else: Path(os.environ["VERIFY_RESULT_JSON"]).write_text(json.dumps(result))','else:\n    dest=Path(os.environ["VERIFY_RESULT_JSON"])\n    if phase=="candidate":\n        target=dest.parent/"other.json"; target.write_text(json.dumps(result)); dest.symlink_to(target)\n    else: dest.write_text(json.dumps(result))')
   s.put(repo,'checks/check.py',text)
  base=base_edit(repo,base,edit);b=s.invoke(repo,base,True);c=s.invoke(repo,base);assert b['exit']==0 and c['exit']==2,(b,c)
  s.details['rejection']=c['records'][0]['candidate_checks'][0].get('result_protocol_error')
 def symlink_parent():
  repo,base,_=s.fixture('directory-symlink')
  def edit():
   (repo/'alias').symlink_to('checks',target_is_directory=True);text=(repo/'tasks/check.toml').read_text().replace('checks/check.py','alias/check.py');s.put(repo,'tasks/check.toml',text.replace('evidence=["checks/*"]','evidence=["alias*"]'))
  base=base_edit(repo,base,edit);c=s.invoke(repo,base);assert c['exit']==3,c
 record('DIRECT_BARE_ENTRY_AND_PACKAGE_BINDING',direct);record('RUNTIME_SYMLINK_INTO_REPOSITORY_REJECTED',runtime_alias)
 for mode in ['boolean_protocol','duplicate_key','symlink']:record('RESULT_'+mode.upper(),lambda mode=mode:malformed_result(mode))
 record('ENTRY_DIRECTORY_SYMLINK_REJECTED',symlink_parent)
 payload={'kind':'additional independent deterministic probes, not frozen contract gates','candidate':'b6217c81ff5c4762c9f7632a4d0252c584b93eaf','cases':result,'counts':{v:sum(r['status']==v for r in result) for v in ['pass','fail']}}
 (out/'independent-probes.json').write_text(json.dumps(payload,indent=2)+'\n');print(json.dumps(payload['counts']))
