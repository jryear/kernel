"""Manual pre-freeze cost calibration, never acceptance or sandbox proof.
Run from the repository root with PYTHONDONTWRITEBYTECODE=1 python3 -B
 tests/sandbox_fixtures/measure_cost.py. Writes only external state and temp fixtures.
"""
import json,sys,time,tempfile,platform,math
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from harness import Probe,exercise,GROUPS,configure_file,direct_control,listener
rows=[]
def timed(label,fn):
 start=time.monotonic(); result=fn();elapsed=time.monotonic()-start
 row={'label':label,'seconds':elapsed};rows.append(row);print(json.dumps(row),flush=True);return result
for group in GROUPS:
 for repeat in range(2):
  result=timed(group+'-baseline-witness-'+str(repeat),lambda:exercise(group))
  assert result[0] is False and result[1]['decisive_counterexample']['nested_verdict']=='supported'
with tempfile.TemporaryDirectory(prefix='sandbox-cost-') as tmp:
 top=Path(tmp)
 for repeat in range(3):
  case={'id':'CONTROL_COST','layer':'effect','operation':'write','expected':'unverifiable'}
  p=Probe(top/('file-'+str(repeat)),case,'disabled');configure_file(p,case)
  timed('file-positive-control-'+str(repeat),lambda:direct_control(p))
 for repeat in range(2):
  def network_control():
   with listener() as server:
    case={'id':'NETWORK_COST','layer':'policy','operation':'connect','expected':'unverifiable'}
    p=Probe(top/('network-'+str(repeat)),case,'disabled')
    p.config.update(address='127.0.0.1',port=server.server_address[1],expect_ack=True,expected_ack=p.config['nonce'])
    assert direct_control(p)['ack_matches'] is True
  timed('network-positive-control-'+str(repeat),network_control)
report={'method':'Two actual unsandboxed nested baseline+candidate witness runs per group; separate direct controls. Full matrix costs are calibrated projections, not backend qualification.','platform':platform.platform(),'python':sys.version,'measurements':rows}
# Preserve the approved v2 calibration floor when budgeting new v3 variants.
nested=max(2.3116281669936143, max(r['seconds'] for r in rows if 'witness' in r['label']))
file=max(0.23199816700071096, max(r['seconds'] for r in rows if r['label'].startswith('file')))
network=max(0.7374945409828797, max(r['seconds'] for r in rows if r['label'].startswith('network')))
cases=json.loads((Path(__file__).parent/'matrix.json').read_text())['cases']
costs=[]
for group,layers in GROUPS.items():
    assigned=[c for c in cases if c['layer'] in layers]
    variants=sum(len(c['logging']) for c in assigned)
    nested_count=sum(len(c['logging'])*c.get('params',{}).get('runs',1) for c in assigned)
    file_controls=sum(len(c['logging']) for c in assigned if c['layer']=='effect' and c['operation'] not in ('clean','environment_probe'))
    network_controls=sum(len(c['logging']) for c in assigned if c['layer']=='policy' and c['operation'] in ('connect','bind','udp','proxy_http','proxy_connect'))
    timeout_allowance=sum(len(c['logging'])*6 for c in assigned if c['operation']=='timeout')
    projected=nested*(1+nested_count)+file*file_controls+network*network_controls+timeout_allowance
    costs.append({'group':group,'cases':len(assigned),'variants':variants,
                  'charged_nested_invocations':nested_count,'file_controls':file_controls,
                  'network_controls':network_controls,'timeout_allowance_seconds':timeout_allowance,
                  'measured_witness_seconds':[r['seconds'] for r in rows if r['label'].startswith(group)],
                  'projected_seconds':projected,
                  'timeout_seconds':max(600,math.ceil((120+4*projected+5*variants)/60)*60)})
report.update(cost_model='All variants charged the slowest measured nested invocation, including classifier/prelaunch rows (conservative surrogate); extra sequential runs, direct controls, and 6s per timeout variant added. Timeout=max(600,ceil_to_60(120+4*projection+5*variants)). Approved v2 calibration floors are retained; backend overhead not measured; projection is not a full matrix timing.',checks=costs)
state=Path.home()/'.local/state/kernel'
state.mkdir(parents=True,exist_ok=True)
with (state/'sandbox-v4-costs.json').open('x', encoding='utf-8') as output:
 output.write(json.dumps(report,indent=2)+'\n')
