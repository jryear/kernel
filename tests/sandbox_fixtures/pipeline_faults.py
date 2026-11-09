"""Host-owned reproductions through the actual v5 collector/decision path.

The adapter is a test-only Node preload applied by the trusted Python driver.
It reads a host-owned anonymous descriptor; production supervisor and sandboxed
candidate input have no switch or endpoint for event injection.
"""
from __future__ import annotations
import json
import uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent


def run_pipeline_fault(top, case, mode, bundle, harness):
    name=case['id']
    if mode!='enabled':
        raise harness.Unavailable(name+': real collector path requires enabled logging')
    control_case={**case,'layer':'diagnostic'}
    control=harness.Probe(top/'control',control_case,mode,bundle)
    control.config.update(operation='write',target=str(control.target))
    direct=harness.direct_control(control)
    probe=harness.Probe(top/('fault-'+name),control_case,mode,bundle)
    probe.collector_adapter=HERE/'fault_collector_adapter.mjs'
    probe.config.update(operation='write',target=str(probe.target),swallow_denial=True,
                        diagnostic_barrier_nonce=uuid.uuid4().hex,
                        diagnostic_barrier_handshake='$TMP/diagnostic-handshake.json',
                        diagnostic_barrier_release='$TMP/diagnostic-release.json')
    probe.prepare()
    observed=probe.invoke()
    receipt=harness.receipt_check(observed,case,mode)
    harness.need(not observed['changes'] and observed['prefix_unchanged'],
                 name+': independent protected inventory or receipt prefix changed')
    harness.need(observed['operation'] is None,name+': hidden payload witness leaked into subject')
    provisional=receipt.get('assertions',{}).get('provisional')
    harness.need(isinstance(provisional,dict) and all(x.get('status')=='pass' for x in provisional.get('assertions',[])),
                 name+': independently complete passing candidate assertions missing')
    cleanup=receipt['assertions']['cleanup']
    harness.need(cleanup.get('complete') is True and not cleanup.get('survivors') and not cleanup.get('errors'),
                 name+': independent cleanup not healthy')
    audit_path=probe.root/'collector-adapter-audit.jsonl'
    fault_path=probe.root/'fault-adapter-audit.jsonl'
    if not audit_path.exists() or not fault_path.exists():
        raise harness.Unavailable(name+': host collector/fault audit missing')
    records=[json.loads(line) for line in audit_path.read_text().splitlines()]
    fault_records=[json.loads(line) for line in fault_path.read_text().splitlines()]
    injected=[row for row in records if row.get('type')=='injected']
    harness.need(len(injected)==1 and injected[0]['witness'].get('errno') in harness.DENIED and
                 injected[0]['witness'].get('outcome')=='denied',name+': actual blocked operation witness missing')
    diag=receipt['diagnostics']; reasons=receipt['decision'].get('unavailable_reasons',[])
    required={'SUBSCRIPTION_DROP':'diagnostic_loss','SPOOL_OVERFLOW':'diagnostic_loss',
              'COLLECTOR_DEATH':'diagnostic_collector_fault',
              'AMBIGUOUS_EVENT_ID':'diagnostic_attribution_ambiguous',
              'CROSS_INVOCATION_EVENT':'diagnostic_cross_invocation',
              'DRAIN_TIMEOUT':'diagnostic_drain_incomplete',
              'LATE_RELEVANT_DENIAL':'observed_relevant_denial'}
    if name in required:
        harness.need(required[name] in reasons,name+': named fault not reflected in verdict: '+str(reasons))
    kinds={row.get('type') for row in fault_records}
    if name=='SUBSCRIPTION_DROP':
        harness.need('subscription_callbacks_held' in kinds and diag.get('dropped',0)>0,
                     name+': actual subscriber gap not recorded')
        harness.need(diag.get('raw_denial_count')==150,name+': retained raw burst is incomplete')
    elif name=='SPOOL_OVERFLOW':
        harness.need('write_benign_burst' in kinds and diag.get('dropped',0)>0 and diag.get('persisted')==10000,
                     name+': actual 10000-event supervisor capacity not crossed')
    elif name=='COLLECTOR_DEATH':
        harness.need('terminate_real_collector' in kinds and diag.get('monitor',{}).get('exit'),
                     name+': real collector exit not recorded')
    elif name=='AMBIGUOUS_EVENT_ID':
        harness.need('write_unknown_command_tag' in kinds and any(e.get('attribution')=='ambiguous' for e in diag.get('events',[])),
                     name+': unresolvable real event not retained')
    elif name=='CROSS_INVOCATION_EVENT':
        harness.need('write_prior_benign_event' in kinds and any(e.get('attribution')=='prior_invocation' for e in diag.get('events',[])),
                     name+': prior origin was not retained')
    elif name=='DRAIN_TIMEOUT':
        harness.need('schedule_after_unchanged_drain_deadline' in kinds and diag.get('drain_timed_out') is True,
                     name+': data after real drain deadline missing')
    elif name=='LATE_RELEVANT_DENIAL':
        harness.need('supervisor_finish_observed' in kinds and 'write_late_denial' in kinds and injected[0]['leader_exited'] and any(e.get('relevance')=='relevant_denial' and e.get('arrival_phase')=='drain' for e in diag.get('events',[])),
                     name+': relevant denial was not received after leader exit')
    elif name=='DELAYED_AFTER_LEADER_EXIT':
        harness.need('supervisor_finish_observed' in kinds and 'write_benign_delayed_event' in kinds and injected[0]['leader_exited'] and any(e.get('relevance')=='benign' and e.get('attribution')=='original_invocation' and e.get('arrival_phase')=='drain' for e in diag.get('events',[])),
                     name+': delayed original benign event missing')
    return {'id':name,'mode':mode,'verdict':observed['record']['verdict'],
            'control':direct,'host_witness':injected[0]['witness'],'fault_audit':fault_records,
            'reasons':reasons,'received':diag.get('received'),'persisted':diag.get('persisted'),
            'dropped':diag.get('dropped'),'events':diag.get('events'),
            'receipt_identity':receipt['identity']}
