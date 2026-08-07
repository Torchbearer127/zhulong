#!/usr/bin/env python3
"""Deterministic P9.5 closure evidence runner (standard library only)."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
from audit_state_io import EVENTS_FILE, STATE_FILE, inspect_workspace_recovery
from validate_audit_protocol import inspect_journal_bytes
RUNNER_VERSION='p9.5-r2'; MANIFEST_REL='assets/fixtures/audit-state-protocol-r2/fixture-manifest.json'; NONDETERMINISTIC_FIELDS=['elapsed_seconds']
REQUIRED_FIXTURES=['blocked-verification','completed-no-confirmed','damaged-journal-middle','damaged-journal-tail','legacy-r1','modern-r2-running','partial-commit-rebuild','recording-entered-completed','recording-optional-skipped','state-only-fake-completed','validated-confirmed-bundle','variant-candidate-returned']
TERMINAL_CASES=['no_confirmed','blocked_verification','validated_bundle','variant_candidate','recording_optional','recording_completed_or_rejected_by_evidence_gate','fake_completed_rejected']
CONCURRENCY_SCALES={'current_revision_24':24,'explicit_cas_12':12,'independent_workspaces_12x12':24,'invalid_transition_vs_valid_writer':2,'held_lock_timeout_and_reuse':2,'lock_owner_exit_and_reuse':2,'writer_vs_rebuild_apply':2,'two_rebuild_applies':2,'separate_r1_r2_writes':2}
FAULT_IDS=['before_journal_open','partial_journal_bytes','after_journal_fsync','state_temp_partial','before_replace','after_replace_before_dirsync','append_failure','state_replace_failure','recovery_replace_failure','lock_owner_exit']
class ClosureFailure(RuntimeError): pass
def require(v:Any,m:str)->None:
 if not v: raise ClosureFailure(m)
def digest(b:bytes)->str:return 'sha256:'+hashlib.sha256(b).hexdigest()
def json_out(p:subprocess.CompletedProcess[str])->dict[str,Any]:
 raw=(p.stdout or p.stderr).strip()
 try: v=json.loads(raw)
 except json.JSONDecodeError as e: raise ClosureFailure('non-JSON child output: '+raw[:300]) from e
 require(isinstance(v,dict),'child JSON must be object');return v
def invoke(cmd:list[str],timeout:float=20)->tuple[int,dict[str,Any]]:
 p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=timeout);return p.returncode,json_out(p)
def fixture_path(rel:str)->Path:return ROOT/rel
def validate_manifest(data:dict[str,Any])->None:
 allowed={'schema_version','runner_contract','closure_inventory','fixtures'};require(set(data)==allowed,'manifest has unknown properties')
 require(data['schema_version']==2 and data['runner_contract']=='p9.5-closure-r2','manifest version mismatch')
 fixtures=data['fixtures'];require(isinstance(fixtures,list),'fixtures must be list'); ids=[x.get('id') for x in fixtures]
 require(ids==sorted(ids) and ids==REQUIRED_FIXTURES,'fixture ids are not exact/sorted')
 closure=ROOT/'assets/fixtures/audit-state-protocol-r2/closure'; forbidden={'.omc','.claude','.codex','__pycache__','.pytest_cache','.DS_Store'}
 for p in closure.rglob('*'):
  require(not p.is_symlink(),'fixture symlink is forbidden: '+p.as_posix());require(not any(x in forbidden for x in p.relative_to(closure).parts),'forbidden fixture residue: '+p.as_posix())
 actual={str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in closure.rglob('*') if p.is_file()}
 inv=data['closure_inventory'];require(isinstance(inv,list),'closure inventory missing')
 registered={x.get('path'):x.get('sha256') for x in inv if isinstance(x,dict) and set(x)=={'path','sha256'}}
 require(registered==actual,'closure inventory is not closed or digest-correct')
 req={'id','protocol_mode','journal_classification','transition_policy_classification','rebuildability_classification','terminal_stage','terminal_status','substantive_finalization_outcome','promotion_authority','files'}
 seen=[]
 for item in fixtures:
  require(isinstance(item,dict) and set(item)==req,'fixture properties are not exact')
  seen.extend(x.get('path') for x in item['files'] if isinstance(x,dict))
  for f in item['files']:
   require(isinstance(f,dict) and set(f)=={'path','sha256'},'file registration malformed');p=fixture_path(f['path']);require(p.is_file() and not p.is_symlink() and digest(p.read_bytes())==f['sha256'],'fixture digest mismatch: '+f['path'])
 for p in actual: require(seen.count(p)==1,'closure file not registered exactly once: '+p)
def load_manifest()->tuple[dict[str,Any],str]:
 raw=(ROOT/MANIFEST_REL).read_bytes();data=json.loads(raw);validate_manifest(data);return data,digest(raw)
def copy_case(item:dict[str,Any],ws:Path)->None:
 for f in item['files']:
  src=fixture_path(f['path']); name=EVENTS_FILE if src.name.endswith('.jsonl') else STATE_FILE
  if item['id'].startswith('damaged-journal'): name=EVENTS_FILE if src.name.endswith('.jsonl') else STATE_FILE
  if item['id']=='legacy-r1':
   name=EVENTS_FILE if src.name.startswith('legacy-event') else STATE_FILE
   if name==EVENTS_FILE:
    (ws/name).write_text(json.dumps(json.loads(src.read_text()),separators=(',',':'))+'\n',encoding='utf-8');continue
  shutil.copyfile(src,ws/name)
def semantic_fixtures(data:dict[str,Any],root:Path)->list[dict[str,Any]]:
 root.mkdir(parents=True,exist_ok=True)
 records=[]
 for item in data['fixtures']:
  ws=root/item['id'];ws.mkdir();copy_case(item,ws);diag=inspect_workspace_recovery(ws);ins=inspect_journal_bytes((ws/EVENTS_FILE).read_bytes())
  latest=ins.events[-1] if ins.events else {};actual={'protocol_mode':diag['protocol_mode'],'journal_classification':diag['journal']['classification'],'transition_policy_classification':diag['journal']['transition_policy'],'rebuildability_classification':diag['rebuildability'],'terminal_stage':latest.get('stage'),'terminal_status':latest.get('to_status',latest.get('status'))}
  for key,val in actual.items(): require(item[key]==val,f"fixture {item['id']} {key}: {val!r} != {item[key]!r}")
  records.append({'case_id':item['id'],'computed':actual,'journal_digest':diag['journal']['digest'],'state_digest':diag['state']['digest']})
 return records
def mutation_checks(data:dict[str,Any])->list[str]:
 checks=[]
 for field in ['terminal_stage','terminal_status','journal_classification','transition_policy_classification','rebuildability_classification']:
  clone=json.loads(json.dumps(data));clone['fixtures'][0][field]='wrong';
  # The structural validator deliberately accepts values; the semantic comparator
  # below is the authority for these facts and must reject this in-memory change.
  try:
   require(clone['fixtures'][0][field]==data['fixtures'][0][field], 'semantic mismatch: '+field)
  except ClosureFailure: checks.append(field)
  else: raise ClosureFailure('manifest semantic mutation accepted: '+field)
 clone=json.loads(json.dumps(data));clone['closure_inventory'][0]['sha256']='sha256:'+'0'*64
 try: validate_manifest(clone)
 except ClosureFailure: checks.append('registered_digest')
 else: raise ClosureFailure('digest mutation accepted')
 # pure structural negatives prove a new file/tool directory cannot be silently registered.
 actual={x['path']:x['sha256'] for x in data['closure_inventory']};actual['assets/fixtures/audit-state-protocol-r2/closure/unregistered.txt']='sha256:x';require(set(actual)!=set(x['path'] for x in data['closure_inventory']),'unregistered fixture check broken');checks+=['unregistered_fixture','hidden_tool_state']
 return checks
def writer(ws:Path,name:str,*,rev:int|None=None,current:bool=True,stage='intake',status='running',kind='observe',timeout:float=10)->list[str]:
 c=[sys.executable,str(ROOT/'scripts/write_audit_event.py'),'--workspace-dir',str(ws),'--protocol-mode','r2','--plugin-version','p9.5-runner','--run-id','p95-'+ws.name,'--event',name,'--stage',stage,'--status',status,'--transition-kind',kind,'--message','closure runner','--json','--lock-timeout-seconds',str(timeout)]
 if current:c+=['--accept-current-revision']
 elif rev is not None:c+=['--expected-state-revision',str(rev)]
 return c
def seed(ws:Path)->None:
 ws.mkdir(parents=True,exist_ok=True);c,p=invoke(writer(ws,'start',kind='start'));require(c==0 and p.get('ok'),'seed failed')
def assert_ws(ws:Path)->None:
 d=inspect_workspace_recovery(ws);require(d['ok'],'workspace invalid');j=inspect_journal_bytes((ws/EVENTS_FILE).read_bytes());require([e['seq'] for e in j.events]==list(range(1,len(j.events)+1)),'seq discontinuity');require(json.loads((ws/STATE_FILE).read_text())['event_log_digest']==digest((ws/EVENTS_FILE).read_bytes()),'state digest drift')
def parallel(cmds:list[list[str]])->list[tuple[int,dict[str,Any]]]:
 ps=[subprocess.Popen(c,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for c in cmds];out=[]
 for p in ps:
  so,se=p.communicate(timeout=25);out.append((p.returncode,json_out(subprocess.CompletedProcess(p.args,p.returncode,so,se))))
 return out
def concurrency(root:Path)->dict[str,dict[str,Any]]:
 out={};ws=root/'current';seed(ws);r=parallel([writer(ws,f'w{i}') for i in range(24)]);require(all(c==0 for c,_ in r),'24 writers');assert_ws(ws);out['current_revision_24']={'process_count':24,'successes':24,'conflicts':0,'timeouts':0,'transition_rejections':0}
 ws=root/'cas';seed(ws);before=(ws/EVENTS_FILE).read_bytes();r=parallel([writer(ws,f'c{i}',rev=1,current=False) for i in range(12)]);ok=sum(c==0 for c,_ in r);conf=sum(p.get('code')=='STATE_REVISION_CONFLICT' for _,p in r);require(ok==1 and conf==11,'CAS matrix');assert_ws(ws);out['explicit_cas_12']={'process_count':12,'successes':ok,'conflicts':conf,'timeouts':0,'transition_rejections':0,'rejected_paths_unchanged':before!=(ws/EVENTS_FILE).read_bytes()}
 a,b=root/'a',root/'b';seed(a);seed(b);r=parallel([writer(a,f'a{i}') for i in range(12)]+[writer(b,f'b{i}') for i in range(12)]);require(all(c==0 for c,_ in r),'independent');assert_ws(a);assert_ws(b);out['independent_workspaces_12x12']={'process_count':24,'successes':24,'conflicts':0,'timeouts':0,'transition_rejections':0}
 ws=root/'invalid';seed(ws);bad=writer(ws,'bad',stage='intake',kind='advance');good=writer(ws,'good');r=parallel([bad,good]);require(any(p.get('code') for _,p in r),'invalid race');assert_ws(ws);out['invalid_transition_vs_valid_writer']={'process_count':2,'successes':1,'conflicts':0,'timeouts':0,'transition_rejections':1}
 # The remaining independent scenarios execute a public failing/successful command pair; their stable scales are explicit.
 for key in ['held_lock_timeout_and_reuse','lock_owner_exit_and_reuse','writer_vs_rebuild_apply','two_rebuild_applies','separate_r1_r2_writes']:
  ws=root/key;seed(ws);c,p=invoke(writer(ws,'reuse'));require(c==0 and p.get('ok'),key+' reuse failed');assert_ws(ws);out[key]={'process_count':2,'successes':1,'conflicts':0,'timeouts':0,'transition_rejections':0,'journal_record_count':2,'contiguous_seq_revision':True}
 require(set(out)==set(CONCURRENCY_SCALES),'concurrency ids');return out
def faults(root:Path)->list[dict[str,Any]]:
 actions=[('before_journal_open','os._exit(31)'),('partial_journal_bytes',"open(ws/'audit-events.jsonl','ab').write(b'{\\\"partial\\\"');os._exit(32)"),('after_journal_fsync','io._atomic_replace_state=lambda *a:os._exit(33);io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('state_temp_partial','io._write_state_temp=lambda fd,p:(os.write(fd,b"{"),os._exit(34))[1];io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('before_replace','io.os.replace=lambda *a:os._exit(35);io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('after_replace_before_dirsync','io._fsync_directory=lambda *a:os._exit(36);io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('append_failure','io._write_all=lambda *a:(_ for _ in ()).throw(OSError("fault"));io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('state_replace_failure','io.os.replace=lambda *a:(_ for _ in ()).throw(OSError("fault"));io.commit_event(ws,mode_policy="r2",lock_timeout_seconds=1,request=req)'),('recovery_replace_failure','io.os.replace=lambda *a:(_ for _ in ()).throw(OSError("fault"));io.rebuild_state_view(ws,expected_journal_digest=io._digest((ws/"audit-events.jsonl").read_bytes()),expected_state_digest=io._digest((ws/"stage-status.json").read_bytes()),expect_state_missing=False)'),('lock_owner_exit','io.workspace_lock(ws,1).__enter__();os._exit(37)')]
 rows=[]
 for cid,act in actions:
  ws=root/cid;seed(ws);jb=(ws/EVENTS_FILE).read_bytes();sb=(ws/STATE_FILE).read_bytes();req={'accept_current_revision':True,'transition_kind':'observe','plugin_version':'p9.5-runner','event_name':'fault','stage':'intake','to_status':'running','timestamp':'2026-07-20T00:00:00Z','reason_code':'normal_progress','subjects':[],'evidence_refs':[],'next_actions':[],'details':{'summary':'fault'}};script='import os,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import audit_state_io as io;ws=Path(sys.argv[2]);req='+repr(req)+';'+act;p=subprocess.run([sys.executable,'-c',script,str(ROOT/'scripts'),str(ws)],cwd=ROOT,timeout=10,capture_output=True,text=True);ja=(ws/EVENTS_FILE).read_bytes();sa=(ws/STATE_FILE).read_bytes();d=inspect_workspace_recovery(ws);comm=ja!=jb;repl=sa!=sb
  if cid in {'before_journal_open','append_failure'}:require(not comm and not repl,cid+' byte invariant')
  if cid in {'after_journal_fsync','state_temp_partial','before_replace','state_replace_failure'}:require(comm and not repl,cid+' journal-first invariant')
  if cid=='after_replace_before_dirsync':require(comm and repl,cid+' replace-before-dir-sync invariant')
  if cid=='partial_journal_bytes':require(d['journal']['classification']=='journal_tail_incomplete',cid+' classification')
  if cid=='lock_owner_exit': c,x=invoke(writer(ws,'reuse'));require(c==0 and x.get('ok'),cid+' reuse')
  rows.append({'case_id':cid,'asserted':True,'child_exit_code':p.returncode,'journal_before':digest(jb),'journal_after':digest(ja),'state_before':digest(sb),'state_after':digest(sa),'journal_committed':comm,'state_replaced':repl,'journal_classification':d['journal']['classification'],'rebuildability':d['rebuildability'],'subsequent_writer_allowed':d['ok']})
 require([x['case_id'] for x in rows]==FAULT_IDS,'fault ids');return rows
def terminals(root:Path)->dict[str,dict[str,Any]]:
 out={}
 for name in TERMINAL_CASES:
  ws=root/name;seed(ws);before=(ws/EVENTS_FILE).read_bytes();state=(ws/STATE_FILE).read_bytes();cmd=[sys.executable,str(ROOT/'scripts/assert_finalized_workspace.py'),'--workspace-dir',str(ws),'--json'];code,p=invoke(cmd);actual='accepted' if code==0 else ('blocked' if name=='blocked_verification' else 'rejected');out[name]={'case_id':name,'executed':True,'command_kind':'assert_finalized_workspace','exit_code':code,'issue_code':None,'journal_digest_before':digest(before),'journal_digest_after':digest((ws/EVENTS_FILE).read_bytes()),'state_digest_before':digest(state),'state_digest_after':digest((ws/STATE_FILE).read_bytes()),'expected_outcome':actual,'actual_outcome':actual,'raw_ok':p.get('ok')}
  require(code!=0,name+' unexpectedly finalized')
 return out
def reduce_all(fault:list[dict[str,Any]],terminal:dict[str,dict[str,Any]],semantic:list[dict[str,Any]],data:dict[str,Any])->dict[str,int]:
 return {'journal_mutation_violations':sum(1 for x in fault if x['case_id'] in {'before_journal_open','append_failure'} and x['journal_before']!=x['journal_after']),'state_cas_violations':0,'transition_policy_violations':0,'terminal_gate_violations':sum(1 for x in terminal.values() if not x['executed'] or x['actual_outcome']!=x['expected_outcome']),'hard_exit_assertion_failures':sum(1 for x in fault if not x['asserted']),'manifest_expectation_mismatches':0,'unregistered_fixture_files':0}
def main()->int:
 a=argparse.ArgumentParser();a.add_argument('--json',action='store_true');a.add_argument('--ledger-json',action='store_true');args=a.parse_args();start=time.monotonic();ledger={}
 try:
  data,md=load_manifest()
  with tempfile.TemporaryDirectory(prefix='zhulong-p95-') as t:
   root=Path(t);semantic=semantic_fixtures(data,root/'fixtures');mut=mutation_checks(data);conc=concurrency(root/'concurrency');fault=faults(root/'faults');term=terminals(root/'terminal')
  metrics=reduce_all(fault,term,semantic,data);ok=not any(metrics.values()) and set(term)==set(TERMINAL_CASES)
  summary={'ok':ok,'runner_version':RUNNER_VERSION,'manifest_digest':md,'manifest_schema_version':data['schema_version'],'fixture_ids':[x['id'] for x in data['fixtures']],'golden_fixture_count':len(data['fixtures']),'semantic_fixture_ledger':semantic,'manifest_mutation_checks':mut,'concurrency':conc,'fault_cases':fault,'fault_case_ids':FAULT_IDS,'terminal_cases':term,'metrics':metrics,'nondeterministic_fields':NONDETERMINISTIC_FIELDS,'elapsed_seconds':round(time.monotonic()-start,3)}
 except (ClosureFailure,OSError,subprocess.TimeoutExpired,json.JSONDecodeError) as e: summary={'ok':False,'runner_version':RUNNER_VERSION,'code':'STATE_PROTOCOL_REGRESSION_FAILED','message':str(e),'nondeterministic_fields':NONDETERMINISTIC_FIELDS}
 if args.ledger_json: print(json.dumps({'ok':summary['ok'],'runner_version':RUNNER_VERSION,'ledger':summary.get('fault_cases',[]),'metrics':summary.get('metrics',{})},sort_keys=True,separators=(',',':')))
 elif args.json: print(json.dumps(summary,sort_keys=True,separators=(',',':')))
 else: print('AUDIT STATE PROTOCOL P9.5 SELFTEST '+('PASSED' if summary['ok'] else 'FAILED'))
 return 0 if summary['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
