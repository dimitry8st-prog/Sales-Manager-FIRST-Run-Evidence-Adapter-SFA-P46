import unittest,json,hashlib,copy
from audit_release.command_evidence import build_run_evidence,RunEvidenceError
from audit_release.test_applicability import assess_applicability
from audit_release.unittest_evidence import RecordingResult
from qa_completion.offline.unittest_runner import run_suite

class EvidencePublic(unittest.TestCase):
 def inputs(self):
  b=[{'test_id':'tests.one','suite_id':'suite','case_id':'one'}]
  r={'schema_version':'FIRST_OFFLINE_UNITTEST_RUN_V1','records':[{'release_id':'r','suite_id':'suite','case_id':'one','attempt':1,'status':'PASS','exit_code':0,'skip_count':0}],'counts':{'tests_run':1,'failures':0,'errors':0,'skips':0},'stdout':'Привіт\r\n','stderr':''}
  c={'key':'Runs/Main','argv':['python','RUN.py'],'cwd':'C:/Путь','interpreter':'Python 3.12'}
  return r,dict(release_id='r',bindings=b,command=c,test_artifacts=[{'key':'Tests/Unit.py','content':b'print(1)\n'}])
 def call(self):
  r,k=self.inputs();return build_run_evidence(r,**k)
 def test_exact_output_and_hashes(self):
  r,k=self.inputs();o=build_run_evidence(r,**k)
  self.assertEqual(set(o),{'schema_version','records','report_sha256','identity_snapshot','raw_outputs','external_effect_authorized','gate_acceptance'})
  self.assertEqual(o['schema_version'],'FIRST_RUN_EVIDENCE_ENVELOPE_V1');self.assertEqual(o['records'],r['records'])
  enc=lambda x:json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
  self.assertEqual(o['report_sha256'],hashlib.sha256(enc(r)).hexdigest())
  self.assertEqual(o['identity_snapshot']['artifacts'][0],{'kind':'COMMAND','key':'runs/main','sha256':hashlib.sha256(enc({k:v for k,v in k['command'].items() if k!='key'})).hexdigest()})
  self.assertEqual(o['raw_outputs']['stdout'],{'content':'Привіт\r\n'.encode(),'size_bytes':14,'sha256':hashlib.sha256('Привіт\r\n'.encode()).hexdigest()})
  self.assertIs(o['external_effect_authorized'],False);self.assertIs(o['gate_acceptance'],False)
 def test_real_p47_consumer_missing_dimensions_unknown(self):
  o=self.call();pins=[{'kind':x['kind'],'key':x['key']} for x in o['identity_snapshot']['artifacts']]
  c=[{'case_id':'case','before_required':pins,'after_required':pins,'footprint_complete':True}]
  a=assess_applicability(o['identity_snapshot'],o['identity_snapshot'],c)
  self.assertEqual(a['cases'][0]['status'],'UNKNOWN');self.assertIn('SOURCE',a['cases'][0]['missing_dimensions'])
 def test_real_p47_full_dimensions_and_change(self):
  r,k=self.inputs();a=build_run_evidence(r,**k)['identity_snapshot'];k['command']['argv'][-1]='OTHER.py';b=build_run_evidence(r,**k)['identity_snapshot']
  for kind in ['SOURCE','SCHEMA','CONFIG','DEPENDENCY','RUNTIME']:
   x={'kind':kind,'key':'pin','sha256':'a'*64};a['artifacts'].append(copy.deepcopy(x));b['artifacts'].append(copy.deepcopy(x))
  pins=[{'kind':x['kind'],'key':x['key']} for x in a['artifacts']];c=[{'case_id':'case','before_required':pins,'after_required':pins,'footprint_complete':True}]
  self.assertEqual(assess_applicability(a,a,c)['cases'][0]['status'],'MATCH')
  z=assess_applicability(a,b,c)['cases'][0];self.assertEqual(z['status'],'CHANGED_AFFECTED');self.assertEqual(z['changed'][0]['kind'],'COMMAND')
 def test_actual_runner_report(self):
  class T(unittest.TestCase):
   def id(self):return 'tests.one'
   def runTest(self):print('actual')
  _,k=self.inputs();r=run_suite(unittest.TestSuite([T()]),release_id='r',bindings=k['bindings'],result_factory=RecordingResult)
  self.assertEqual(build_run_evidence(r,**k)['raw_outputs']['stdout']['content'],b'actual\n')
 def test_four_statuses(self):
  for s,e,n in [('PASS',0,0),('FAIL',1,0),('ERROR',1,0),('SKIP',0,1)]:
   r,k=self.inputs();r['records'][0].update(status=s,exit_code=e,skip_count=n);r['counts'].update(failures=int(s=='FAIL'),errors=int(s=='ERROR'),skips=int(s=='SKIP'))
   self.assertEqual(build_run_evidence(r,**k)['records'][0]['status'],s)
 def test_count_mismatch(self):
  r,k=self.inputs();r['counts']['tests_run']=2
  with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
 def test_bool_exit_and_attempt(self):
  for which in ['exit_code','attempt']:
   r,k=self.inputs();r['records'][0][which]=True
   with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
 def test_unknown_or_duplicate_case(self):
  for duplicate in [False,True]:
   r,k=self.inputs()
   if duplicate:r['records'].append(copy.deepcopy(r['records'][0]));r['counts']['tests_run']=2
   else:r['records'][0]['case_id']='other'
   with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
 def test_invalid_path_and_case_collision(self):
  for key in ['../x','a/CON.txt','a.','a//b','тест','a\\b']:
   r,k=self.inputs();k['command']['key']=key
   with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
  r,k=self.inputs();k['test_artifacts'].append({'key':'TESTS/unit.PY','content':b'x'})
  with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
 def test_unicode_surrogates_rejected(self):
  r,k=self.inputs();r['stdout']='\ud800'
  with self.assertRaises(RunEvidenceError):build_run_evidence(r,**k)
 def test_empty_and_unvisited(self):
  r,k=self.inputs();r['records']=[];r['counts']['tests_run']=0
  o=build_run_evidence(r,**k);self.assertEqual(o['records'],[]);self.assertNotIn('PASS',o)
 def test_detached_outputs_and_input_preserved(self):
  r,k=self.inputs();before=copy.deepcopy((r,k));o=build_run_evidence(r,**k);o['records'][0]['status']='X';o['identity_snapshot']['artifacts'].clear()
  self.assertEqual((r,k),before);self.assertEqual(build_run_evidence(r,**k)['records'][0]['status'],'PASS')
 def test_exact_fields(self):
  r,k=self.inputs();r['PASS']=True
  with self.assertRaises(RunEvidenceError) as c:build_run_evidence(r,**k)
  self.assertEqual(str(c.exception),'INVALID_INPUT')

if __name__=='__main__':unittest.main()
