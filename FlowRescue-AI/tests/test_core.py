import json,copy
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from flowrescue.core import analyze,repair,verify_changes,replay_scenarios,WorkflowError
from flowrescue.web import app
ROOT=Path(__file__).resolve().parents[1]
@pytest.fixture
def broken():return json.loads((ROOT/'examples/broken-workflow.json').read_text())
@pytest.fixture
def client():return TestClient(app)
def test_broken_findings(broken):
    f=analyze(broken)['findings'];c={v['code'] for v in f}
    assert {'UNREACHABLE','DISCONNECTED','HTTP_TIMEOUT','RETRY_IDEMPOTENCY'}<=c

def test_safe_repair(broken):
    old=copy.deepcopy(broken);fixed,changes=repair(broken)
    assert broken==old and len(changes)==1
    assert fixed['nodes'][2]['parameters']['options']['timeout']==10000
    assert 'HTTP_TIMEOUT' in verify_changes(broken,fixed)['resolved_codes']
    assert 'RETRY_IDEMPOTENCY' in {f['code'] for f in analyze(fixed)['findings']}

def test_clean():
    w=json.loads((ROOT/'examples/healthy-workflow.json').read_text())
    assert analyze(w)['findings']==[]
    assert repair(w)[1]==[]

def test_dangling():
    w={'nodes':[{'name':'Start','type':'n8n-nodes-base.manualTrigger'}], 'connections':{'Start':{'main':[[{'node':'Missing','type':'main','index':0}]]}}}
    assert 'MISSING_TARGET' in {f['code'] for f in analyze(w)['findings']}

def test_secrets():
    w={'nodes':[{'name':'Start','type':'n8n-nodes-base.manualTrigger','parameters':{'apiKey':'sk-123456789012345678'}}], 'connections':{}}
    assert 'POSSIBLE_INLINE_SECRET' in {f['code'] for f in analyze(w)['findings']}

def test_invalid():
    with pytest.raises(WorkflowError):analyze({'nodes':{},'connections':[]})

def test_api(client,broken):
    assert client.get('/health').json()['live_n8n_execution'] is False
    assert client.get('/').status_code==200
    assert client.post('/api/analyze',json={'workflow':broken}).status_code==200
    result=client.post('/api/repair',json={'workflow':broken}).json()
    assert len(result['changes'])==1
    assert client.post('/api/report',json={'workflow':broken}).status_code==200
    assert len(client.post('/api/scenarios',json={'workflow':broken}).json())==7

def test_api_rejects_invalid(client):
    assert client.post('/api/analyze',json={'workflow':{'nodes':[]}}).status_code==422

def test_scenarios_static(broken):
    assert all(x['validation_type'].startswith('static') for x in replay_scenarios(broken))
