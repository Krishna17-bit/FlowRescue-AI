"""Conservative static n8n workflow analysis and safe, reviewable repairs.
No arbitrary JS, Python, expressions, or external workflow nodes are executed.
"""
from __future__ import annotations
import copy, json, re, hashlib
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Finding:
    code: str
    severity: str
    node: str
    message: str
    recommendation: str

TRIGGERS={'n8n-nodes-base.manualTrigger','n8n-nodes-base.webhook','n8n-nodes-base.scheduleTrigger','n8n-nodes-base.formTrigger','n8n-nodes-base.emailReadImap','n8n-nodes-base.errorTrigger'}
HTTP='n8n-nodes-base.httpRequest'
SENSITIVE=re.compile(r'(api[_-]?key|access[_-]?token|secret|password|authorization)',re.I)

class WorkflowError(ValueError): pass

def validate(workflow: Any) -> dict:
    if not isinstance(workflow,dict): raise WorkflowError('Workflow must be a JSON object')
    if not isinstance(workflow.get('nodes'),list) or not isinstance(workflow.get('connections'),dict):
        raise WorkflowError('Workflow must have nodes[] and connections{}')
    if len(workflow['nodes'])>300: raise WorkflowError('Max 300 nodes per analysis')
    names=[]
    for n in workflow['nodes']:
        if not isinstance(n,dict) or not isinstance(n.get('name'),str) or not isinstance(n.get('type'),str):
            raise WorkflowError('Each node needs a name and type')
        names.append(n['name'])
    if len(set(names))!=len(names): raise WorkflowError('Duplicate node names are not supported')
    return workflow

def edges(w:dict):
    for src,blocks in w['connections'].items():
        if not isinstance(blocks,dict):continue
        for kind,lists in blocks.items():
            if not isinstance(lists,list):continue
            for branch in lists:
                if not isinstance(branch,list):continue
                for conn in branch:
                    if isinstance(conn,dict) and isinstance(conn.get('node'),str):yield src,conn['node'],kind

def analyze(workflow:dict) -> dict:
    w=validate(workflow);nodes=w['nodes']; by={n['name']:n for n in nodes}; links=list(edges(w)); findings=[]
    def add(code,severity,node,message,recommendation):findings.append(asdict(Finding(code,severity,node,message,recommendation)))
    for a,b,_ in links:
        if a not in by:add('MISSING_SOURCE','critical',a,f'Connection references missing source node {a}', 'Remove invalid connection or restore node')
        if b not in by:add('MISSING_TARGET','critical',a,f'Connection points to nonexistent node {b}', 'Reconnect to a valid node')
    incoming={x:0 for x in by}; outgoing={x:0 for x in by}
    for a,b,_ in links:
        if a in outgoing:outgoing[a]+=1
        if b in incoming:incoming[b]+=1
    triggers=[n['name'] for n in nodes if n['type'] in TRIGGERS or n['type'].endswith('Trigger')]
    if not triggers:add('NO_TRIGGER','high','Workflow','No recognized trigger found','Add appropriate manual, webhook, or schedule trigger')
    reachable=set(triggers);changed=True
    while changed:
        old=len(reachable)
        reachable.update(b for a,b,_ in links if a in reachable and b in by)
        changed=len(reachable)!=old
    for n in nodes:
        name=n['name']; typ=n['type'];p=n.get('parameters') or {}
        if name not in reachable and triggers:add('UNREACHABLE','high',name,'Node cannot be reached from any trigger','Review connections and connect intended branch')
        if typ not in TRIGGERS and not typ.endswith('Trigger') and incoming[name]==0:add('DISCONNECTED','high',name,'Node has no incoming connection','Connect it to intended predecessor')
        if typ==HTTP:
            url=p.get('url','')
            if not url or not isinstance(url,str):add('HTTP_URL_MISSING','critical',name,'HTTP Request has no target URL','Set URL to approved endpoint')
            if p.get('options',{}).get('timeout',None) is None:add('HTTP_TIMEOUT','medium',name,'HTTP Request has no explicitly configured timeout','Set a bounded timeout appropriate to the service')
            if not n.get('retryOnFail',False):add('HTTP_RETRY','medium',name,'HTTP Request has no retry-on-failure','Enable bounded retries only for idempotent operations')
            if str(p.get('method','GET')).upper() in {'POST','PUT','PATCH'} and n.get('retryOnFail'):
                add('RETRY_IDEMPOTENCY','high',name,'Mutating HTTP request uses retry without demonstrable idempotency','Use idempotency keys and downstream deduplication')
        serialized=json.dumps(p,ensure_ascii=False)
        if SENSITIVE.search(serialized) and re.search(r'(sk-[a-zA-Z0-9]{12,}|Bearer\s+[A-Za-z0-9_.-]{12,})',serialized):
            add('POSSIBLE_INLINE_SECRET','critical',name,'Parameters may contain literal credentials','Replace literal secrets with n8n credentials')
        if typ=='n8n-nodes-base.code' and re.search(r'\$\$?\.\w+|eval\(',str(p.get('jsCode',''))):
            add('CODE_REVIEW','medium',name,'Code node contains potentially sensitive dynamic operations','Review code manually; this tool does not execute JavaScript')
    # directed cycle detection; iterative depth first avoids Python recursion issues
    graph={k:[] for k in by}
    for a,b,_ in links:
        if a in by and b in by:graph[a].append(b)
    visiting=set();done=set();has_cycle=False
    def dfs(node):
        nonlocal has_cycle
        visiting.add(node)
        for nxt in graph[node]:
            if nxt in visiting:has_cycle=True
            elif nxt not in done:dfs(nxt)
        visiting.remove(node);done.add(node)
    for node in graph:
        if node not in done:dfs(node)
    if has_cycle:add('CYCLE_REVIEW','high','Workflow','Graph contains a cycle; repeated execution may be intentional','Verify loop exit conditions and execution limits')
    high=sum(f['severity'] in ('high','critical') for f in findings)
    return {'workflow':w.get('name','Unnamed workflow'),'nodes':len(nodes),'edges':len(links),'triggers':triggers,'reachable':len(reachable),'findings':findings,'summary':{'critical':sum(f['severity']=='critical' for f in findings),'high':sum(f['severity']=='high' for f in findings),'medium':sum(f['severity']=='medium' for f in findings),'low':sum(f['severity']=='low' for f in findings)},'risk_label':'needs attention' if high else 'review recommended' if findings else 'no listed issues detected','fingerprint':hashlib.sha256(json.dumps(w,sort_keys=True).encode()).hexdigest()[:16]}

SAFE_FIX={'HTTP_TIMEOUT'}
def repair(workflow:dict, fix_codes:list[str]|None=None):
    """Apply only low-risk, local fixes; never modify server workflows."""
    w=copy.deepcopy(validate(workflow)); allowed=set(fix_codes or SAFE_FIX); changes=[]
    for n in w['nodes']:
        if n['type']==HTTP and 'HTTP_TIMEOUT' in allowed:
            p=n.setdefault('parameters',{});opts=p.setdefault('options',{})
            if 'timeout' not in opts:
                opts['timeout']=10000
                changes.append({'node':n['name'],'code':'HTTP_TIMEOUT','path':'parameters.options.timeout','before':None,'after':10000,'reason':'Bounded 10-second timeout; review according to upstream SLA'})
    return w,changes

def verify_changes(original:dict,patched:dict):
    a=analyze(original); b=analyze(patched)
    return {'before':a['summary'],'after':b['summary'],'resolved_codes':sorted(set(f['code'] for f in a['findings'])-set(f['code'] for f in b['findings'])),'new_codes':sorted(set(f['code'] for f in b['findings'])-set(f['code'] for f in a['findings'])),'static_only':True}

def replay_scenarios(workflow:dict):
    """Explicit static fault scenarios, NOT actual executions of n8n."""
    a=analyze(workflow); codes={f['code'] for f in a['findings']}
    cases=[('Missing target node','MISSING_TARGET'),('Unreachable processing branch','UNREACHABLE'),('HTTP timeout absent','HTTP_TIMEOUT'),('HTTP retry absent','HTTP_RETRY'),('Mutation retry without idempotency','RETRY_IDEMPOTENCY'),('Inline token suspicion','POSSIBLE_INLINE_SECRET'),('Cyclic graph','CYCLE_REVIEW')]
    return [{'scenario':label,'finding_present':code in codes,'status':'flagged' if code in codes else 'not flagged','validation_type':'static rule (no API calls)'} for label,code in cases]
