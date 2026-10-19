import io,json,os,html,zipfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel
from .core import analyze,repair,verify_changes,replay_scenarios,WorkflowError

ROOT=Path(__file__).resolve().parents[1]
app=FastAPI(title='FlowRescue AI',description='Conservative n8n workflow static analyzer and reviewable repair export',version='0.1.0')
class WorkflowBody(BaseModel): workflow:dict

def safe_run(fn,*args):
    try:return fn(*args)
    except WorkflowError as e:raise HTTPException(422,str(e)) from e

@app.get('/health')
def health():return {'status':'ok','mode':'local static analysis','live_n8n_execution':False}
@app.post('/api/analyze')
def do_analyze(body:WorkflowBody):return safe_run(analyze,body.workflow)
@app.post('/api/scenarios')
def scenarios(body:WorkflowBody):return safe_run(replay_scenarios,body.workflow)
@app.post('/api/repair')
def do_repair(body:WorkflowBody):
    patched,changes=safe_run(repair,body.workflow)
    return {'workflow':patched,'changes':changes,'verification':verify_changes(body.workflow,patched)}
@app.post('/api/report')
def report(body:WorkflowBody):
    data=safe_run(analyze,body.workflow);patched,changes=safe_run(repair,body.workflow)
    final={'analysis':data,'scenarios':replay_scenarios(body.workflow),'proposed_changes':changes,'post_repair':verify_changes(body.workflow,patched),'disclaimer':'Static analysis only; no workflow execution or production changes'}
    return JSONResponse(final,headers={'Content-Disposition':'attachment; filename="flowrescue-report.json"'})
@app.get('/api/demo')
def demo():return json.loads((ROOT/'examples/broken-workflow.json').read_text())
@app.get('/',response_class=HTMLResponse)
def index():return (ROOT/'flowrescue/index.html').read_text()
