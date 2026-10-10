"""Export the running SDK tool contract without any installation data."""
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ha_diagnostics.mcp_server import tool_definitions
from ha_diagnostics.policy import LocalPolicy
from ha_diagnostics.broker import REQUEST_ADAPTER

def main():
    output=ROOT/'schemas';output.mkdir(exist_ok=True)
    for tool in tool_definitions():
        (output/(tool.name+'.input.schema.json')).write_text(json.dumps(tool.input_schema,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        (output/(tool.name+'.output.schema.json')).write_text(json.dumps(tool.output_schema,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    (output/'local-policy.schema.json').write_text(json.dumps(LocalPolicy.model_json_schema(),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    (output/'broker-request.schema.json').write_text(json.dumps(REQUEST_ADAPTER.json_schema(),indent=2)+'\n',encoding='utf-8')
    (output/'tools.json').write_text(json.dumps({'schema_version':'1','product_version':'1.0.0-alpha.8','tools':[t.model_dump(by_alias=True,mode='json',exclude_none=True) for t in tool_definitions()]},indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('Exported 10 tool input/output schemas, broker and local policy schemas.')
if __name__=='__main__':main()
