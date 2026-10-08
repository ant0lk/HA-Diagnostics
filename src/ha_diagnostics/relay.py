"""Outgoing-only HTTPS relay for one owner's installation. Never uploads a stream."""
import asyncio
import json
import random
import time
from urllib.parse import urlsplit
import httpx

ROUTING_HEADERS=frozenset({'mcp-protocol-version','mcp-method','mcp-name'})
RESPONSE_HEADERS=frozenset({'www-authenticate','retry-after','mcp-protocol-version'})

def validate_header_map(values,allowed,*,maximum=4096):
    """A finite carrier, never a general HTTP header forwarding facility."""
    if not isinstance(values,dict) or not set(values)<=allowed:
        raise ValueError('CHANNEL_INVALID_HEADERS')
    for name,value in values.items():
        if not isinstance(value,str) or not value or len(value)>maximum or any(ord(c)<32 or ord(c)>126 for c in value):
            raise ValueError('CHANNEL_INVALID_HEADERS')
    return values

def validate_gateway(url):
    value=urlsplit(url)
    if value.scheme!="https" or not value.hostname or value.username or value.password or value.query or value.fragment or value.path not in {"","/"}:
        raise ValueError("INVALID_GATEWAY_ORIGIN")
    return url.rstrip("/")

class RelayClient:
    def __init__(self,origin,device_key,*,client=None,local=None):
        self.origin=validate_gateway(origin)
        self.device_key=device_key
        self.client=client or httpx.AsyncClient(timeout=35,follow_redirects=False,trust_env=False)
        self.local=local or httpx.AsyncClient(timeout=25,follow_redirects=False,trust_env=False)
        self.seen={};self.stop=asyncio.Event()
    async def step(self):
        async with self.client.stream("GET",self.origin+"/channel/poll",headers={"Authorization":"Bearer "+self.device_key}) as response:
            if response.status_code==204:return
            if response.status_code!=200:raise ValueError("CHANNEL_UNAVAILABLE")
            raw=b""
            async for chunk in response.aiter_bytes():
                raw+=chunk
                if len(raw)>49152:raise ValueError("CHANNEL_REQUEST_TOO_LARGE")
        request=json.loads(raw)
        if not isinstance(request,dict) or set(request)!={"request_id","nonce","expires_at","body","authorization","routing_headers"}:raise ValueError("CHANNEL_INVALID_REQUEST")
        routing=validate_header_map(request['routing_headers'],ROUTING_HEADERS,maximum=256)
        if 'mcp-protocol-version' not in routing:raise ValueError('CHANNEL_INVALID_HEADERS')
        now=time.time();self.seen={k:v for k,v in self.seen.items() if v>now}
        rid=request['request_id'];nonce=request['nonce']
        if not isinstance(rid,str) or not isinstance(nonce,str) or len(rid)>64 or len(nonce)>100 or rid in self.seen or not now<request['expires_at']<=now+30: return
        self.seen[rid]=request['expires_at']+60
        if len(self.seen)>128:raise ValueError("CHANNEL_BACKPRESSURE")
        # Only the fixed diagnostic MCP listener is reachable. No cloud-supplied URL/path.
        # Preserve original routing values. Reconstructing them from the body
        # would hide mismatches that the pinned modern SDK must reject.
        headers={"Accept":"application/json, text/event-stream","Content-Type":"application/json",**routing}
        if request['authorization']:headers['Authorization']=request['authorization']
        async with self.local.stream("POST","http://127.0.0.1:8000/mcp",content=json.dumps(request['body']),headers=headers) as response:
            body=b""
            async for chunk in response.aiter_bytes():
                body+=chunk
                if len(body)>300*1024:raise ValueError("CHANNEL_RESPONSE_TOO_LARGE")
            response_headers=validate_header_map({name:response.headers[name] for name in RESPONSE_HEADERS if name in response.headers},RESPONSE_HEADERS)
            result={"request_id":rid,"nonce":nonce,"status":response.status_code,"body":json.loads(body) if body else None,"content_type":"application/json","response_headers":response_headers}
        if time.time()>=request['expires_at']:return
        sent=await self.client.post(self.origin+"/channel/result",json=result,headers={"Authorization":"Bearer "+self.device_key})
        if sent.status_code!=200:raise ValueError("CHANNEL_RESULT_REJECTED")
    async def run(self):
        delay=1
        try:
            while not self.stop.is_set():
                try:await self.step();delay=1
                except Exception:
                    await asyncio.sleep(min(delay,30)+random.random());delay=min(delay*2,30)
        finally:await self.client.aclose();await self.local.aclose()
