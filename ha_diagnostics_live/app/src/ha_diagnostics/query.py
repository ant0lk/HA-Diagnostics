"""Queries use the cleaned archive only. No broker, HA API, or write commands."""
import asyncio
import hashlib
import json
import time
import math
from collections import deque
from uuid import uuid4
from pydantic import ValidationError
from . import __version__
from .auth import authorize, AccessDenied
from .schemas import TOOLS, SCOPES, Envelope
from .timeutil import utc_now
from .limits import RateLimited,rate_admitted_context

SAFE_ERRORS={"INVALID_TIME_RANGE","AMBIGUOUS_DEVICE","SOURCE_UNAVAILABLE","DATA_GAP","RECORD_NOT_FOUND","CURSOR_EXPIRED","POLICY_CHANGED","QUERY_TOO_LARGE","TIMEOUT","ACCESS_DENIED","UNSUPPORTED_CAPABILITY"}

class QueryService:
    def __init__(self, archive, policies, cursors, audit=None):
        self.archive,self.policies,self.cursors,self.audit=archive,policies,cursors,audit
        self.semaphore=asyncio.Semaphore(2)
        self.calls=deque()

    def check_rate(self):
        now=time.monotonic()
        while self.calls and self.calls[0]<=now-60:self.calls.popleft()
        if len(self.calls)>=30:raise RateLimited(math.ceil(60-(now-self.calls[0])))
        self.calls.append(now)

    @staticmethod
    def trim_messages(value,message_bytes=8192):
        if isinstance(value,list):return [QueryService.trim_messages(x,message_bytes) for x in value]
        if isinstance(value,dict):
            result={k:QueryService.trim_messages(v,message_bytes) for k,v in value.items()}
            if isinstance(result.get("sanitized_message"),str):
                raw=result["sanitized_message"].encode("utf-8")
                if len(raw)>message_bytes:
                    result["sanitized_message"]=raw[:message_bytes].decode("utf-8",errors="ignore")
                    result["truncated"]=True
            return result
        return value

    def bounded_page(self,fetch,limit):
        deadline=time.monotonic()+5
        while True:
            if time.monotonic()>deadline:raise ValueError("TIMEOUT")
            result=self.trim_messages(fetch(limit))
            if len(json.dumps(result,ensure_ascii=False).encode())<=48*1024 or limit==1:return result
            limit=max(1,limit//2)

    def catalog(self, policy):
        if "entities" not in policy.allowed_sources():
            return []
        entries=[]
        for row in self.archive.get_device_metadata():
            fields=row if row.get("device_ref") else row.get("safe_fields",row.get("data",row))
            if isinstance(fields,list): candidates=fields
            elif isinstance(fields,dict): candidates=fields.get("devices",[fields])
            else: continue
            for item in candidates:
                if not isinstance(item,dict) or not item.get("device_ref"): continue
                refs=[r for r in item.get("entity_refs",[]) if r in policy.entity_refs]
                if not refs: continue
                entries.append({k:v for k,v in item.items() if k in {"device_ref","entity_refs","integration_ref","mapping_origin","mapping_confidence","observed_at","related_source_ids","name","snapshot_id"}} | {"entity_refs":refs,"related_source_ids":[s for s in item.get("related_source_ids",[]) if s in policy.allowed_sources()]})
        return entries

    def device_context(self, device):
        snapshots=self.archive.get_entity_snapshots(device["entity_refs"])
        states=[]
        for row in snapshots:
            fields=row.get("safe_fields",row)
            states.append({k:v for k,v in fields.items() if k in {"state","last_changed","last_updated"}} | {"attributes":fields.get("safe_attributes",fields.get("attributes",{})),"entity_ref":row["entity_ref"],"observed_at":row["observed_at"],"snapshot_id":row["snapshot_id"]})
        return device | {"states":states,"state_origin":"observed_snapshot","snapshot_is_historical_evidence":False}

    def emit_audit(self,name,principal,policy,started,error_code,byte_count=0):
        if self.audit:
            self.audit({"at":utc_now(),"subject":hashlib.sha256((principal.sub if principal else "anonymous").encode()).hexdigest()[:16],"tool":name if name in TOOLS else "unsupported","policy":policy.version,"decision":"deny" if error_code else "allow","bytes":byte_count,"latency_ms":int((time.monotonic()-started)*1000),"error_code":error_code})

    async def call(self,name,arguments,principal):
        started=time.monotonic(); p=self.policies.read(); request_id=str(uuid4())
        try:
            if name not in TOOLS: raise ValueError("UNSUPPORTED_CAPABILITY")
            authorize(principal,p,SCOPES[name])
            if not rate_admitted_context.get():self.check_rate()
            if self.semaphore.locked():raise RateLimited()
            params=TOOLS[name].model_validate(arguments)
        except ValidationError:
            self.emit_audit(name,principal,p,started,"INVALID_PARAMS")
            raise ValueError("INVALID_PARAMS") from None
        except (ValueError,AccessDenied) as e:
            self.emit_audit(name,principal,p,started,"UNSUPPORTED_CAPABILITY" if name not in TOOLS else "ACCESS_DENIED")
            raise
        except RateLimited:
            self.emit_audit(name,principal,p,started,"RATE_LIMITED")
            raise
        args=params.model_dump(by_alias=True,exclude={"cursor"},exclude_none=True)
        coverage=[]; warnings=[]; next_cursor=None; truncated=False; error=None
        try:
            async with self.semaphore:
                generation=self.archive.generation
                after=None
                if getattr(params,"cursor",None):
                    after=self.cursors.decode(params.cursor,sub=principal.sub,policy=p,tool=name,arguments=args,generation=generation)
                allowed=p.allowed_sources()
                if hasattr(params,"source_ids") and not set(params.source_ids)<=allowed: raise AccessDenied()
                if hasattr(params,"entity_refs") and not set(params.entity_refs)<=set(p.entity_refs): raise AccessDenied()
                if name=="get_entity_history" and "entities" not in allowed: raise AccessDenied()
                if name=="get_diagnostics_status":
                    sources=[{k:v for k,v in s.items() if k!="local_ref"} for s in self.archive.source_status() if s["source_id"] in allowed]
                    installation=(self.archive.get_installation_metadata() or {}) if "metadata" in allowed else {}
                    ha_timezone=installation.get("timezone",p.timezone)
                    versions={k:v.get("version") for k,v in installation.get("safe_fields",{}).items() if k in {"core","supervisor","os"} and isinstance(v,dict)} if "metadata" in allowed else {}
                    data={"version":__version__,"ha_versions":versions,"mode":p.mode,"server_time_utc":utc_now(),"ha_timezone":ha_timezone,"timezone_origin":installation.get("timezone_origin","local_configuration_unverified"),"metadata_observed_at":installation.get("observed_at"),"sources":sources,"capabilities":list(TOOLS),"transport":"request_received","limitations":["Only locally selected cleaned data is available.","Coverage does not prove HA recorded every physical event.","Names remain pseudonymized in this alpha.","Live OS isolation and ChatGPT acceptance require the target environment."]}
                elif name=="find_devices":
                    found=[x for x in self.catalog(p) if params.query.casefold() in json.dumps(x,ensure_ascii=False).casefold()]
                    offset=int(after or 0); data={"devices":found[offset:offset+params.limit],"ambiguous":len(found)>1}
                    if len(found)>offset+params.limit: next_cursor=offset+params.limit
                elif name in {"get_device_context","get_incident_context"}:
                    found=[x for x in self.catalog(p) if x["device_ref"]==params.device_ref]
                    if len(found)!=1: raise AccessDenied()
                    device=found[0]
                    if name=="get_device_context": data=self.device_context(device)
                    else:
                        authorize(principal,p,"history:read")
                        related=device["related_source_ids"]
                        incident=self.bounded_page(lambda n:self.archive.query_incident(device["entity_refs"],related,params.from_,params.to,limit=n,after=after),params.limit)
                        data={"device":self.device_context(device),"timeline":incident["timeline"],"boundary_states":incident.get("boundary_states",[]),"root_cause":"not_established"}
                        coverage=incident["coverage"];next_cursor=incident.get("next_after")
                elif name=="query_logs":
                    result=self.bounded_page(lambda n:self.archive.query_logs(params.source_ids,params.from_,params.to,levels=params.levels,query=params.query,limit=n,after=after),params.limit)
                    data={"records":result["records"]}; coverage=result["coverage"]; next_cursor=result.get("next_after")
                elif name=="get_log_record":
                    result=self.archive.get_log_record(params.record_id,before=params.before,after=params.after,allowed_source_ids=list(allowed))
                    if not result: raise AccessDenied()
                    data=self.trim_messages(result,48*1024)
                    while len(json.dumps(data,ensure_ascii=False).encode())>48*1024 and (data["before"] or data["after"]):
                        if len(data["before"])>=len(data["after"]):data["before"].pop(0)
                        else:data["after"].pop()
                        truncated=True
                    if truncated:warnings.append("Neighboring evidence was limited by the UTF-8 response budget.")
                elif name=="get_entity_history":
                    result=self.bounded_page(lambda n:self.archive.query_history(params.entity_refs,params.from_,params.to,limit=n,after=after),params.limit)
                    data={"records":result["records"],"boundary_states":result.get("boundary_states",[])};coverage=result["coverage"];next_cursor=result.get("next_after")
                elif name=="summarize_errors":
                    result=self.bounded_page(lambda n:self.archive.summarize_errors(params.source_ids,params.from_,params.to,limit=n,after=after),params.limit)
                    data={k:v for k,v in result.items() if k not in {"coverage","next_after","generation"}};coverage=result["coverage"];next_cursor=result.get("next_after")
                elif name=="list_artifacts":
                    result=self.bounded_page(lambda n:self.archive.list_artifacts(kind=params.kind,limit=n,after=after,approved_only=True),params.limit)
                    data={"artifacts":result.get("artifacts",[])};next_cursor=result.get("next_after")
                elif name=="read_artifact":
                    data=self.archive.read_artifact(params.artifact_id,offset=params.offset,max_chars=params.max_chars,approved_only=True)
                    if data is None: raise AccessDenied()
                    if len(data["content"].encode())>48*1024:
                        data["content"]=data["content"].encode()[:48*1024].decode("utf-8",errors="ignore")
                        data["end_offset"]=data["offset"]+len(data["content"])
                        data["next_offset"]=data["end_offset"];data["truncated"]=True
                if next_cursor is not None:
                    next_cursor=self.cursors.encode(next_cursor,sub=principal.sub,policy=p,tool=name,arguments=args,generation=generation);truncated=True
                # A local revoke/policy change cancels already computed results before disclosure.
                current=self.policies.read();authorize(principal,current,SCOPES[name])
                if current.version!=p.version: raise ValueError("POLICY_CHANGED")
                if self.archive.generation!=generation: raise ValueError("CURSOR_EXPIRED")
        except (ValueError,AccessDenied) as e:
            code=str(e); error=code if code in SAFE_ERRORS else "ACCESS_DENIED";data={};coverage=[];next_cursor=None
        result=Envelope(request_id=request_id,generated_at=utc_now(),data_as_of=utc_now(),access_policy_version=p.version,data=data,coverage=coverage,warnings=warnings,truncated=truncated,next_cursor=next_cursor,error_code=error).model_dump()
        if len(json.dumps(result,ensure_ascii=False).encode())>64*1024:
            result.update(data={},coverage=[],next_cursor=None,truncated=True,error_code="QUERY_TOO_LARGE")
        self.emit_audit(name,principal,p,started,result["error_code"],len(json.dumps(result).encode()))
        return result
