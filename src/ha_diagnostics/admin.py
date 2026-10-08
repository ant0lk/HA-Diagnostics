"""Finite owner-local administration of this app's own data only."""
import base64
from pathlib import Path
from pydantic import Field
from .policy import Strict, LocalPolicy, SourcePolicy, SENSITIVE_DOMAINS
from .schemas import Empty
from .imports import ImportService
from .timeutil import utc_now
from . import __version__

class PreviewArgs(Strict):
    filename: str = Field(min_length=1,max_length=200)
    content_base64: str = Field(min_length=1,max_length=28*1024**2)
class CommitArgs(Strict):
    preview_id: str = Field(pattern=r"^preview_[a-f0-9]{32}$")
    share_with_chatgpt: bool = False
class PolicyArgs(Strict):
    policy: LocalPolicy
class ArtifactArgs(Strict):
    artifact_id: str = Field(pattern=r"^art_[a-f0-9]{32}$")
class ApprovalArgs(ArtifactArgs):
    approved: bool
class EvidenceArgs(Strict):
    record_id: str = Field(pattern=r"^rec_[a-f0-9]{32}$")

class AdminService:
    def __init__(self,archive,policies,broker,profile="import_only"):
        self.archive,self.policies,self.broker,self.profile=archive,policies,broker,profile
        self.imports=ImportService(archive,timezone=policies.read().timezone)
    async def status(self,args):
        p=self.policies.read()
        metadata=self.archive.get_installation_metadata() or {}
        from datetime import timedelta
        from .timeutil import parse_explicit,format_utc
        now=utc_now();sources=self.archive.source_status()
        coverage=self.archive.coverage([s['source_id'] for s in sources],format_utc(parse_explicit(now)-timedelta(days=1)),now)
        return {"version":__version__,"time":now,"policy":p.model_dump(),"ha_timezone":metadata.get("timezone",p.timezone),"timezone_origin":metadata.get("timezone_origin","local_configuration_unverified"),"ha_metadata":metadata,"sources":sources,"coverage":coverage,"local_log_preview":self.archive.local_log_preview(),"storage_bytes":self.archive.storage_bytes(),"disk_ok":self.archive.check_disk(),"artifacts":self.archive.list_artifacts(approved_only=False),"mode":p.mode,"isolation":"target_validation_required","transport":"not_verified"}
    async def discover(self,args):
        addons=await self.broker.execute({"op":"addon_catalog"})
        return {"sources":[{"source_id":"core"},{"source_id":"supervisor"},{"source_id":"entities"},{"source_id":"metadata"}]+[{"source_id":"addon:"+x["slug"],"name":x.get("name",x["slug"])} for x in addons]}
    async def entities(self,args):
        return await self.broker.execute({"op":"entity_catalog"})
    async def preview(self,args):
        raw=base64.b64decode(args.content_base64,validate=True)
        self.imports.timezone=self.policies.read().timezone
        return self.imports.preview(args.filename,raw).public_preview()
    async def commit(self,args):
        return {"artifact_id":self.imports.commit(args.preview_id,share_with_chatgpt=args.share_with_chatgpt)}
    async def configure(self,args):
        p=args.policy
        if p.mode!=self.profile: raise ValueError("INSTALL_PROFILE_REQUIRED")
        if p.entity_ids:
            p=p.model_copy(update={"entity_refs":[self.broker.ref("entity",e) for e in p.entity_ids]})
        else: p=p.model_copy(update={"entity_refs":[]})
        for source in p.sources:
            self.archive.register_source(source.source_id,kind="history" if source.source_id=="entities" else "metadata" if source.source_id=="metadata" else "log",enabled=source.collect)
        existing={s["source_id"] for s in self.archive.source_status()}
        for removed in existing-{s.source_id for s in p.sources}: self.archive.set_source_enabled(removed,False)
        from .storage_budget import archive_budget
        self.archive.max_bytes=archive_budget(p.max_bytes);self.archive.retention_days=p.retention_days
        self.archive.enforce_retention()
        return {"policy":self.policies.write(p).model_dump()}
    async def revoke(self,args):
        p=self.policies.read().model_copy(update={"remote_enabled":False})
        return {"revoked":True,"version":self.policies.write(p).version}
    async def pause(self,args):
        p=self.policies.read().model_copy(update={"collection_enabled":False})
        return {"stopped":True,"version":self.policies.write(p).version}
    async def clear(self,args):
        self.archive.clear()
        return {"deleted":True,"physical_erasure_guaranteed":False}
    async def artifact_read(self,args):
        return self.archive.read_artifact(args.artifact_id,approved_only=False) or {"error":"RECORD_NOT_FOUND"}
    async def artifact_approve(self,args):
        self.archive.approve_artifact(args.artifact_id,args.approved)
        return {"approved":args.approved}
    async def artifact_delete(self,args):
        self.archive.delete_artifact(args.artifact_id)
        return {"deleted":True}
    async def evidence(self,args):
        return self.archive.get_log_record(args.record_id) or {"error":"RECORD_NOT_FOUND"}
    def handlers(self):
        return {"admin_status":(Empty,self.status),"discover_sources":(Empty,self.discover),"discover_entities":(Empty,self.entities),"import_preview":(PreviewArgs,self.preview),"import_commit":(CommitArgs,self.commit),"set_policy":(PolicyArgs,self.configure),"revoke_access":(Empty,self.revoke),"pause_collection":(Empty,self.pause),"delete_archive":(Empty,self.clear),"read_local_artifact":(ArtifactArgs,self.artifact_read),"approve_artifact":(ApprovalArgs,self.artifact_approve),"delete_artifact":(ArtifactArgs,self.artifact_delete),"read_evidence":(EvidenceArgs,self.evidence)}
    async def request(self,op,args):
        if op not in self.handlers(): raise ValueError("ADMIN_OPERATION_DENIED")
        model,handler=self.handlers()[op]
        return await handler(model.model_validate(args))
