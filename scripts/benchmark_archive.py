"""Reproducible small-fixture benchmark; does not certify HA resource SLOs.

An explicitly selected empty directory holds only generated synthetic data.
Tracemalloc measures Python heap, not aggregate RSS or bundled Tunnel memory.
"""
import argparse
from datetime import datetime,timedelta,timezone
import json
import hashlib
from pathlib import Path
import platform
import statistics
import sys
import time
import tracemalloc

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ha_diagnostics.archive import Archive,SCHEMA_VERSION
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.timeutil import parse_explicit

def run(output:Path,records:int,anchor:str|None=None):
    if output.exists():raise ValueError('REFUSE_EXISTING_BENCHMARK_DIRECTORY')
    if not 100<=records<=1_000_000:raise ValueError('RECORD_LIMIT')
    output.mkdir(parents=True)
    now=parse_explicit(anchor) if anchor else datetime.now(timezone.utc).replace(microsecond=0)
    start=now-timedelta(hours=3)
    stamp=lambda d:d.isoformat().replace('+00:00','Z')
    archive=Archive(output/'synthetic.sqlite',Redactor(b'benchmark-fixture-key-only-0000000'),min_free_bytes=0)
    sources=[f'src_fixture_{i}' for i in range(4)]
    for source in sources:archive.register_source(source)
    tracemalloc.start();cpu_start=time.process_time();ingest_start=time.perf_counter()
    input_bytes=0;saved=0;input_digest=hashlib.sha256()
    for offset in range(0,records,500):
        batches={s:[] for s in sources}
        for index in range(offset,min(offset+500,records)):
            at=start+timedelta(seconds=index*10000/max(records,1))
            level='ERROR' if index%20==0 else 'WARNING' if index%7==0 else 'INFO'
            batches[sources[index%4]].append(f'{stamp(at)} {level} [fixture.component_{index%11}] synthetic event {index}; value={index%17}')
        for source,lines in batches.items():
            if not lines:continue
            content='\n'.join(lines);input_bytes+=len(content.encode())
            input_digest.update(source.encode()+b'\0'+content.encode()+b'\0')
            saved+=archive.ingest_logs(source,'synthetic_boot',content,stamp(now))['inserted']
    ingest_seconds=time.perf_counter()-ingest_start;cpu_seconds=time.process_time()-cpu_start
    queries=[]
    for _ in range(100):
        began=time.perf_counter();result=archive.query_logs(sources,stamp(start),stamp(now),limit=200)
        assert len(result['records'])<=200
        queries.append((time.perf_counter()-began)*1000)
    began=time.perf_counter();summary=archive.summarize_errors(sources,stamp(start),stamp(now));summary_ms=(time.perf_counter()-began)*1000
    heap_peak=tracemalloc.get_traced_memory()[1];tracemalloc.stop()
    report={'product_version':'1.0.0-alpha.2','schema_version':SCHEMA_VERSION,'python':platform.python_version(),'platform':sys.platform,'fixture':{'sources':4,'records_requested':records,'records_saved':saved,'input_bytes':input_bytes,'input_sha256':input_digest.hexdigest(),'anchor_utc':stamp(now),'seed':'deterministic_index_v1','source':'generated_synthetic_only'},'measurements':{'ingest_seconds':round(ingest_seconds,4),'ingest_process_cpu_seconds':round(cpu_seconds,4),'query_count':100,'query_p95_ms':round(sorted(queries)[94],3),'query_median_ms':round(statistics.median(queries),3),'summary_ms':round(summary_ms,3),'database_wal_shm_bytes':archive.storage_bytes(),'python_heap_peak_bytes':heap_peak},'limitations':['Python heap is not process RSS.','Tracemalloc affects timings.','Not HA OS hardware or container/tunnel acceptance.','No 15-minute steady-state, 60-second burst or 24-hour soak.','1-million-record criterion is unverified unless this exact run records that count.']}
    archive.close();(output/'benchmark.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--records',type=int,default=10000)
    parser.add_argument('--anchor',help='Explicit ISO8601 UTC/offset to reproduce fixture timestamps')
    args=parser.parse_args();run(args.output,args.records,args.anchor)
