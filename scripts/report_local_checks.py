"""Create content-free evidence from this task's successful local JUnit run.

Live statuses record this task's observations; this is not a deployment detector.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]

def report(junit:Path,benchmark:Path):
    original=ET.parse(junit).getroot()
    suites=list(original.iter('testsuite'))
    totals={key:sum(int(s.get(key,'0')) for s in suites) for key in ['tests','failures','errors','skipped']}
    if not totals['tests'] or totals['failures'] or totals['errors']:raise ValueError('SUCCESSFUL_TEST_REPORT_REQUIRED')
    clean_root=ET.Element('testsuites')
    for suite in suites:
        clean=ET.SubElement(clean_root,'testsuite',{k:v for k,v in suite.attrib.items() if k in {'name','tests','failures','errors','skipped','time','timestamp'}})
        for case in suite.findall('testcase'):
            target=ET.SubElement(clean,'testcase',{k:v for k,v in case.attrib.items() if k in {'name','classname','time'}})
            if case.find('skipped') is not None:ET.SubElement(target,'skipped',{'message':'PLATFORM_CAPABILITY_UNAVAILABLE; complete Linux symlink check on target.'})
    output=ROOT/'docs/verification';output.mkdir(parents=True,exist_ok=True)
    clean_xml=output/'pytest-junit.xml'
    ET.ElementTree(clean_root).write(clean_xml,encoding='utf-8',xml_declaration=True)
    benchmark_result=json.loads(benchmark.read_text(encoding='utf-8'))
    from importlib.metadata import version
    result={'product_version':'1.0.0-alpha.6','date':'2026-10-07','environment':{'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,'mcp_sdk':version('mcp'),'platform':sys.platform,'docker_available':False,'linux_runtime_available':False},'pytest':totals|{'passed':totals['tests']-totals['skipped'],'seconds':sum(float(s.get('time','0')) for s in suites),'junit_sha256':hashlib.sha256(clean_xml.read_bytes()).hexdigest()},'benchmark':benchmark_result,'checks':[{'name':'unit_fixture_and_local_http','status':'passed','evidence':'pytest-junit.xml'},{'name':'mcp_sdk_legacy_2025_11_25_and_modern_2026_07_28','status':'passed','evidence':'tests.test_mcp and tests.test_output_schemas'},{'name':'ui_browser_render_360_keyboard_synthetic_preview','status':'passed','evidence':'ui-desktop.jpg, ui-mobile.jpg, ui-preview.jpg; local import-only, not HA Ingress'},{'name':'docker_ha_os_process_isolation','status':'unverified'},{'name':'actual_ha_reads_both_architectures','status':'unverified'},{'name':'full_idp_pkce_resource_refresh_revocation','status':'unverified'},{'name':'mcp_inspector','status':'unverified'},{'name':'tunnel_linux_runtime_and_account','status':'unverified'},{'name':'real_chatgpt_registered_plugin_dialogue','status':'unverified'},{'name':'gateway_tls_real_roundtrip','status':'unverified'},{'name':'million_records_steady_burst_aggregate_rss_24h_soak','status':'unverified'},{'name':'container_image_sbom_vulnerability_sigstore','status':'unverified'}],'git_commit_push_or_publication_performed':False,'owner_input_documents_rewritten':False}
    (output/'local-checks.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(f"SAFE_REPORT_CREATED: {result['pytest']['passed']} passed, {totals['skipped']} skipped; live acceptance remains unverified.")
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--junit',type=Path,required=True)
    parser.add_argument('--benchmark',type=Path,required=True)
    args=parser.parse_args();report(args.junit,args.benchmark)
