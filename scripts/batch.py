import csv
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from collections import Counter
from urllib.parse import quote

ROOT = Path.cwd()

def load():
    entries = json.loads(Path('config/repositories.json').read_text(encoding='utf-8'))
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
        raise ValueError('Expected 1–1000 entries')
    result, seen = [], set()
    for e in entries:
        repo, ref = e['repository'], e['ref']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or any(x in ('.','..') for x in repo.split('/')):
            raise ValueError(f'Invalid repository: {repo}')
        if not isinstance(ref, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or ref.startswith('-') or '..' in ref:
            raise ValueError(f'Invalid ref: {ref}')
        key = (repo.lower(), ref)
        if key not in seen:
            seen.add(key)
            result.append({'repository': repo, 'ref': ref, 'id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]})
    return result

def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(path)

def run(args, timeout, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True, timeout=timeout).stdout

def url(repo, sha, loc):
    path, sep, line = loc.rpartition(':')
    if not sep or not line.isdigit():
        return ''
    return f'https://github.com/{repo}/blob/{sha}/{quote(path, safe="/")}#L{line}'

def summary(text):
    if os.getenv('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(text + '\n')

def prepare():
    entries = load()
    n = min(10, len(entries))
    matrix = {'include': [{'shard': i, 'shards': n} for i in range(n)]}
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write('matrix=' + json.dumps(matrix, separators=(',', ':')) + '\n')
    summary(f'## Scan plan\n\n{len(entries)} unique repository/ref pairs; {n} scan jobs.')

def scan():
    shard, shards = int(os.environ['SHARD']), int(os.environ['SHARDS'])
    entries = load()[shard::shards]
    counts = Counter()
    for e in entries:
        record = dict(e, status='failed', commit='', candidates=[], error='')
        print(f"Scanning {e['repository']} @ {e['ref']}", flush=True)
        try:
            with tempfile.TemporaryDirectory(prefix='mtrace-') as tmp:
                # Fetch source only; never build or execute target code.
                run(['git','init','-q',tmp], 30)
                run(['git','-C',tmp,'fetch','--depth=1','--no-tags',f"https://github.com/{e['repository']}.git",e['ref']], 120)
                run(['git','-C',tmp,'checkout','--detach','FETCH_HEAD'], 60)
                record['commit'] = run(['git','-C',tmp,'rev-parse','HEAD'], 30).strip()
                raw = run([str(ROOT/'mtrace'),tmp], 120)
                candidates = json.loads(raw) or []
                if not isinstance(candidates,list):
                    raise ValueError('Scanner output is not an array')
                for c in candidates:
                    c.update(repository=e['repository'], ref=e['ref'], commit=record['commit'])
                    for k in ('source','sink'):
                        c[k+'_url'] = url(e['repository'],record['commit'],c.get(k+'_location',''))
                record.update(status='success', candidates=candidates)
        except Exception as exc:
            record['error'] = str(exc)[:500]
        write_json(Path('results')/(e['id']+'.json'), record)
        counts[record['status']] += 1
        print(f"  {record['status']}: {len(record['candidates'])} candidates", flush=True)
    summary(f'## Shard {shard+1}/{shards}\n\nSuccess: {counts["success"]}; failed: {counts["failed"]}.')

def aggregate():
    expected = load()
    actual = {}
    for p in Path('shards').glob('mtrace-shard-*/*.json'):
        r = json.loads(p.read_text(encoding='utf-8'))
        actual[r['id']] = r
    records = [actual.get(e['id'],dict(e,status='missing',commit='',candidates=[],error='No shard artifact received')) for e in expected]
    candidates = [c for r in records for c in r['candidates']]
    counts = Counter(r['status'] for r in records)
    types = Counter(c.get('m_type','unknown') for c in candidates)
    out = Path('report'); out.mkdir(exist_ok=True)
    write_json(out/'repositories.json', records)
    write_json(out/'candidates.json', candidates)
    write_json(out/'summary.json', {'projects':len(records),'status':dict(counts),'candidates':len(candidates),'m_types':dict(types)})
    fields = ['repository','ref','commit','score','m_type','metadata_type','metadata_key','resource_type','pattern','source_location','sink_location','source_url','sink_url','source_expr','sink_expr']
    def safe(v):
        return "'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v
    with (out/'candidates.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w = csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for c in candidates: w.writerow({k:safe(c.get(k,'')) for k in fields})
    def esc(v): return html.escape(str(v),quote=True)
    rows=[]
    for c in sorted(candidates,key=lambda c:-c.get('score',0)):
        cells=[esc(c.get(k,'')) for k in ['repository','ref','score','m_type','metadata_type','pattern']]
        for k in ('source','sink'):
            cells.append(f'<a href="{esc(c.get(k+"_url",""))}">{esc(c.get(k+"_location",""))}</a>')
        rows.append('<tr>'+''.join('<td>'+v+'</td>' for v in cells)+'</tr>')
    (out/'report.html').write_text('''<!doctype html><meta charset="utf-8"><title>MTrace report</title><style>body{font:15px system-ui;margin:30px}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}input{padding:10px;width:90%}</style><h1>MTrace candidates</h1><p>Static candidates, not confirmed vulnerabilities.</p><input id="q" placeholder="Filter repository, M type, score or path" oninput="for(const r of document.querySelectorAll('tbody tr'))r.hidden=!r.textContent.toLowerCase().includes(this.value.toLowerCase())"><table><thead><tr><th>Repository</th><th>Ref</th><th>Score</th><th>M type</th><th>Metadata</th><th>Pattern</th><th>Source</th><th>Sink</th></tr></thead><tbody>'''+''.join(rows)+'</tbody></table>',encoding='utf-8')
    lines=['## MTrace batch results','',f'Projects: {len(records)} | Success: {counts["success"]} | Failed: {counts["failed"]} | Missing: {counts["missing"]} | Candidates: {len(candidates)}','','| M type | Count |','|---|---:|']
    lines += [f'| {k} | {v} |' for k,v in sorted(types.items())]
    lines += ['','### Repository status','','| Repository | Ref | Status | Candidates |','|---|---|---|---:|']
    lines += [f'| {r["repository"]} | {r["ref"]} | {r["status"]} | {len(r["candidates"])} |' for r in records]
    lines += ['','### Top 100 candidates (all results in artifact)','','| Repository | Score | M type | Source | Sink |','|---|---:|---|---|---|']
    for c in sorted(candidates,key=lambda c:-c.get('score',0))[:100]:
        def link(k):
            label=str(c.get(k+'_location','')).replace('|','\\|').replace('[','').replace(']','')
            return f'[{label}]({c[k+"_url"]})' if c.get(k+'_url') else label
        lines.append(f'| {c["repository"]} | {c["score"]} | {c["m_type"]} | {link("source")} | {link("sink")} |')
    summary('\n'.join(lines))

if __name__ == '__main__':
    {'prepare':prepare,'scan':scan,'aggregate':aggregate}[sys.argv[1]]()
