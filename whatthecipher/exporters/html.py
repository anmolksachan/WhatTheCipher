"""HTML exporter — a self-contained, offline-safe assessment report.

Design: a dark "security instrument panel". No external fonts, CSS or JS are
loaded, so the file renders identically on an air-gapped box. All interactivity
(search, sort, copy, theme toggle, charts) is vanilla JS + hand-drawn SVG.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..utils.colors import GRADE_HEX, SEVERITY_HEX, STRENGTH_HEX
from .json import result_to_dict

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import ScanResult


def _summary(dicts: list[dict]) -> dict:
    grades: dict[str, int] = {}
    crit = high = med = 0
    for d in dicts:
        g = (d.get("grade") or {}).get("letter") or "?"
        grades[g] = grades.get(g, 0) + 1
        for v in d.get("vulnerabilities", []):
            if not v.get("present"):
                continue
            if v["severity"] == "critical":
                crit += 1
            elif v["severity"] == "high":
                high += 1
            elif v["severity"] == "medium":
                med += 1
    reachable = sum(1 for d in dicts if d.get("reachable"))
    return {
        "total": len(dicts),
        "reachable": reachable,
        "grades": grades,
        "critical": crit,
        "high": high,
        "medium": med,
    }


def export(results: list[ScanResult], tool_version: str = "") -> str:
    dicts = [result_to_dict(r) for r in results]
    summary = _summary(dicts)
    payload = {
        "version": tool_version,
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": summary,
        "results": dicts,
        "palette": {
            "grade": GRADE_HEX,
            "severity": SEVERITY_HEX,
            "strength": STRENGTH_HEX,
        },
    }
    data_json = json.dumps(payload, default=str)
    return _TEMPLATE.replace("/*__DATA__*/null", data_json)


def write(results: list[ScanResult], path: str, tool_version: str = "") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(export(results, tool_version))


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhatTheCipher — TLS/SSL Assessment</title>
<style>
:root{
  --bg:#0b0d13; --surface:#12151d; --surface2:#171b25; --elev:#1d2230;
  --border:#262c3b; --text:#e7e9f0; --muted:#8b90a3; --faint:#5b6072;
  --accent:#5b8cff; --accent-dim:#2a3a63; --grid:#1a1f2b;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --radius:10px; --shadow:0 1px 0 rgba(255,255,255,.03),0 8px 30px rgba(0,0,0,.35);
}
html[data-theme="light"]{
  --bg:#eef0f5; --surface:#ffffff; --surface2:#f5f6fa; --elev:#ffffff;
  --border:#e0e3ec; --text:#161923; --muted:#5b6070; --faint:#9aa0b0;
  --accent:#2f6feb; --accent-dim:#d5e0fb; --grid:#eaecf2;
  --shadow:0 1px 2px rgba(20,25,40,.06),0 10px 30px rgba(20,25,40,.08);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:14px;line-height:1.5;
  background-image:linear-gradient(var(--grid) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid) 1px,transparent 1px);
  background-size:44px 44px;background-attachment:fixed}
a{color:var(--accent);text-decoration:none}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 80px}
.mono{font-family:var(--mono)}

/* Header */
header{display:flex;align-items:center;justify-content:space-between;
  gap:16px;flex-wrap:wrap;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:40px;height:40px;border-radius:9px;
  background:linear-gradient(135deg,var(--accent),#7b5bff);
  display:grid;place-items:center;font-family:var(--mono);font-weight:700;
  color:#fff;font-size:18px;box-shadow:var(--shadow)}
.brand h1{font-size:19px;margin:0;letter-spacing:-.3px}
.brand .sub{color:var(--muted);font-size:12px;font-family:var(--mono)}
.tools{display:flex;gap:8px;align-items:center}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);
  padding:8px 12px;border-radius:8px;cursor:pointer;font-size:13px;
  font-family:var(--sans);transition:.15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}

/* Dashboard */
.dash{display:grid;grid-template-columns:1.1fr 1.4fr;gap:16px;margin-bottom:22px}
@media(max-width:820px){.dash{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:18px;box-shadow:var(--shadow)}
.card h2{margin:0 0 14px;font-size:12px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--muted);font-weight:600}
.donutrow{display:flex;align-items:center;gap:22px}
.legend{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);
  font-size:12px}
.legend span{display:inline-flex;align-items:center;gap:8px}
.dot{width:10px;height:10px;border-radius:3px;display:inline-block}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.stat{background:var(--surface2);border:1px solid var(--border);
  border-radius:9px;padding:14px}
.stat .n{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
.stat .l{color:var(--muted);font-size:11px;margin-top:6px;
  text-transform:uppercase;letter-spacing:.08em}

/* Controls */
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.search{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);
  color:var(--text);padding:10px 12px;border-radius:9px;font-family:var(--mono);
  font-size:13px}
.search:focus{outline:none;border-color:var(--accent)}
select.sort{background:var(--surface);border:1px solid var(--border);
  color:var(--text);padding:10px;border-radius:9px;font-size:13px}

/* Host card */
.host{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);margin-bottom:16px;overflow:hidden;
  box-shadow:var(--shadow)}
.host-head{display:flex;align-items:center;gap:16px;padding:16px 18px;
  cursor:pointer;user-select:none}
.seal{width:52px;height:52px;flex:none;position:relative}
.host-id{flex:1;min-width:0}
.host-id .h{font-family:var(--mono);font-size:16px;font-weight:600;
  display:flex;align-items:center;gap:8px;overflow:hidden;text-overflow:ellipsis}
.host-id .meta{color:var(--muted);font-size:12px;font-family:var(--mono);
  margin-top:3px}
.leds{display:flex;gap:5px}
.led{font-family:var(--mono);font-size:10px;padding:3px 7px;border-radius:5px;
  border:1px solid var(--border);color:var(--faint)}
.led.on{color:#fff;border-color:transparent}
.sevpills{display:flex;gap:6px}
.pill{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 9px;
  border-radius:20px;color:#0b0d13}
.chev{color:var(--muted);transition:.2s;font-size:12px}
.host.open .chev{transform:rotate(90deg)}
.host-body{display:none;padding:0 18px 18px;border-top:1px solid var(--border)}
.host.open .host-body{display:block}
.host.unreach .host-head{opacity:.7}

.section{margin-top:18px}
.section h3{font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted);margin:0 0 10px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);
  font-family:var(--mono)}
th{color:var(--muted);font-weight:600;cursor:pointer;white-space:nowrap;
  font-size:11px;text-transform:uppercase;letter-spacing:.05em}
th:hover{color:var(--accent)}
td.name{max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-size:10px;padding:2px 6px;border-radius:4px;font-weight:700;
  color:#0b0d13;text-transform:uppercase}
.kv{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:13px}
.kv dt{color:var(--muted);font-family:var(--mono);font-size:12px}
.kv dd{margin:0;font-family:var(--mono);word-break:break-word}
.flag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:5px;
  margin:2px 4px 2px 0;font-family:var(--mono);color:#0b0d13;font-weight:600}
.rec{border-left:3px solid var(--border);padding:8px 0 8px 14px;margin:8px 0}
.rec .t{font-weight:600}
.rec .d{color:var(--muted);font-size:13px;margin-top:2px}
.rec .r{font-family:var(--mono);font-size:11px;color:var(--faint);margin-top:4px}
.copy{background:none;border:1px solid var(--border);color:var(--muted);
  cursor:pointer;border-radius:6px;padding:3px 8px;font-size:11px;
  font-family:var(--mono)}
.copy:hover{color:var(--accent);border-color:var(--accent)}
.empty{color:var(--faint);font-family:var(--mono);font-size:12px;padding:6px 0}
footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--border);
  color:var(--muted);font-size:12px;display:flex;justify-content:space-between;
  flex-wrap:wrap;gap:10px;font-family:var(--mono)}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">WC</div>
      <div>
        <h1>WhatTheCipher</h1>
        <div class="sub" id="genmeta"></div>
      </div>
    </div>
    <div class="tools">
      <button class="btn" id="expand">Expand all</button>
      <button class="btn" id="theme">◐ Theme</button>
    </div>
  </header>

  <div class="dash">
    <div class="card">
      <h2>Grade distribution</h2>
      <div class="donutrow">
        <div id="donut"></div>
        <div class="legend" id="legend"></div>
      </div>
    </div>
    <div class="card">
      <h2>Risk overview</h2>
      <div class="stats" id="stats"></div>
    </div>
  </div>

  <div class="controls">
    <input class="search" id="search" placeholder="filter by host, cipher, protocol, finding…">
    <select class="sort" id="sortby">
      <option value="grade">Sort: worst grade first</option>
      <option value="host">Sort: host A→Z</option>
      <option value="risk">Sort: most findings</option>
    </select>
  </div>

  <div id="hosts"></div>

  <footer>
    <span>WhatTheCipher · TLS/SSL assessment framework</span>
    <span>by Anmol K Sachan · @FR13ND0x7F ·
      <a href="https://github.com/anmolksachan/WhatTheCipher">github</a></span>
  </footer>
</div>

<script>
const DATA = /*__DATA__*/null;
const GRADE_HEX = DATA.palette.grade, SEV_HEX = DATA.palette.severity,
      STR_HEX = DATA.palette.strength;
const GRADE_ORDER = ["A+","A","B","C","D","E","F","T","M","?"];
const PROTO_ORDER = ["SSLv3","TLS1.0","TLS1.1","TLS1.2","TLS1.3"];

function el(t,c,h){const e=document.createElement(t);if(c)e.className=c;
  if(h!==undefined)e.innerHTML=h;return e;}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,
  m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));}

/* ---- dashboard ---- */
document.getElementById('genmeta').textContent =
  'v'+(DATA.version||'')+' · '+DATA.generated+' · '+DATA.summary.total+' hosts';

function donut(grades){
  const entries=GRADE_ORDER.filter(g=>grades[g]).map(g=>[g,grades[g]]);
  const total=entries.reduce((a,[,n])=>a+n,0)||1;
  const R=54,r=34,cx=64,cy=64;let a=-Math.PI/2;
  let paths='';
  entries.forEach(([g,n])=>{
    const frac=n/total,a2=a+frac*2*Math.PI;
    const x1=cx+R*Math.cos(a),y1=cy+R*Math.sin(a);
    const x2=cx+R*Math.cos(a2),y2=cy+R*Math.sin(a2);
    const xi2=cx+r*Math.cos(a2),yi2=cy+r*Math.sin(a2);
    const xi1=cx+r*Math.cos(a),yi1=cy+r*Math.sin(a);
    const large=frac>0.5?1:0;
    paths+=`<path d="M${x1} ${y1} A${R} ${R} 0 ${large} 1 ${x2} ${y2} `+
      `L${xi2} ${yi2} A${r} ${r} 0 ${large} 0 ${xi1} ${yi1} Z" `+
      `fill="${GRADE_HEX[g]||'#8b8d98'}"/>`;
    a=a2;
  });
  return `<svg width="128" height="128" viewBox="0 0 128 128">${paths}
    <text x="64" y="60" text-anchor="middle" font-family="var(--mono)"
      font-size="22" font-weight="700" fill="var(--text)">${total}</text>
    <text x="64" y="78" text-anchor="middle" font-family="var(--mono)"
      font-size="10" fill="var(--muted)">HOSTS</text></svg>`;
}
document.getElementById('donut').innerHTML=donut(DATA.summary.grades);
document.getElementById('legend').innerHTML=
  GRADE_ORDER.filter(g=>DATA.summary.grades[g]).map(g=>
   `<span><i class="dot" style="background:${GRADE_HEX[g]||'#8b8d98'}"></i>`+
   `${g} · ${DATA.summary.grades[g]}</span>`).join('');

const s=DATA.summary;
document.getElementById('stats').innerHTML=[
  ['reachable',s.reachable+'/'+s.total,'var(--text)'],
  ['critical',s.critical,SEV_HEX.critical],
  ['high',s.high,SEV_HEX.high],
  ['medium',s.medium,SEV_HEX.medium],
].map(([l,n,c])=>`<div class="stat"><div class="n" style="color:${c}">${n}</div>
  <div class="l">${l}</div></div>`).join('');

/* ---- host cards ---- */
function seal(letter){
  const c=GRADE_HEX[letter]||'#8b8d98';
  return `<svg class="seal" viewBox="0 0 52 52">
    <circle cx="26" cy="26" r="24" fill="none" stroke="${c}" stroke-width="2.5"
      opacity="0.5"/>
    <circle cx="26" cy="26" r="19" fill="${c}" opacity="0.14"/>
    <text x="26" y="33" text-anchor="middle" font-family="var(--mono)"
      font-size="19" font-weight="700" fill="${c}">${esc(letter)}</text></svg>`;
}
function leds(protocols){
  return PROTO_ORDER.map(p=>{
    const on=protocols[p]&&protocols[p].supported;
    const deprecated=['SSLv3','TLS1.0','TLS1.1'].includes(p);
    const col=on?(deprecated?SEV_HEX.high:STR_HEX.recommended):'transparent';
    return `<span class="led${on?' on':''}" style="${on?`background:${col}`:''}">
      ${p.replace('TLS','T')}</span>`;
  }).join('');
}
function sevpills(vulns){
  const c={critical:0,high:0,medium:0};
  vulns.forEach(v=>{if(v.present&&c[v.severity]!=null)c[v.severity]++;});
  return Object.entries(c).filter(([,n])=>n).map(([k,n])=>
    `<span class="pill" style="background:${SEV_HEX[k]}">${n} ${k[0].toUpperCase()}</span>`
  ).join('')||'<span class="pill" style="background:'+STR_HEX.recommended+
    '">clean</span>';
}

function cipherTable(ciphers){
  if(!ciphers.length) return '<div class="empty">no suites enumerated</div>';
  const rows=ciphers.map(c=>{
    const col=STR_HEX[c.strength]||'#8b8d98';
    const w=c.weaknesses.length?` <span class="tag" style="background:${SEV_HEX.high}">${esc(c.weaknesses.join(' '))}</span>`:'';
    return `<tr><td class="name" title="${esc(c.name)}">${esc(c.name)}${w}</td>
      <td>${c.bits}</td><td>${c.forward_secret?'✓':'—'}</td>
      <td>${c.aead?'✓':'—'}</td>
      <td><span class="tag" style="background:${col}">${c.strength}</span></td></tr>`;
  }).join('');
  return `<table><thead><tr><th data-k="0">Cipher</th><th data-k="1">Bits</th>
    <th data-k="2">PFS</th><th data-k="3">AEAD</th>
    <th data-k="4">Strength</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function certBlock(cert){
  if(!cert||(cert.errors&&cert.errors.length))
    return '<div class="empty">'+(cert&&cert.errors?esc(cert.errors.join('; ')):'no certificate')+'</div>';
  const flags=[];
  if(cert.self_signed)flags.push(['self-signed',SEV_HEX.high]);
  if(cert.expired)flags.push(['expired',SEV_HEX.critical]);
  if(cert.not_yet_valid)flags.push(['not yet valid',SEV_HEX.high]);
  if(cert.hostname_mismatch)flags.push(['hostname mismatch',SEV_HEX.high]);
  if(cert.uses_sha1)flags.push(['SHA-1',SEV_HEX.high]);
  if(cert.must_staple)flags.push(['must-staple',STR_HEX.recommended]);
  const flagsHtml=flags.length?flags.map(([t,c])=>
    `<span class="flag" style="background:${c}">${t}</span>`).join(''):
    '<span class="flag" style="background:'+STR_HEX.recommended+'">valid</span>';
  return `<dl class="kv">
    <dt>Subject</dt><dd>${esc(cert.subject)}</dd>
    <dt>Issuer</dt><dd>${esc(cert.issuer)}</dd>
    <dt>SAN</dt><dd>${esc((cert.san||[]).slice(0,10).join(', '))||'—'}</dd>
    <dt>Valid until</dt><dd>${esc(cert.not_after)} (${cert.days_until_expiry} days)</dd>
    <dt>Key</dt><dd>${esc(cert.public_key_type)} ${cert.public_key_bits}-bit</dd>
    <dt>Signature</dt><dd>${esc(cert.signature_algorithm)}</dd>
    <dt>Status</dt><dd>${flagsHtml}</dd></dl>`;
}

function vulnBlock(vulns){
  const present=vulns.filter(v=>v.present);
  if(!present.length) return '<div class="empty">no issues detected in passive checks</div>';
  const order={critical:0,high:1,medium:2,low:3,info:4};
  present.sort((a,b)=>order[a.severity]-order[b.severity]);
  return `<table><tbody>${present.map(v=>
    `<tr><td><span class="tag" style="background:${SEV_HEX[v.severity]}">${v.severity}</span></td>
     <td class="name">${esc(v.name)}</td><td>${esc(v.detail)}</td>
     <td>${esc(v.reference||'')}</td></tr>`).join('')}</tbody></table>`;
}

function recBlock(recs){
  if(!recs.length) return '<div class="empty">no recommendations — configuration looks solid</div>';
  return recs.map(r=>`<div class="rec" style="border-color:${SEV_HEX[r.severity]}">
    <div class="t">${esc(r.title)}</div><div class="d">${esc(r.detail)}</div>
    ${r.reference?`<div class="r">ref: ${esc(r.reference)}</div>`:''}</div>`).join('');
}

function hostCard(d,i){
  const grade=(d.grade&&d.grade.letter)||'?';
  const unreach=!d.reachable;
  const card=el('div','host'+(unreach?' unreach':''));
  card.dataset.grade=grade;card.dataset.host=d.target;
  const findings=d.vulnerabilities.filter(v=>v.present).length;
  card.dataset.risk=findings;
  const blob=[d.target,d.ip,grade,
    ...PROTO_ORDER.filter(p=>d.protocols[p]&&d.protocols[p].supported),
    ...Object.values(d.protocols).flatMap(p=>(p.ciphers||[]).map(c=>c.name)),
    ...d.vulnerabilities.filter(v=>v.present).map(v=>v.name)].join(' ').toLowerCase();
  card.dataset.search=blob;

  const head=el('div','host-head');
  head.innerHTML=seal(grade)+
    `<div class="host-id"><div class="h">${esc(d.target)}:${d.port}</div>
       <div class="meta">${esc(d.ip||'')}${unreach?' · '+esc(d.error||'unreachable'):
       ' · '+(d.grade?d.grade.score+'/100':'')+' · '+d.duration_seconds+'s'}</div></div>`+
    (unreach?'':`<div class="leds">${leds(d.protocols)}</div>
       <div class="sevpills">${sevpills(d.vulnerabilities)}</div>`)+
    `<span class="chev">▶</span>`;
  head.onclick=()=>card.classList.toggle('open');
  card.appendChild(head);

  if(!unreach){
    const body=el('div','host-body');
    const capHtml=(d.grade&&d.grade.caps&&d.grade.caps.length)?
      `<div class="empty">grade caps: ${esc(d.grade.caps.join('; '))}</div>`:'';
    body.innerHTML=
      `<div class="section"><h3>Cipher suites</h3>${
        Object.entries(d.protocols).filter(([,p])=>p.supported&&p.ciphers.length)
        .map(([proto,p])=>`<div style="margin-bottom:6px;color:var(--muted);
          font-family:var(--mono);font-size:12px">${proto}</div>${cipherTable(p.ciphers)}`)
        .join('')||'<div class="empty">no suites</div>'}</div>`+
      `<div class="section"><h3>Certificate</h3>${certBlock(d.certificate)}</div>`+
      `<div class="section"><h3>Vulnerabilities</h3>${vulnBlock(d.vulnerabilities)}</div>`+
      `<div class="section"><h3>Recommendations
         <button class="copy" data-i="${i}">copy as markdown</button></h3>${capHtml}
         ${recBlock(d.recommendations)}</div>`;
    card.appendChild(body);
  }
  return card;
}

const hostsEl=document.getElementById('hosts');
function render(list){
  hostsEl.innerHTML='';
  list.forEach((d,i)=>hostsEl.appendChild(hostCard(d,d.__i)));
}
DATA.results.forEach((d,i)=>d.__i=i);

function sortList(list,mode){
  const c=[...list];
  if(mode==='host')c.sort((a,b)=>a.target.localeCompare(b.target));
  else if(mode==='risk')c.sort((a,b)=>
    b.vulnerabilities.filter(v=>v.present).length-
    a.vulnerabilities.filter(v=>v.present).length);
  else c.sort((a,b)=>GRADE_ORDER.indexOf((b.grade&&b.grade.letter)||'?')-
    GRADE_ORDER.indexOf((a.grade&&a.grade.letter)||'?')||0);
  if(mode==='grade')c.sort((a,b)=>
    GRADE_ORDER.indexOf((a.grade&&a.grade.letter)||'?')-
    GRADE_ORDER.indexOf((b.grade&&b.grade.letter)||'?'));
  return c;
}
function apply(){
  const q=document.getElementById('search').value.toLowerCase().trim();
  const mode=document.getElementById('sortby').value;
  let list=DATA.results.filter(d=>!q||(d.__i,
    (d.target+' '+(d.ip||'')+' '+((d.grade&&d.grade.letter)||'')+' '+
     Object.entries(d.protocols).filter(([,p])=>p.supported).map(([k])=>k).join(' ')+' '+
     Object.values(d.protocols).flatMap(p=>(p.ciphers||[]).map(c=>c.name)).join(' ')+' '+
     d.vulnerabilities.filter(v=>v.present).map(v=>v.name).join(' ')
    ).toLowerCase().includes(q)));
  render(sortList(list,mode));
}
document.getElementById('search').addEventListener('input',apply);
document.getElementById('sortby').addEventListener('change',apply);

/* sortable cipher tables (delegated) */
hostsEl.addEventListener('click',e=>{
  const th=e.target.closest('th[data-k]');
  if(th){
    const table=th.closest('table'),k=+th.dataset.k;
    const tb=table.querySelector('tbody');
    const rows=[...tb.rows];
    const num=k===1;
    rows.sort((a,b)=>{
      let x=a.cells[k].textContent.trim(),y=b.cells[k].textContent.trim();
      return num?(+y-+x):x.localeCompare(y);
    });
    rows.forEach(r=>tb.appendChild(r));
    e.stopPropagation();
  }
  const cp=e.target.closest('.copy');
  if(cp){
    e.stopPropagation();
    const d=DATA.results[+cp.dataset.i];
    const md=d.recommendations.map(r=>`- **${r.title}** — ${r.detail}`+
      (r.reference?` (ref: ${r.reference})`:'')).join('\n')||'No recommendations.';
    navigator.clipboard.writeText(`### ${d.target}:${d.port} recommendations\n`+md)
      .then(()=>{cp.textContent='copied ✓';setTimeout(()=>cp.textContent='copy as markdown',1500);});
  }
});

/* controls */
let expanded=false;
document.getElementById('expand').onclick=()=>{
  expanded=!expanded;
  document.querySelectorAll('.host:not(.unreach)').forEach(h=>
    h.classList.toggle('open',expanded));
  document.getElementById('expand').textContent=expanded?'Collapse all':'Expand all';
};
document.getElementById('theme').onclick=()=>{
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
};

apply();
</script>
</body>
</html>"""
