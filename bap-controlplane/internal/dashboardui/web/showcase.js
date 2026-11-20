/* Local diagnostic reports are explicitly untrusted. Never insert their HTML. */
(function(root){
'use strict';
const names=['In-harness tool hooks','Execution broker','Cryptographic file integrity and pinning','Anomaly risk engine','Control-plane attestation'];
const statuses=new Set(['ready','participated','blocked','not_reached','unavailable','failed']);
function validate(report){
 if(!report || report.schema!=='bap-defense-showcase/v1' || report.diagnostic!==true || typeof report.demo_run_id!=='string' || typeof report.session_id!=='string' || !/^[\w-]{1,100}$/.test(report.demo_run_id) || !/^[\w-]{1,100}$/.test(report.session_id) || !Array.isArray(report.evidence) || report.evidence.length>1000)throw Error('Invalid diagnostic report');
 for(const e of report.evidence){
  if(e.demo_run_id!==report.demo_run_id || e.session_id!==report.session_id || e.diagnostic!==true || !Number.isInteger(e.layer) || e.layer<1 || e.layer>5 || !statuses.has(e.status) || !Number.isFinite(Date.parse(e.timestamp)))throw Error('Invalid or cross-run evidence');
  for(const key of ['event_id','scenario_id','action_id','producer','decision','explanation'])if(typeof e[key]!=='string' || !e[key] || e[key].length>10000)throw Error('Invalid evidence field '+key);
 }
 return report;
}
function merge(report, extra){
 validate(report);validate(extra);
 if(report.demo_run_id!==extra.demo_run_id || report.session_id!==extra.session_id)throw Error('Cannot merge different runs');
 const map=new Map();
 for(const e of [...report.evidence,...extra.evidence]){
  const key=JSON.stringify([e.demo_run_id,e.session_id,e.scenario_id,e.action_id,e.layer,e.producer,e.event_id]);
  if(map.has(key)){
   const old=map.get(key);
   // A delivery retry may change its delivery time, but not its verdict.
   for(const field of ['layer','status','decision','explanation','details'])if(JSON.stringify(old[field])!==JSON.stringify(e[field]))throw Error('Conflicting evidence identity');
  }else map.set(key,e);
 }
 return {...report,developer_override_active:report.developer_override_active===true || extra.developer_override_active===true,evidence:[...map.values()]};
}
function overview(report){
 return names.map((name,i)=>{
 const events=report?report.evidence.filter(e=>e.layer===i+1).sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp)):[];
  // Keep all evidence in the timeline; a later unavailable result cannot erase
  // a real verdict, and a ready result cannot count as participation.
  const actual=events.filter(e=>['participated','blocked','failed'].includes(e.status));
  const selected=(actual.length?actual:events).slice(-1)[0];
  return {name,layer:i+1,status:selected?selected.status:'unavailable',evidence:selected||null};
 });
}
const api={validate,merge,overview};if(typeof module!=='undefined')module.exports=api;
if(!root.document)return;
let report=null;const doc=root.document,$=id=>doc.getElementById(id);
function node(tag,text,cls){const n=doc.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function render(){
 $('layers').replaceChildren();$('timeline').replaceChildren();
 const scenario=$('scenario').value;
 const scenarios=report?[...new Set(report.evidence.map(e=>e.scenario_id))]:[];
 $('scenario').replaceChildren(node('option','All scenarios'));$('scenario').firstChild.value='';
 for(const name of scenarios){const option=node('option',name);option.value=name;$('scenario').append(option);}
 $('scenario').value=scenarios.includes(scenario)?scenario:'';
 const visible=report && $('scenario').value?{...report,evidence:report.evidence.filter(e=>e.scenario_id===$('scenario').value)}:report;
 for(const layer of overview(visible)){
  const card=node('article',undefined,'card');card.append(node('small','Layer '+layer.layer),node('h2',layer.name),node('div',layer.status.replaceAll('_',' '),'status '+layer.status));
  const e=layer.evidence;
  card.append(node('p',e?e.explanation:'No attributable evidence received.'),node('small',e?e.producer:'Source: absent'),node('small',e?e.timestamp:'Time: absent'),node('small',e?'Decision: '+e.decision:'Decision: absent'));$('layers').append(card);
 }
 if(!report)return;
 $('identity').textContent='Client '+(report.client||'unspecified')+' · Run '+report.demo_run_id+' · Session '+report.session_id+' · Diagnostic only';
 $('validation').className='banner'+(report.developer_override_active?' override':'');
 $('validation').textContent=report.developer_override_active?'DEVELOPER OVERRIDE ACTIVE — unsuitable for normal enforcement validation.':(report.validation||'Component diagnostics; not live endpoint acceptance.');
 for(const e of [...visible.evidence].sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp))){
  const tr=node('tr'),a=node('td'),b=node('td'),c=node('td'),d=node('td');
  a.append(node('small',e.timestamp),node('div',e.scenario_id),node('small',e.action_id));b.append(node('div','Layer '+e.layer),node('small',e.producer));c.append(node('div',e.status.replaceAll('_',' '),'status '+e.status),node('small',e.decision));d.append(node('div',e.explanation));
  if(e.details){const detail=node('details');detail.append(node('summary','Evidence details'),node('pre',JSON.stringify(e.details,null,2)));d.append(detail);}tr.append(a,b,c,d);$('timeline').append(tr);
 }
 $('attest').disabled=false;$('download').disabled=false;
}
$('scenario').addEventListener('change',render);
$('report').addEventListener('change',async event=>{try{const file=event.target.files[0];if(!file)return;if(file.size>2*1024*1024)throw Error('Report exceeds 2 MB');const incoming=validate(JSON.parse(await file.text()));report=report && report.demo_run_id===incoming.demo_run_id?merge(report,incoming):incoming;$('message').textContent='';render();}catch(e){$('message').textContent=e.message;}});
$('attest').addEventListener('click',async()=>{if(!report)return;$('attest').disabled=true;try{const response=await fetch('/api/v1/admin/showcase/attestation',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({demo_run_id:report.demo_run_id,session_id:report.session_id})});if(!response.ok)throw Error('Control-plane diagnostic refused ('+response.status+'). Sign in through the existing administrator flow.');report=merge(report,await response.json());$('message').textContent='';render();}catch(e){$('message').textContent=e.message;}finally{$('attest').disabled=false;}});
$('download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download=report.demo_run_id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});render();
})(typeof window==='undefined'?globalThis:window);
