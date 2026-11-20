(function(root){
'use strict';
const names=['In-harness hooks','Execution broker','Integrity and pinning','Anomaly risk','Control-plane attestation'];
function esc(value){return String(value==null?'':value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function layers(input){
 return names.map((name,i)=>{
  const received=Array.isArray(input)?input.find(x=>x.layer===i+1):null;
  const e=received&&received.evidence;
  // Neither a colored state supplied without evidence nor an installation
  // flag can establish participation.
  const valid=e && e.layer===i+1 && e.event_id && e.action_id && e.producer && e.decision && Number.isFinite(Date.parse(e.timestamp)) && !e.diagnostic;
  return {layer:i+1,name:received&&received.name||name,state:valid?(['blocked','alert'].includes(received.state)?received.state:'evaluated'):(received&&received.state==='disabled'?'disabled':'not_observed'),evidence:valid?e:null};
 });
}
function render(input){
 const actual=layers(input);
 let html='<div class="defense-5layers" role="group" aria-label="Defense evidence from live activity">';
 for(const l of actual){const e=l.evidence;const cls=l.state==='evaluated'?'observed':l.state==='alert'?'bypassed':l.state==='blocked'||l.state==='disabled'?'disabled':'silent';const detail=e?[e.producer,e.decision,e.timestamp,'Scope: '+(e.scope||'action'),'Action: '+e.action_id,e.reason].filter(Boolean).join(' · '):'No evidence received for this layer';html+='<span class="layer-pill '+cls+'" title="'+esc(detail)+'">'+esc('L'+l.layer+' '+l.name+' · '+l.state.replaceAll('_',' '))+'</span>';}
 html+='</div>';
 const evidence=actual.filter(l=>l.evidence);
 if(evidence.length){html+='<details style="margin-top:6px"><summary>Live defense evidence</summary>';for(const l of evidence){const e=l.evidence;html+='<div style="font-size:12px;padding:6px 0">'+esc('L'+l.layer+' · '+e.producer+' · '+e.decision)+'<br><small>'+esc(e.timestamp+' · '+(e.scope||'action')+' · '+e.action_id)+'</small><br>'+esc(e.reason||'')+'</div>';}html+='</details>';}
 if(evidence.some(l=>l.evidence.developer_override_active)){html+='<strong style="color:var(--warn)">Developer override active: unsuitable for normal enforcement validation.</strong>';}
 if(!actual[0].evidence && actual[1].evidence){html+='<small>Native hook evidence absent; the broker independently evaluated a received request.</small>';}
 return html;
}
const api={layers,render};if(typeof module!=='undefined')module.exports=api;if(root)root.BapDefenseLive=api;
})(typeof window==='undefined'?globalThis:window);
