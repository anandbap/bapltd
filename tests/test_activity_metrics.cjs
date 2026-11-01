const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname,'../bap-controlplane/internal/dashboardui/web');
const html = fs.readFileSync(path.join(root,'v2.html'),'utf8');
const start = html.indexOf('    function renderMissionControlSummary(summary)');
const end = html.indexOf('    // Render Canonical Workstreams',start);
const nodes = new Map();
const ctx=vm.createContext({document:{getElementById(id){if(!nodes.has(id))nodes.set(id,{textContent:''});return nodes.get(id);}}});
vm.runInContext(html.slice(start,end),ctx);
ctx.renderMissionControlSummary({total_active_agents:8,estimated_assisted_hours:null,assisted_fte_equivalent:null,high_risk_prevented:null});
assert.equal(nodes.get('mcActiveAgents').textContent,8);
for(const id of ['mcAssistedHours','mcFTEEquiv','mcPrevented','buEngCount','buSecCount','buSupCount'])assert.equal(nodes.get(id).textContent,'Unavailable',id);
ctx.renderMissionControlSummary({});assert.equal(nodes.get('mcActiveAgents').textContent,'Unavailable');
ctx.renderMissionControlSummary({estimated_assisted_hours:0,assisted_fte_equivalent:0,high_risk_prevented:0});assert.equal(nodes.get('mcAssistedHours').textContent,'0');assert.equal(nodes.get('mcPrevented').textContent,0);
for(const file of ['index.html','v2.html','v3.html']){
 const page=fs.readFileSync(path.join(root,file),'utf8');
 for(const match of page.matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(match[1],{filename:file});
}
console.log('Activity measurement UI: passed');
