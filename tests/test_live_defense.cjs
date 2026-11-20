const test=require('node:test');const assert=require('node:assert/strict');
const {layers,render}=require('../bap-controlplane/internal/dashboardui/web/defense-live.js');
const evidence=(layer)=>({layer,event_id:'e-'+layer,action_id:'a',producer:'edge/test',decision:'passed',timestamp:'2026-11-19T23:00:00Z',scope:'action'});
test('all five visible without inventing participation',()=>{assert.equal(layers([]).length,5);assert(layers([]).every(x=>x.state==='not_observed'));assert.equal(layers([{layer:1,state:'evaluated'}])[0].state,'not_observed');});
test('missing hooks do not hide independent broker evidence',()=>{const data=[{layer:2,state:'evaluated',evidence:evidence(2)}];const view=layers(data);assert.equal(view[0].state,'not_observed');assert.equal(view[1].state,'evaluated');assert.match(render(data),/broker independently evaluated/);});
test('show actual producer/action/time and escape untrusted text',()=>{const e=evidence(3);e.reason='<script>alert(1)</script>';const html=render([{layer:3,state:'evaluated',evidence:e}]);assert.match(html,/edge\/test/);assert.match(html,/2026-11-19/);assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));});
test('fixtures never establish live coverage',()=>{const e=evidence(1);e.diagnostic=true;assert.equal(layers([{layer:1,state:'evaluated',evidence:e}])[0].state,'not_observed');});
