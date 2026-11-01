// No external packages. Exercise state, stale responses, pagination and safe DOM rendering.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../bap-controlplane/internal/dashboardui/web/discovery.js'),'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
async function main() {
  const elements = new Map();
  function node() {return {value:'',textContent:'',children:[],disabled:false,addEventListener(name,fn){this[name]=fn;},appendChild(child){this.children.push(child);},replaceChildren(){this.children=[];},showModal(){this.open=true;},close(){this.open=false;}};}
  const element=id=>{if(!elements.has(id))elements.set(id,node());return elements.get(id);};
  let admin=false, live=true, calls=[], fail=false, hold;
  let roster={fresh_workstations:1,expected_workstations:2,expected_people:2,as_of:'2026-11-01T00:00:00Z',rows:[{person_id:'<img src=x>',team:'engineering',instance_id:'station',state:'fresh'}]};
  let page={findings:[{id:'one',name:'<img src=x onerror=alert(1)>',instance_id:'station',kind:'mcp_config',evidence:'configured',state:'present'}],total:2,revision:123,next_cursor:'one'};
  const ctx=vm.createContext({console,Date,Promise,JSON,Number,URLSearchParams,document:{getElementById:element,createElement:node},setInterval(){},confirm:()=>true,prompt:()=>null});ctx.window=ctx;
  vm.runInContext(source,ctx);
  ctx.BAPDiscovery.init({isAdmin:()=>admin,isLive:()=>live,apiFetch:async()=>({json:async()=>({})}),getJSON:async url=>{calls.push(url);if(hold)return hold;if(fail)throw Error('503');if(url.includes('/pilot/coverage'))return roster;if(url.includes('/summary'))return {open_findings:1,fresh_workstations:0,expected_workstations:2,partial_workstations:1,stale_workstations:0,not_scanned_workstations:1,storage:'sqlite'};if(url.includes('/reports'))return {reports:[],count:0};return page;}});
  assert.match(element('discoverySummary').textContent,/Authenticate/);assert.equal(calls.length,0);
  admin=true;ctx.BAPDiscovery.authChanged();ctx.BAPDiscovery.show();await flush();
  assert.match(element('discoverySummary').textContent,/0\/2/);assert.equal(element('discoveryRows').children[0].children[0].textContent,page.findings[0].name);
  assert.match(element('pilotCoverageSummary').textContent,/1\/2 expected workstations/);assert.match(element('pilotCoverageRows').children[0].textContent,/<img src=x>/);
  assert.equal(element('discoveryMore').disabled,false);
  page={findings:[{id:'two',name:'second'}],total:2,revision:123};element('discoveryMore').onclick();await flush();
  assert.equal(element('discoveryRows').children.length,2);assert.match(calls.at(-1),/cursor=one&revision=123/);
  fail=true;await ctx.BAPDiscovery.refresh();assert.match(element('discoveryMessage').textContent,/stale/);assert.equal(element('discoveryRows').children.length,2);
  fail=false;let release;hold=new Promise(resolve=>{release=resolve;});const pending=ctx.BAPDiscovery.refresh();admin=false;ctx.BAPDiscovery.authChanged();release(page);await pending;
  assert.equal(element('discoveryRows').children.length,0);assert.match(element('discoverySummary').textContent,/Authenticate/);
  assert.equal(element('pilotCoverageRows').children.length,0);assert.match(element('pilotCoverageSummary').textContent,/not loaded/);
  hold=null;admin=true;live=false;ctx.BAPDiscovery.authChanged();await flush();assert.equal(element('discoveryRows').children.length,0);
  console.log('UI v3 discovery: passed');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
