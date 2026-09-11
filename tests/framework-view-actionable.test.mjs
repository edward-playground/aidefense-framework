import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {aidefendData} from '../main.js';
import {frameworkMigrations} from '../framework-migrations.js';
import {ciscoFramework} from '../cisco-framework.js';
const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
const atlasStart=html.indexOf('const atlasTechToTactics =');
const atlasEnd=html.indexOf('const atlasTechNames =',atlasStart);
const atlasText=html.slice(atlasStart,atlasEnd);
const atlasTechToTactics=new Function(atlasText+';return atlasTechToTactics;')();
const configStart=html.indexOf('const frameworkViewConfig =');
const configEnd=html.indexOf('function clearElement(',configStart);
const configs=new Function('owaspLlmCatalog','ciscoFramework','atlasTechToTactics',html.slice(configStart,configEnd)+';return frameworkViewConfig;')(frameworkMigrations.frameworks.owasp_llm,ciscoFramework,atlasTechToTactics);
const prepareStart=html.indexOf('function prepareFrameworkViews()');
const prepareEnd=html.indexOf('// === Two-Phase Rendering ===',prepareStart);
const prepare=new Function('eligibleTechniques','frameworkViewConfig','let frameworkViews,atlasDefenseMap;'+html.slice(prepareStart,prepareEnd)+';prepareFrameworkViews();return {frameworkViews,atlasDefenseMap};');
const all=aidefendData.tactics.flatMap(t=>t.techniques.flatMap(p=>[{...p,tactic:t.name},...(p.subTechniques??[]).map(c=>({...c,parent:p,tactic:t.name}))]));
const leaves=all.filter(c=>!c.subTechniques?.length);
const parents=new Set(all.filter(c=>c.subTechniques?.length).map(c=>c.id));
const result=prepare(all,configs);
test('all nine framework views count only independently mapped actionable controls',()=>{
 assert.equal(Object.keys(configs).length,9);
 for(const [key,config] of Object.entries(configs))for(const [group,actual] of Object.entries(result.frameworkViews[key])){
  const expected=leaves.filter(c=>c.defendsAgainst.find(m=>m.framework===config.frameworkKey)?.items.some(item=>{
   const parsed=config.parseGroup(item);return (Array.isArray(parsed)?parsed:[parsed]).includes(group);
  }));
  assert.deepEqual(actual.map(c=>c.id).sort(),expected.map(c=>c.id).sort(),key+':'+group);
  assert.equal(new Set(actual.map(c=>c.id)).size,actual.length);
  assert.ok(actual.every(c=>!parents.has(c.id)));
 }
});
test('ATLAS reverse lookup rejects parent navigation unions and unrelated siblings',()=>{
 for(const [id,actual] of Object.entries(result.atlasDefenseMap)){
  const expected=leaves.filter(c=>c.defendsAgainst.find(m=>m.framework==='MITRE ATLAS')?.items.some(item=>item.split(' ')[0]===id));
  assert.deepEqual(actual.map(c=>c.id).sort(),expected.map(c=>c.id).sort(),id);
  assert.ok(actual.every(c=>!parents.has(c.id)));
 }
 const parent={id:'parent',subTechniques:[{id:'child-match'},{id:'child-other'}],defendsAgainst:[{framework:'MITRE ATLAS',items:['AML.T0051 Parent union']}]};
 const matching={id:'child-match',defendsAgainst:[{framework:'MITRE ATLAS',items:['AML.T0051 Prompt Injection']}]};
 const sibling={id:'child-other',defendsAgainst:[{framework:'MITRE ATLAS',items:['N/A']}]};
 assert.deepEqual(prepare([parent,matching,sibling],configs).atlasDefenseMap['AML.T0051'].map(c=>c.id),['child-match']);
});
test('frameworks keep family taxonomy available without treating it as an actionable result',()=>{
 assert.ok(parents.size>0);
 assert.equal(all.length,parents.size+leaves.length);
 assert.match(html,/Parent families remain available in the Tactics view/);
 assert.doesNotMatch(html,/config\.actionableOnly/);
});
export {configs,leaves,parents,result};
