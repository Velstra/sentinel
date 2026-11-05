// Real Chromium layout/accessibility smoke over every palette destination.
// No configuration writes: use the disposable API provided by run.sh.
import {browser,signIn,sleep,test,check,equal,summary} from './harness.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';

const page=await browser({width:1440,height:1000});
const evidence=[];
try {
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 const destinations=await page.evaluate('paletteItems().map((item,index)=>({index,name:item.g+" / "+item.t}))');
 check(destinations.length>=60,'destination inventory unexpectedly shrank');
 for(const width of [1440,390,320]){
  await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
  await test('every destination retains labeled, reachable controls at '+width+'px',async()=>{
   const problems=[];
   for(const destination of destinations){
    await page.evaluate(`paletteItems()[${destination.index}].run()`);await sleep(100);
    const state=await page.evaluate(`(()=>{
     const visible=n=>n.getClientRects().length>0&&getComputedStyle(n).visibility!=='hidden';
     const inScroll=n=>{for(let p=n.parentElement;p;p=p.parentElement){const s=getComputedStyle(p);if(['auto','scroll'].includes(s.overflowX)&&p.scrollWidth>p.clientWidth)return true;}return false;};
     const fields=[...document.querySelectorAll('main input,main select,main textarea')].filter(visible);
     const controls=[...document.querySelectorAll('main button,main input,main select,main textarea')].filter(visible);
     const overlaps=[];
     for(const grid of document.querySelectorAll('main .grid')){
      const rows=[...grid.children].filter(n=>n.classList.contains('field')&&visible(n));
      for(let i=0;i<rows.length;i++)for(let j=i+1;j<rows.length;j++){
       const a=rows[i].getBoundingClientRect(),b=rows[j].getBoundingClientRect();
       if(Math.min(a.right,b.right)-Math.max(a.left,b.left)>1&&Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1)overlaps.push([rows[i].textContent.slice(0,60),rows[j].textContent.slice(0,60)]);
      }
     }
     return{width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
      unlabeled:fields.filter(n=>!n.labels?.length&&!n.getAttribute('aria-label')&&!n.getAttribute('aria-labelledby')).map(n=>n.id||n.placeholder||n.type),
      clipped:controls.filter(n=>{const r=n.getBoundingClientRect();return(r.left<0||r.right>innerWidth+1)&&!inScroll(n);}).map(n=>n.id||n.textContent||n.type),
      overlaps,heading:document.querySelector('#pagehead h2')?.textContent};})()`);
    evidence.push({destination:destination.name,...state});
    if(state.scrollWidth>width||state.unlabeled.length||state.clipped.length||state.overlaps.length||!state.heading){
     problems.push({destination:destination.name,...state});
    }
   }
   equal(problems,[],'layout/accessibility regressions');
  });
 }
 await test('destination walk has no JavaScript errors or requests outside the appliance',()=>{
  equal(page.thrown,[],'browser JavaScript errors');
  const origin=new URL(process.env.CONSOLE_URL).origin;
  check(page.requests.filter(url=>/^https?:/.test(url)).every(url=>new URL(url).origin===origin),'an asset or request left the appliance');
 });
}finally{
 const out=process.env.CONSOLE_SCREENSHOTS;
 if(out){mkdirSync(out,{recursive:true});writeFileSync(out+'/layout-report.json',JSON.stringify({states:evidence,errors:page.thrown,responses:page.responses,failedRequests:page.failedRequests,logs:page.logs},null,2));}
 page.close();
}
process.exitCode=summary()?1:0;
