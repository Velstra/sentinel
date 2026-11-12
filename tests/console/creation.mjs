// Real physical Chrome interactions; no native/dataplane certification.
import {browser,signIn,sleep,test,check} from './harness.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';

export async function click(page,selector){
 const p=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});
  if(!n||n.disabled||!n.getClientRects().length)throw Error('Unavailable control: '+${JSON.stringify(selector)});
  n.scrollIntoView({block:'center',inline:'nearest'});const r=n.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2,h=document.elementFromPoint(x,y);
  if(h!==n&&!n.contains(h))throw Error('Control occluded');return{x,y};})()`);
 await page.send('Input.dispatchMouseEvent',{type:'mousePressed',...p,button:'left',clickCount:1});
 await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',...p,button:'left',clickCount:1});await sleep(30);
}

export async function creationTests(){
 for(const width of [1440,390]){
  const page=await browser({width,height:1000}),seen=new Set(),observations=[];
  try{
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
   await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
   check(await page.evaluate('innerWidth')===width,'Creation sweep viewport differs from its receipt');
   const inventory=await page.evaluate(`([...document.querySelectorAll('main button[id^="toggle"]')].map(n=>n.id))`);
   await test('creation readiness ownership at '+width,async()=>{
    check(inventory.length===41,'Review changed creation inventory: '+inventory.length);
    const bad=await page.evaluate(`([...document.querySelectorAll('main button[id^="toggle"]')].filter(n=>n.hasAttribute('data-config-loading')
     ?!n.disabled||n.getAttribute('aria-busy')!=='true':typeof n.onclick!=='function'||!n.getAttribute('aria-controls')).map(n=>n.id))`);
    check(!bad.length,'Enabled/unowned creation controls: '+bad.join(','));
   });
   const destinations=await page.evaluate(`paletteItems().map(n=>({title:n.t,group:n.g,key:n.g+' / '+n.t}))`);
   for(const {title,group,key} of destinations){
    if(!await page.evaluate(`!!document.querySelector('#palettehint').getClientRects().length`))await click(page,'#navtoggle');
    await click(page,'#palettehint');
    const destination=await page.evaluate(`(()=>{const n=[...document.querySelectorAll('#palettelist .palitem')].find(n=>n.querySelector('.palt').textContent===${JSON.stringify(title)}&&n.querySelector('.palg').textContent===${JSON.stringify(group)});
     if(!n)throw Error('Actual navigation choice absent');n.id='qa-creation-destination';return '#'+n.id;})()`);
    await click(page,destination);await sleep(150);
    const controls=await page.evaluate(`([...document.querySelectorAll('main button[id^="toggle"]')].filter(n=>n.getClientRects().length).map(n=>n.id))`);
    for(const id of controls){
     if(seen.has(id))continue;seen.add(id);
     await test('creation '+id+' at '+width,async()=>{
      const deadline=Date.now()+10000;let ready;
      do{
       ready=await page.evaluate(`(()=>{const n=document.getElementById(${JSON.stringify(id)});return{loading:n.hasAttribute('data-config-loading'),disabled:n.disabled,handler:typeof n.onclick,panel:n.getAttribute('aria-controls'),title:n.title};})()`);
       if(!ready.loading)break;await sleep(100);
      }while(Date.now()<deadline);
      check(!ready.loading,'Form never ready: '+JSON.stringify({key,id,...ready}));
      if(ready.disabled){observations.push({width,key,id,prerequisite_disabled:true,reason:ready.title});return;}
      check(ready.handler==='function'&&ready.panel,'Missing disclosure handler: '+id);
      const box='#'+ready.panel;
      try{
       await click(page,'#'+id);
       const actual=await page.evaluate(`(()=>{const b=document.querySelector(${JSON.stringify(box)}),fields=[...b.querySelectorAll('input,select,textarea')].filter(n=>n.getClientRects().length);
        return{visible:!!b.getClientRects().length,expanded:document.getElementById(${JSON.stringify(id)}).getAttribute('aria-expanded'),fields:fields.length,
         unlabelled:fields.filter(n=>!n.labels?.length&&!n.getAttribute('aria-label')).length,staged:stagedCommands().length,focusInside:b.contains(document.activeElement)};})()`);
       check(actual.visible&&actual.expanded==='true'&&actual.fields>0&&!actual.unlabelled&&actual.focusInside,'First physical click failed: '+JSON.stringify({key,id,actual}));
       check(actual.staged===0,'Opening a form staged work');
       await click(page,box+' .maskfoot > .primary');
       check(await page.evaluate(`stagedCommands().length===0&&!!document.querySelector(${JSON.stringify(box)}).querySelector('[aria-invalid="true"]')`),'Invalid empty creation staged work: '+id);
       if(['toggleupchan','toggleradius','togglenpt','togglevrf'].includes(id)){
        const folder=process.env.CONSOLE_SCREENSHOTS||'screenshots';mkdirSync(folder,{recursive:true});
        writeFileSync(folder+'/creation-'+id+'-'+width+'.png',Buffer.from(await page.screenshot(),'base64'));
       }
       await click(page,box+' .maskfoot > button:not(.primary)');
       check(await page.evaluate(`!document.querySelector(${JSON.stringify(box)}).getClientRects().length&&document.activeElement.id===${JSON.stringify(id)}`),'Cancel/focus failed: '+id);
       await click(page,'#'+id);
       await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
       await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
       check(await page.evaluate(`!document.querySelector(${JSON.stringify(box)}).getClientRects().length&&document.activeElement.id===${JSON.stringify(id)}&&stagedCommands().length===0`),'Escape/focus failed: '+id);
       observations.push({width,key,id,first_physical_click:true,invalid_add_refused:true,cancel_and_escape:true});
      }finally{
       if(await page.evaluate(`!!document.querySelector(${JSON.stringify(box)})?.getClientRects().length`))await click(page,box+' .maskfoot > button:not(.primary)');
      }
     });
    }
   }
   await test('all declared creation controls inspected at '+width,async()=>{
    const missing=inventory.filter(id=>!seen.has(id));check(!missing.length,'Unvisited controls: '+missing.join(','));
    check(!page.thrown.length&&!page.consoleMessages.some(row=>row.level==='error'),'Browser script/console error');
   });
   const folder=process.env.CONSOLE_SCREENSHOTS||'screenshots';mkdirSync(folder,{recursive:true});
   writeFileSync(folder+'/creation-observations-'+width+'.json',JSON.stringify({inventory,observations},null,2));
  }finally{page.close();}
 }
}
