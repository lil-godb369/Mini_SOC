// ECC-inspired browser checks. API fixtures never change the lab database.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const baseURL = process.env.BASE_URL || 'http://127.0.0.1:8000';
const artifacts = path.join(__dirname, 'artifacts');
fs.mkdirSync(artifacts, {recursive:true});

async function login(page, email='analyst@test.local', password='browser-test-only') {
  await page.locator('#email').fill(email);
  await page.locator('#password').fill(password);
  await page.locator('#login-button').click();
  try { await page.locator('#app-view').waitFor({state:'visible'}); }
  catch (error) { console.error('Login state:', await page.locator('#login-error').innerText()); throw error; }
  await page.waitForFunction(() => !document.getElementById('notice').textContent);
}

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.BROWSER_CHANNEL ? {channel:process.env.BROWSER_CHANNEL} : {})});
  const errors=[];
  try {
    const context=await browser.newContext({viewport:{width:1440,height:1000}});
    const page=await context.newPage();
    page.on('pageerror', e=>{errors.push(e.message); console.error('Browser error:',e.message);});
    const malicious='<img src=x onerror="window.injected=true">';
    const alerts=Array.from({length:23},(_,i)=>({id:i+1,title:i===0?malicious:'Cảnh báo kiểm thử '+(i+1),severity:i===0?'critical':'medium',status:'new',host:i===0?'LAB-PC':'OTHER-PC',source:'ransomware',technique:'T1486',technique_name:'Data Encrypted for Impact',rule_id:'test-ransomware',ts:'2026-11-09T11:00:00Z',evidence:{command_line:malicious,score:0.42}}));
    let fail=false,expired=false,lastQuery;
    await page.route('**/api/v1/**',async route=>{
      const req=route.request(), url=new URL(req.url()), p=url.pathname;
      const send=(data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
      if(p.endsWith('/auth/login')) {
        if(req.postDataJSON().password==='wrong') return send({detail:'Email hoặc mật khẩu không đúng'},401);
        return send({access_token:'fixture-token'});
      }
      assert.equal(req.headers().authorization,'Bearer fixture-token');
      if(expired) return send({detail:'Expired'},401);
      if(p.endsWith('/stats/overview')) return send({total_events:3024,total_alerts:23,open_alerts:alerts.filter(a=>a.status!=='closed').length,agents_online:1});
      if(p.endsWith('/agents')) return send([{hostname:'LAB-PC'},{hostname:'OTHER-PC'}]);
      if(p.endsWith('/alerts')) {
        lastQuery=url.searchParams;
        if(fail) return send({detail:'Backend temporarily unavailable'},503);
        let items=alerts.filter(a=>['severity','status','host','source'].every(k=>!url.searchParams.get(k)||a[k]===url.searchParams.get(k)));
        const offset=Number(url.searchParams.get('offset')),limit=Number(url.searchParams.get('limit'));
        return send({total:items.length,items:items.slice(offset,offset+limit)});
      }
      const match=p.match(/\/alerts\/(\d+)(\/status)?$/);
      if(match) {const a=alerts.find(a=>a.id===Number(match[1])); if(req.method()==='PATCH') a.status=req.postDataJSON().status; return send(a);}
      throw new Error('Unexpected API route '+p);
    });
    await page.goto(baseURL+'/dashboard/');
    await page.locator('#email').fill('analyst@test.local'); await page.locator('#password').fill('wrong'); await page.locator('#login-button').click();
    await page.waitForFunction(()=>document.getElementById('login-error').textContent.includes('không đúng'));
    await login(page);
    console.log('Checked login and initial alert list.');
    assert.equal(await page.locator('#alert-rows tr').count(),20);
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    assert.equal(await page.evaluate(()=>window.injected),undefined);
    assert((await page.locator('#alert-rows').innerText()).includes(malicious));
    await page.locator('#auto-refresh').uncheck();
    await page.locator('#next').click(); await page.waitForFunction(()=>document.querySelectorAll('#alert-rows tr').length===3);
    assert.equal(lastQuery.get('offset'),'20');
    console.log('Checked pagination.');
    await page.locator('#previous').click(); await page.waitForFunction(()=>document.querySelectorAll('#alert-rows tr').length===20);
    await page.locator('[name=severity]').selectOption('critical');await page.locator('[name=host]').fill('LAB-PC');await page.locator('[name=status]').selectOption('new');
    await page.locator('#filters button[type=submit]').click(); await page.waitForFunction(()=>document.querySelectorAll('#alert-rows tr').length===1);
    await page.locator('#alert-rows button').click();await page.locator('#status-form').waitFor({state:'visible'});
    console.log('Checked filters and detail.');
    assert.equal(JSON.parse(await page.locator('#evidence').innerText()).command_line,malicious);
    await page.locator('#detail-status').selectOption('closed');await page.locator('#save-status').click();
    await page.waitForFunction(()=>document.getElementById('detail-message').textContent.includes('Đã lưu'));
    await page.locator('#close-detail').click();await page.locator('#empty').waitFor({state:'visible'});
    await page.locator('[name=status]').selectOption('closed');await page.locator('#filters button[type=submit]').click();
    await page.waitForFunction(()=>document.querySelectorAll('#alert-rows tr').length===1);
    assert((await page.locator('#alert-rows').innerText()).includes('Đã xử lý'));
    console.log('Checked persisted status and empty state.');
    await page.locator('#reset-filters').click();await page.waitForFunction(()=>document.querySelectorAll('#alert-rows tr').length===20);
    fail=true;await page.locator('#refresh').click();await page.locator('#page-error').waitFor({state:'visible'});
    fail=false;await page.locator('#refresh').click();await page.locator('#page-error').waitFor({state:'hidden'});
    await page.screenshot({path:path.join(artifacts,'dashboard-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(artifacts,'dashboard-mobile.png'),fullPage:true});
    console.log('Mobile widths:',await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,inner:innerWidth})));
    await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth);
    await page.locator('#alert-rows button').first().click();await page.locator('#status-form').waitFor({state:'visible'});
    await page.screenshot({path:path.join(artifacts,'dashboard-mobile-detail.png'),fullPage:true});
    await page.keyboard.press('Escape');
    expired=true;await page.locator('#refresh').click();await page.locator('#login-view').waitFor({state:'visible'});
    assert((await page.locator('#login-error').innerText()).includes('hết hạn'));
    assert.equal(errors.length,0,errors.join('\n'));
    console.log('PASS: wrong login, login, pagination, filters, text/XSS safety, evidence, status persistence, empty state, API errors, mobile layout, session expiry.');
    await context.close();

    if(process.argv.includes('--live')) {
      const values=Object.fromEntries(fs.readFileSync(path.join(__dirname,'../../.env'),'utf8').split(/\r?\n/).filter(l=>l.includes('=')&&!l.trimStart().startsWith('#')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i).trim(),l.slice(i+1).trim().replace(/^(['"])(.*)\1$/,'$2')]}));
      const live=await browser.newContext({viewport:{width:1440,height:1000}});
      const p=await live.newPage();p.on('pageerror',e=>errors.push(e.message));
      await p.goto(baseURL+'/dashboard/');await login(p,values.ADMIN_EMAIL||'admin@minisoc.local',values.ADMIN_PASSWORD);
      assert.equal(await p.locator('#page-error').isVisible(),false);
      const response=await p.request.get(baseURL+'/dashboard/');
      assert(response.headers()['content-security-policy'].includes("script-src 'self'"));
      if(await p.locator('#alert-rows button').count()){await p.locator('#alert-rows button').first().click();await p.locator('#status-form').waitFor({state:'visible'});await p.locator('#close-detail').click();}
      await p.screenshot({path:path.join(artifacts,'dashboard-live.png'),fullPage:true});
      await p.locator('#logout').click();await p.locator('#login-view').waitFor({state:'visible'});
      assert.equal(errors.length,0,errors.join('\n'));
      console.log('PASS: live Docker login, alert reads, detail reads, security headers, logout. No live alert status changed.');
      await live.close();
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
