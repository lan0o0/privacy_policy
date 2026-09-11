import fs from 'fs';
import vm from 'vm';
import crypto from 'crypto';

const html = fs.readFileSync('/workspace/privacy-policy-manager/index.html','utf8');
const m = html.match(/<script id="app-js">([\s\S]*?)<\/script>/);
if(!m){console.log('SCRIPT NOT FOUND');process.exit(1)}
try{new vm.Script(m[1]);console.log('JS SYNTAX OK')}catch(e){console.log('SYNTAX ERROR: '+e.message);process.exit(1)}

const sec = m[1].match(/\/\* =+ 密码学[\s\S]*?(?=\/\* =+ 会话)/);
if(!sec){console.log('CRYPTO SECTION NOT FOUND');process.exit(1)}
const ctx = {
  TextEncoder, TextDecoder,
  b64: b=>Buffer.from(b).toString('base64'),
  b64d: s=>new Uint8Array(Buffer.from(s,'base64')),
  crypto:{getRandomValues:a=>crypto.randomFillSync(a)}, // 无 subtle → 强制走 JS 后备
  console,
};
vm.createContext(ctx);
vm.runInContext(sec[0] + "\nglobalThis.OUT={sha256js,sha1js,hmacBytes,pbkdf2Js,te,envEnc,envDec,CR};", ctx);
const C = ctx.OUT;
const hex = b=>Buffer.from(b).toString('hex');
let pass=0, fail=0;
const t=(name,got,want)=>{if(got===want){pass++}else{fail++;console.log('FAIL '+name+'\n got='+got+'\nwant='+want)}};

t('sha256(abc)',hex(C.sha256js(new TextEncoder().encode('abc'))),crypto.createHash('sha256').update('abc').digest('hex'));
t('sha256(empty)',hex(C.sha256js(new Uint8Array(0))),crypto.createHash('sha256').update('').digest('hex'));
t('sha256(long)',hex(C.sha256js(new TextEncoder().encode('a'.repeat(1003)))),crypto.createHash('sha256').update('a'.repeat(1003)).digest('hex'));
t('sha1(abc)',hex(C.sha1js(new TextEncoder().encode('abc'))),crypto.createHash('sha1').update('abc').digest('hex'));
t('sha1(empty)',hex(C.sha1js(new Uint8Array(0))),crypto.createHash('sha1').update('').digest('hex'));
t('sha1(long)',hex(C.sha1js(new TextEncoder().encode('x'.repeat(2001)))),crypto.createHash('sha1').update('x'.repeat(2001)).digest('hex'));
const key=crypto.randomBytes(32);
t('hmac256',hex(C.hmacBytes(C.sha256js,new Uint8Array(key),new TextEncoder().encode('hello'))),crypto.createHmac('sha256',key).update('hello').digest('hex'));
t('hmac1',hex(C.hmacBytes(C.sha1js,new Uint8Array(key),new TextEncoder().encode('hello'))),crypto.createHmac('sha1',key).update('hello').digest('hex'));
const longKey=crypto.randomBytes(100);
t('hmac256-longkey',hex(C.hmacBytes(C.sha256js,new Uint8Array(longKey),new TextEncoder().encode('data'))),crypto.createHmac('sha256',longKey).update('data').digest('hex'));
let s=Date.now();
const dk=C.pbkdf2Js('Test@12345',new Uint8Array(Buffer.from('0123456789abcdef')),150000,64);
const ms=Date.now()-s;
t('pbkdf2-150k',hex(dk),crypto.pbkdf2Sync('Test@12345','0123456789abcdef',150000,64,'sha256').toString('hex'));
console.log('pbkdf2Js 150k iterations took '+ms+'ms');

const k=C.CR.rand(32);
const box=await C.envEnc(new Uint8Array(k),'秘密secret-测试123');
const dec=await C.envDec(new Uint8Array(k),box);
t('env-roundtrip',dec,'秘密secret-测试123');
box.c=box.c.slice(0,-2)+Buffer.from('ZZ').toString('base64');
let tampered=false; try{await C.envDec(new Uint8Array(k),box)}catch(e){tampered=true}
t('env-tamper-detect',String(tampered),'true');
console.log('CRYPTO TESTS: '+pass+' passed, '+fail+' failed');
process.exit(fail?1:0);
