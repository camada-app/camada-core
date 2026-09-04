// The 403 challenge page: one self-contained HTML document, no external assets, no-store.
// The inline solver hunts a counter whose SHA-256(`${nonce}.${counter}`) starts with 16 zero
// bits (~65k hashes, tens of milliseconds), fills the hidden form and submits it. The form POST
// means the browser follows the verify endpoint's 302 natively, so the cookie is set and the
// original URL is re-fetched without any fetch/CORS/cookie subtleties.
//
// The page carries its own SHA-256 rather than calling crypto.subtle: subtle is undefined on
// non-secure origins (plain http on a LAN host), and 65k awaited digests would be slow anyway.
import { POW_BITS, escapeAttr, escapeScript } from './format.js';

export interface ChallengePageOptions {
  nonce: string;
  action: string;   // the verify endpoint path
  to: string;       // where to send the browser afterwards (already run through safeReturnTo)
  bits?: number;
}

// FIPS 180-4 round constants (cube roots of the first 64 primes).
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// One SHA-256 over an ASCII string. Returns the 8 state words; the solver reads H[0] only
// (16 leading zero bits === H[0] >>> 16 === 0, which is exactly the server's powOk(hex, 16)).
const SOLVER = `
var __camadaK=[${K.map((k) => '0x' + k.toString(16)).join(',')}];
function __camadaRr(x,n){return (x>>>n)|(x<<(32-n))}
function __camadaSha256Words(msg){
  var K=__camadaK,rr=__camadaRr,l=msg.length,wl=(((l+9+63)>>6)<<4),M=new Uint32Array(wl),i;
  for(i=0;i<l;i++)M[i>>2]|=(msg.charCodeAt(i)&255)<<(24-(i%4)*8);
  M[l>>2]|=0x80<<(24-(l%4)*8);
  M[wl-1]=l*8;
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var W=new Uint32Array(64),bi,t;
  for(bi=0;bi<wl;bi+=16){
    for(t=0;t<16;t++)W[t]=M[bi+t];
    for(t=16;t<64;t++){var x=W[t-15],y=W[t-2];
      W[t]=(W[t-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[t-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0}
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(t=0;t<64;t++){
      var t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[t]+W[t])>>>0;
      var t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0}
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0}
  return H}
function __camadaSha256Hex(msg){
  var H=__camadaSha256Words(msg),s='',i;
  for(i=0;i<8;i++)s+=('00000000'+H[i].toString(16)).slice(-8);
  return s}
`;

export function challengePage(o: ChallengePageOptions): string {
  const bits = Math.min(32, Math.max(1, o.bits ?? POW_BITS));   // shift 32-bits must stay in range
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>
:root{color-scheme:light}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa;color:#1a1a1a;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:28rem;padding:2rem;text-align:center}
h1{font-size:1.25rem;margin:0 0 .5rem}
p{margin:.25rem 0;color:#555}
.bar{margin:1.5rem auto 0;width:12rem;height:4px;border-radius:2px;background:#e5e5e5;overflow:hidden}
.bar i{display:block;height:100%;width:30%;background:#1a1a1a;animation:camada-slide 1.1s ease-in-out infinite}
@keyframes camada-slide{0%{transform:translateX(-120%)}100%{transform:translateX(400%)}}
</style></head>
<body>
<main>
<h1>Checking your browser</h1>
<p id="camada-msg">This takes a moment. It runs entirely in your browser.</p>
<noscript><p>JavaScript is required to continue.</p></noscript>
<div class="bar"><i></i></div>
</main>
<form id="camada-f" method="POST" action="${escapeAttr(o.action)}">
<input type="hidden" name="nonce" value="${escapeAttr(o.nonce)}">
<input type="hidden" name="solution" id="camada-s">
<input type="hidden" name="to" value="${escapeAttr(o.to)}">
</form>
<script>${SOLVER}
(function(){
  if(typeof window==='undefined'||window.__camadaAutostart===false)return;
  var nonce=${escapeScript(o.nonce)},shift=${32 - bits};
  function go(){
    for(var n=0;n<5000000;n++){
      if((__camadaSha256Words(nonce+'.'+n)[0]>>>shift)===0){
        document.getElementById('camada-s').value=String(n);
        document.getElementById('camada-f').submit();
        return}}
    document.getElementById('camada-msg').textContent='Could not complete the check. Please reload.'}
  setTimeout(go,30);
})();
</script>
</body></html>`;
}
