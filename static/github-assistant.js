// Offline helper for the GitHub Pages build. No user text is sent anywhere.
const guideTerms = [
  [/\bpqc\b|post[- ]quantum/i, 'PQC means post-quantum cryptography: methods designed to resist attacks from future large-scale quantum computers.'],
  [/\bml[- ]kem\b/i, 'ML-KEM is the NIST FIPS 203 key-encapsulation standard for helping two systems establish a shared secret.'],
  [/\bml[- ]dsa\b/i, 'ML-DSA is the NIST FIPS 204 digital-signature standard.'],
  [/\bslh[- ]dsa\b/i, 'SLH-DSA is the NIST FIPS 205 stateless hash-based digital-signature standard.'],
  [/\bx\.?509\b|certificate|\bpki\b/i, 'X.509 is a common certificate format used in public-key infrastructure. A certificate reference alone does not identify the public-key algorithm inside it.'],
  [/\brsa\b/i, 'RSA is a public-key cryptography family used for tasks such as key establishment or signatures. A sufficiently capable future quantum computer could threaten it.'],
  [/\becdsa\b/i, 'ECDSA is an elliptic-curve digital-signature method. ML-DSA and SLH-DSA are purpose-matched PQC signature standards to evaluate.'],
  [/\becc\b|\becdh\b|elliptic curve/i, 'ECC means elliptic-curve cryptography. ECDH uses it for key establishment; ML-KEM is a PQC key-establishment standard to evaluate.'],
  [/\baes\b/i, 'AES is symmetric encryption. Its quantum impact differs from public-key crypto; the prototype assesses key size separately.'],
  [/\btls\b/i, 'TLS protects data in transit. A text reference does not show which cipher suite was negotiated, so check runtime settings.'],
  [/mosca|x\s*\+\s*y|threat horizon/i, 'The Mosca-style check compares X (data lifetime) + Y (migration time) with Z (assumed threat horizon). X+Y ≥ Z is a planning signal, not a prediction.'],
  [/data lifetime|retention/i, 'Data lifetime is how long information needs protection. The demo estimates this from filenames; a real assessment asks data owners.'],
  [/\bcbom\b|cyclonedx/i, 'The inventory is CBOM-inspired: a simplified list of crypto references and evidence. It does not claim CycloneDX schema compliance.'],
  [/risk|criticality|priority/i, 'Risk priorities are estimates using filename-based lifetime, migration and impact hints with the X+Y vs Z scenario. Confirm the assumptions with system owners.'],
  [/\bzip\b|upload/i, 'ZIP files are read in your browser. The scanner only checks supported source/config text, applies size and path checks, and never executes uploaded code.'],
  [/report|pdf/i, 'The report view lets you print or save an assessment as PDF. It is a prototype summary, not an audit certificate.'],
];
let pageGuideWelcomed = false;
const guidePanel = document.getElementById('guidePanel');
const guideMessages = document.getElementById('guideMessages');
const guideInput = document.getElementById('guideInput');
const guideContext = document.getElementById('guideContext');
let guideSelected = '';
function guideSay(text, role='bot') {
  const item=document.createElement('div'); item.className=`guide-message ${role}`; item.textContent=text;
  guideMessages.appendChild(item); guideMessages.scrollTop=guideMessages.scrollHeight;
}
function guideOpen(context='') {
  guidePanel.classList.remove('hidden'); document.getElementById('guideToggle').classList.add('is-open');
  if(!pageGuideWelcomed){guideSay('Hello! I’m Aegis Guide ✨ Click a term, select some text, ask about this page, or tell me which feature to open.');pageGuideWelcomed=true;}
  if(context){guideSelected=context;guideContext.textContent=`Selected: “${context.slice(0,105)}${context.length>105?'…':''}”`;guideContext.classList.remove('hidden');}
  guideInput.focus();
}
function guideNavigate(id,label){if(typeof go==='function')go(id);return `Done — I opened ${label}.`;}
function guideAnswer(question,context='') {
  const q=question.toLowerCase();
  if(/\b(run|start)\b.*\bdemo\b|demo scan/.test(q)){
    guideNavigate('sc','Discovery Scanner');
    const button=[...document.querySelectorAll('#main button')].find(b=>/demo.*medivault|medivault.*demo/i.test(b.textContent));
    if(button)button.click();
    return 'Starting the synthetic MediVault demo scan.';
  }
  if(/download.*report|report.*download/.test(q)){
    guideNavigate('rp','Reports');
    setTimeout(()=>{const button=[...document.querySelectorAll('#main button')].find(b=>/pdf|download/i.test(b.textContent));if(button)button.click();},100);
    return 'I opened Reports and started the print/save-as-PDF action.';
  }
  if(/\b(open|show|go to|take me|navigate|switch to)\b/.test(q)){
    if(/inventory|finding|crypto list|cbom/.test(q))return guideNavigate('inv','Cryptographic Inventory');
    if(/risk|mosca/.test(q))return guideNavigate('rk','Risk Assessment');
    if(/simulat|scenario|quantum threat/.test(q))return guideNavigate('sim','Threat Simulator');
    if(/advisor|recommend|pqc/.test(q))return guideNavigate('adv','PQC Advisor');
    if(/migration|roadmap/.test(q))return guideNavigate('rm','Migration Roadmap');
    if(/report|pdf/.test(q))return guideNavigate('rp','Reports');
    if(/scanner|upload|scan page/.test(q))return guideNavigate('sc','Discovery Scanner');
    if(/overview|home/.test(q))return guideNavigate('ov','Overview');
  }
  const searched=context||question;
  for(const [pattern,answer] of guideTerms)if(pattern.test(searched))return answer;
  if(context)return `You selected “${context.slice(0,90)}${context.length>90?'…':''}”. I don’t have a built-in explanation for that exact phrase yet. Try RSA, X.509, AES, TLS, Mosca, CBOM, ML-KEM, ML-DSA or SLH-DSA.`;
  if(/\b(what can you|help|how do i|what is aegisq)\b/.test(q))return 'AegisQ discovers readable crypto references, assesses their planning priority, simulates X+Y vs Z, and suggests PQC migration directions. Try “open risk assessment” or “run the demo scan”.';
  return 'I can explain AegisQ topics and navigate this page. Try “What is TLS?”, “explain Mosca”, “open the simulator”, or “run the demo scan”. I use built-in guidance and work offline.';
}
function guideAsk(question,context=''){
  if(!question.trim()&&!context)return;
  const shown=question.trim()||`Explain: “${context}”`;guideSay(shown,'user');
  const answer=guideAnswer(shown,context);setTimeout(()=>guideSay(answer),100);
  guideInput.value='';guideSelected='';guideContext.classList.add('hidden');
}
document.getElementById('guideToggle').addEventListener('click',()=>{
  if(!guidePanel.classList.contains('hidden')){guidePanel.classList.add('hidden');document.getElementById('guideToggle').classList.remove('is-open');return;}
  const selected=window.getSelection()?.toString().trim()||'';guideOpen(selected);if(selected)guideAsk('',selected);
});
document.getElementById('guideClose').addEventListener('click',()=>{guidePanel.classList.add('hidden');document.getElementById('guideToggle').classList.remove('is-open');});
document.getElementById('guideForm').addEventListener('submit',(event)=>{event.preventDefault();guideAsk(guideInput.value,guideSelected);});
document.querySelectorAll('.guide-quick button').forEach((button)=>button.addEventListener('click',()=>guideAsk(button.dataset.ask)));
function guideWordAt(event){let range;if(document.caretRangeFromPoint)range=document.caretRangeFromPoint(event.clientX,event.clientY);else if(document.caretPositionFromPoint){const p=document.caretPositionFromPoint(event.clientX,event.clientY);if(p){range=document.createRange();range.setStart(p.offsetNode,p.offset);range.collapse(true);}}if(!range||range.startContainer.nodeType!==Node.TEXT_NODE)return'';const t=range.startContainer.textContent;let a=range.startOffset,b=a;while(a>0&&/[\w.+-]/.test(t[a-1]))a--;while(b<t.length&&/[\w.+-]/.test(t[b]))b++;return t.slice(a,b).trim();}
document.getElementById('main').addEventListener('click',(event)=>{if(event.target.closest('button,input,select,textarea,a,label,.guide-widget'))return;const selected=window.getSelection()?.toString().trim()||guideWordAt(event);if(selected.length>1){guideOpen(selected);guideAsk('',selected);}});
