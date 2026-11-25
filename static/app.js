let current = null;
let scenario = {x: 15, y: 4, z: 12};
let simulationRequest = 0;
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const COLORS = {Critical: '#ff6c82', High: '#ffb65b', Moderate: '#54b7fa', Low: '#5be0b3', 'Needs review': '#b69bff'};

function toast(message) {
  const element = $('#toast'); element.textContent = message; element.classList.add('show');
  setTimeout(() => element.classList.remove('show'), 3200);
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function showView(name) {
  $$('.view').forEach((view) => view.classList.toggle('hidden', view.id !== name));
  $$('.nav').forEach((button) => button.classList.toggle('active', button.dataset.view === name));
  const titles = {overview:'Security overview', scanner:'Discovery scanner', inventory:'Cryptographic inventory', risk:'Risk assessment', simulator:'Quantum threat simulator', roadmap:'PQC advisor', migration:'Migration roadmap', reports:'Assessment report'};
  $('#title').textContent = titles[name] || 'AegisQ'; $('#crumb').textContent = name.toUpperCase();
}
$$('.nav').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
$$('[data-goto]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.goto)));

function renderBars(id, entries, colors = ['#39b8e9','#37d9ce','#ab8fff','#ffb65b','#5be0b3']) {
  const target = $(id);
  if (!entries.length) { target.innerHTML = '<div class="chart-empty">No matching findings.</div>'; return; }
  const max = Math.max(1, ...entries.map((entry) => entry[1]));
  target.innerHTML = entries.map(([label, value], index) => `<div class="bar-row"><span title="${escapeHtml(label)}">${escapeHtml(label)}</span><div class="bar-track"><i style="width:${Math.max(4, value/max*100)}%;background:${colors[index%colors.length]}"></i></div><b>${value}</b></div>`).join('');
}
function renderMatrix(assets, horizon) {
  const target = $('#moscaMatrix'); $('#riskHorizonBadge').textContent = `Z = ${horizon} YEARS`;
  if (!assets.length) { target.textContent = 'Run a scan to plot findings.'; target.classList.add('empty'); return; }
  target.classList.remove('empty');
  const algorithms = ['RSA','ECC','ECDSA','TLS','X.509','AES'];
  const maxX = Math.max(horizon + 5, 20, ...assets.map((a) => a.mosca_total_years || 0));
  const x0=88,x1=705,y0=25,row=34,xpos=(value)=>x0+(Math.min(maxX,value)/maxX)*(x1-x0);
  const dots = assets.map((a) => {
    const rowIndex = Math.max(0, algorithms.indexOf(a.algorithm));
    const title = `${a.id} · ${a.algorithm} · ${a.component} · X+Y ${a.mosca_total_years}y vs Z ${horizon}y · ${a.priority}`;
    return `<circle cx="${xpos(a.mosca_total_years)}" cy="${y0+rowIndex*row}" r="7" fill="${COLORS[a.priority]||'#b69bff'}" stroke="#07111f" stroke-width="2"><title>${escapeHtml(title)}</title></circle>`;
  }).join('');
  const labels=algorithms.map((name,index)=>`<text x="78" y="${y0+index*row+4}" text-anchor="end" fill="#91a8ba" font-size="10">${name}</text><line x1="88" x2="705" y1="${y0+index*row+13}" y2="${y0+index*row+13}" stroke="#20364b"/>`).join('');
  const ticks=[0,Math.round(maxX/4),Math.round(maxX/2),Math.round(maxX*3/4),maxX].filter((v,i,a)=>a.indexOf(v)===i);
  const tickSvg=ticks.map((value)=>`<line x1="${xpos(value)}" x2="${xpos(value)}" y1="13" y2="224" stroke="#294156"/><text x="${xpos(value)}" y="244" text-anchor="middle" fill="#91a8ba" font-size="9">${value}</text>`).join('');
  target.innerHTML=`<svg class="mosca-svg" viewBox="0 0 740 258" role="img" aria-label="Mosca-style plot of data lifetime plus migration time compared with the threat horizon">${tickSvg}<rect x="${xpos(horizon)}" y="10" width="${Math.max(0,x1-xpos(horizon))}" height="215" fill="#ff6c82" opacity=".08"/><line x1="${xpos(horizon)}" x2="${xpos(horizon)}" y1="10" y2="225" stroke="#ff6c82" stroke-dasharray="5 4" stroke-width="2"/><text x="${Math.min(690,xpos(horizon)+4)}" y="20" fill="#ff9cab" font-size="9">Z=${horizon}</text>${labels}${dots}<text x="705" y="257" text-anchor="end" fill="#91a8ba" font-size="10">X + Y (years) →</text></svg>`;
}
function render(data) {
  current = data;
  const s = data.summary;
  $('#total').textContent=s.total; $('#vuln').textContent=s.quantum_vulnerable; $('#critical').textContent=s.critical;
  $('#algorithmCount').textContent=s.algorithms_detected; $('#algorithmNames').textContent=s.algorithms.join(' · ') || 'none detected';
  $('#avg').textContent=s.average_risk; $('#moscaCount').textContent=s.mosca_triggered;
  $('#mixCount').textContent=s.total;
  const counts=s.priorities || {};
  const order=['Critical','High','Moderate','Low','Needs review'];
  let start=0; const stops=[];
  for (const priority of order) { const end=start+(s.total ? (counts[priority]||0)/s.total*100 : 0); stops.push(`${COLORS[priority]} ${start}% ${end}%`); start=end; }
  $('#mixRing').style.setProperty('--mix',`conic-gradient(${stops.join(',')})`);
  $('#mixLegend').innerHTML=order.map((p)=>`<div class="legend-row"><i class="dot ${p==='Needs review'?'review':p.toLowerCase()}"></i><span>${p}</span><b>${counts[p]||0}</b></div>`).join('');

  const sorted=[...data.assets].sort((a,b)=>b.risk_score-a.risk_score);
  $('#preview').innerHTML=sorted.length?sorted.slice(0,5).map((a)=>`<div class="factor"><span class="factor-icon">${escapeHtml(a.algorithm)}</span><div><b>${escapeHtml(a.component)}</b><small>${escapeHtml(a.evidence.file)}:${a.evidence.line} · X+Y ${a.mosca_total_years}y</small></div><span class="pill ${a.priority==='Needs review'?'Review':escapeHtml(a.priority)}">${escapeHtml(a.priority)} · ${a.risk_score}</span></div>`).join(''):'No cryptographic references found in the readable files.';

  $('#inventoryTable').classList.remove('empty');
  $('#inventoryTable').innerHTML=data.assets.length?`<table class="table"><thead><tr><th>ID</th><th>ALGORITHM / PURPOSE</th><th>COMPONENT</th><th>DATA</th><th>X + Y vs Z</th><th>CONF.</th><th>PRIORITY</th><th>FILE EVIDENCE</th></tr></thead><tbody>${data.assets.map((a)=>`<tr><td>${escapeHtml(a.id)}</td><td><b>${escapeHtml(a.algorithm)}</b><br><code>${escapeHtml(a.purpose)}</code></td><td>${escapeHtml(a.component)}<br><code>${escapeHtml(a.criticality)} impact</code></td><td>${a.data_lifetime_years}y lifetime</td><td>${a.data_lifetime_years}+${a.migration_time_years} vs ${a.threat_horizon_years}y<br><code>${a.mosca_triggered?'window reaches Z':'window before Z'}</code></td><td>${Math.round(a.confidence*100)}%</td><td><span class="pill ${a.priority==='Needs review'?'Review':escapeHtml(a.priority)}">${escapeHtml(a.priority)} · ${a.risk_score}</span></td><td class="evidence"><code>${escapeHtml(a.evidence.file)}:${a.evidence.line}</code><br>${escapeHtml(a.evidence.excerpt)}</td></tr>`).join('')}</tbody></table>`:'<div class="empty">No matching crypto references found.</div>';

  renderBars('#algoBars',Object.entries(data.assets.reduce((map,a)=>(map[a.algorithm]=(map[a.algorithm]||0)+1,map),{})));
  renderBars('#componentBars',Object.entries(data.assets.reduce((map,a)=>(map[a.component]=(map[a.component]||0)+1,map),{})));
  renderBars('#lifetimeBars',[
    ['≤ 5 years',data.assets.filter(a=>a.data_lifetime_years<=5).length],
    ['6–10 years',data.assets.filter(a=>a.data_lifetime_years>5&&a.data_lifetime_years<=10).length],
    ['11+ years',data.assets.filter(a=>a.data_lifetime_years>10).length],
  ],['#5be0b3','#ffb65b','#ff6c82']);
  renderMatrix(data.assets,s.threat_horizon_years);
  $('#recommendations').innerHTML=data.recommendations.length?data.recommendations.map((r)=>`<div class="rec"><b>${escapeHtml(r.detected)}</b><strong>${escapeHtml(r.recommendation)}<br><small>${escapeHtml(r.purpose)}</small></strong><small>${escapeHtml(r.action)}</small></div>`).join(''):'No findings yet.';
  $('#roadmapFocus').textContent=`Current scan: ${s.mosca_triggered} public-key finding(s) have X + Y ≥ Z. Confirm these estimates with data and system owners.`;
  $('#reportSummary').textContent=`${s.total} references across ${s.algorithms_detected} algorithm families; ${s.critical} critical and ${s.mosca_triggered} public-key Mosca-window triggers at Z = ${s.threat_horizon_years} years.`;
  $('#reportBtn').disabled=false; $('#inventoryReportBtn').disabled=false; $('#reportInlineBtn').disabled=false;
}

function updateScanLog(data) {
  const unique=[...new Set(data.assets.map(a=>a.evidence.file))];
  const lines=['✔ Source/configuration text read in memory.',`✔ ${unique.length} file(s) contained crypto references.`,...data.assets.slice(0,12).map(a=>`› ${a.algorithm} · ${a.evidence.file}:${a.evidence.line} · ${a.priority}`),`✔ ${data.summary.total} evidence-linked references added to simplified CBOM-inspired inventory.`];
  $('#scanLog').innerHTML=lines.map(line=>`<div>${escapeHtml(line)}</div>`).join('')||'<div>Scan complete. No references found.</div>';
  $('#scanState').textContent='Scan complete';$('#scanDetail').textContent=`${data.summary.total} reference(s) · ${data.summary.algorithms_detected} algorithm families`;
  $('#scanProgress').style.width='100%';
}
async function scan(url,options={}) {
  $('#scanState').textContent='Inspecting readable files…';$('#scanDetail').textContent='Checking crypto patterns, evidence, and project context.';$('#scanProgress').style.width='58%';
  toast('Scanning readable source and configuration files…');
  try { const response=await fetch(url,options);const data=await response.json();if(!response.ok)throw Error(data.error||'Scan failed');render(data);updateScanLog(data);toast(`Scan complete · ${data.summary.total} references found`); }
  catch(error){$('#scanState').textContent='Scan could not finish';$('#scanDetail').textContent=error.message;$('#scanProgress').style.width='0';toast(error.message)}
}
function runDemo(){showView('scanner');scan(`/api/demo?z=${scenario.z}`)}
$('#demoBtn').addEventListener('click',runDemo);$('#scannerDemoBtn').addEventListener('click',runDemo);
$('#zipInput').addEventListener('change',(event)=>{const file=event.target.files[0];if(!file)return;const form=new FormData();form.append('file',file);form.append('z',scenario.z);showView('scanner');scan('/api/scan',{method:'POST',body:form});event.target.value=''});

async function downloadReport(){if(!current)return;try{const response=await fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(current)});if(!response.ok)throw Error('Could not create the report');const blob=await response.blob(),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='aegisq-assessment.pdf';link.click();URL.revokeObjectURL(link.href);toast('Assessment report downloaded')}catch(error){toast(error.message)}}
['#reportBtn','#inventoryReportBtn','#reportInlineBtn'].forEach((selector)=>$(selector).addEventListener('click',downloadReport));

async function refreshRiskForHorizon() {
  if(!current||current.summary.threat_horizon_years===scenario.z)return;
  try {const response=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project:current.project,assets:current.assets,z:scenario.z})});const data=await response.json();if(response.ok)render(data)}catch(_error){toast('Could not refresh risk view')}
}
async function simulate() {
  const requestId=++simulationRequest;
  ['x','y','z'].forEach((key)=>{scenario[key]=+$('#'+key).value;$('#'+key+'v').textContent=scenario[key]});
  try {const response=await fetch('/api/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(scenario)});const data=await response.json();if(requestId!==simulationRequest)return;
    $('#urgency').textContent=data.window_coverage;$('#urgencyFill').style.width=data.window_coverage+'%';$('#simLabel').textContent=data.label;$('#xy').textContent=data.classical_x_plus_y;$('#zout').textContent=data.quantum_z;$('#explanation').textContent=data.explanation;
    clearTimeout(simulate.assessTimer);simulate.assessTimer=setTimeout(refreshRiskForHorizon,180);
  }catch(_error){$('#simLabel').textContent='Scenario unavailable'}
}
$$('#x,#y,#z').forEach((input)=>input.addEventListener('input',simulate));simulate();
$('#clock').textContent=new Intl.DateTimeFormat(undefined,{hour:'2-digit',minute:'2-digit'}).format(new Date());

// Offline page helper. User text is matched to built-in explanations and is never sent to a service.
const guideGlossary=[
 [/\b(?:pqc|post[- ]quantum cryptograph\w*)\b/i,'PQC means post-quantum cryptography: methods designed to resist attacks from future large-scale quantum computers. This page helps plan where to review current cryptography.'],
 [/\bml[- ]kem\b/i,'ML-KEM is the NIST FIPS 203 key-encapsulation standard for helping two systems establish a shared secret.'],
 [/\bml[- ]dsa\b/i,'ML-DSA is the NIST FIPS 204 digital-signature standard. It is used to create and verify signatures.'],
 [/\bslh[- ]dsa\b/i,'SLH-DSA is the NIST FIPS 205 stateless hash-based digital-signature standard. The advisor lists it as another signature direction to evaluate.'],
 [/\b(?:x\.?509|certificate|pki)\b/i,'X.509 is a common certificate format used in public-key infrastructure. A certificate reference alone does not tell us which key algorithm is inside; check the certificate and CA/PKI tools.'],
 [/\b(?:rsa|rsa-\d+)\b/i,'RSA is a public-key cryptography family used for tasks such as key establishment and signatures. A sufficiently capable future quantum computer could threaten it.'],
 [/\b(?:ecdsa|elliptic curve digital signature)\b/i,'ECDSA is a digital-signature method based on elliptic curves. ML-DSA and SLH-DSA are purpose-matched PQC signature standards to evaluate.'],
 [/\b(?:ecc|ecdh|ecdhe|elliptic curve)\b/i,'ECC means elliptic-curve cryptography. ECDH/ECDHE use it for key establishment. ML-KEM is a PQC key-establishment standard to evaluate for transition planning.'],
 [/\b(?:aes|aes[- ]?(?:128|192|256))\b/i,'AES is symmetric encryption. Its quantum impact differs from public-key crypto; the prototype reviews key size and key management separately.'],
 [/\btls\b/i,'TLS protects data in transit. A text reference does not reveal the negotiated cipher suite or prove runtime configuration, so the finding is marked for review.'],
 [/\bmosca\b|x\s*\+\s*y|threat horizon/i,'The Mosca-style planning check compares X (data lifetime) + Y (migration time) with Z (assumed threat horizon). X+Y ≥ Z is a planning signal, not a probability or arrival-date prediction.'],
 [/harvest[- ]now|decrypt[- ]later|hndl/i,'“Harvest now, decrypt later” describes saving encrypted data today in case it can be decrypted in the future. It matters when sensitive data needs protection for many years.'],
 [/data lifetime|retention/i,'Data lifetime is how long information needs protection. These values are inferred from filenames in the demo and should be confirmed with the data owner.'],
 [/confidence|needs review/i,'Confidence is a simple text-match heuristic. TLS and X.509 need more information about the negotiated suite or certificate key, so they are flagged for review.'],
 [/\bcbom\b|cyclonedx/i,'This is a CBOM-inspired inventory: a list of crypto references with purposes and evidence. It is a simplified prototype and does not claim CycloneDX schema compliance.'],
 [/risk score|critical priority|risk assessment/i,'Priorities combine a text-match confidence, algorithm family, filename-based criticality and the X+Y vs Z planning window. They are planning estimates, not audit findings.'],
 [/\bzip\b|upload/i,'The ZIP scanner reads supported source/configuration text in memory, limits the upload to 10 MB and 500 entries, rejects unsafe paths, and never executes uploaded code.'],
 [/\breport\b|pdf/i,'The PDF report summarizes evidence, priorities, X+Y vs Z context, and PQC directions. It is a prototype report, not a compliance certificate.'],
];
let guideWelcomed=false,guideContextText='';
const guidePanel=$('#guidePanel'),guideMessages=$('#guideMessages'),guideContext=$('#guideContext'),guideInput=$('#guideInput');
function guideMessage(text,kind='bot'){const bubble=document.createElement('div');bubble.className=`guide-message ${kind}`;bubble.textContent=text;guideMessages.appendChild(bubble);guideMessages.scrollTop=guideMessages.scrollHeight}
function guideOpen(context=''){guidePanel.classList.remove('hidden');$('#guideToggle').classList.add('is-open');if(!guideWelcomed){guideMessage('Hello! I’m Aegis Guide ✨ Click a term, select text, ask a question, or tell me which feature to open.');guideWelcomed=true}if(context){guideContextText=context;guideContext.textContent=`Selected: “${context.slice(0,110)}${context.length>110?'…':''}”`;guideContext.classList.remove('hidden')}guideInput.focus()}
function guideClose(){guidePanel.classList.add('hidden');$('#guideToggle').classList.remove('is-open')}
function guideReply(question,context=''){
  const q=question.toLowerCase();
  if(/\b(open|show|go to|take me|navigate|switch to)\b/.test(q)){
    let view=null,label='';
    if(/inventory|finding|crypto list|cbom/.test(q)){view='inventory';label='Cryptographic Inventory'}else if(/risk|mosca/.test(q)){view='risk';label='Risk Assessment'}else if(/simulat|scenario|quantum threat/.test(q)){view='simulator';label='Threat Simulator'}else if(/advisor|recommend|pqc/.test(q)){view='roadmap';label='PQC Advisor'}else if(/migration|roadmap/.test(q)){view='migration';label='Migration Roadmap'}else if(/report|pdf/.test(q)){view='reports';label='Assessment Report'}else if(/scanner|upload|scan page/.test(q)){view='scanner';label='Discovery Scanner'}else if(/overview|home/.test(q)){view='overview';label='Overview'}
    if(view){showView(view);return `Done — I opened ${label}.`}
  }
  if(/\b(run|start)\b.*\bdemo\b|demo scan/.test(q)){runDemo();return 'Starting the synthetic MediVault demo scan.'}
  if(/download.*report|report.*download/.test(q)){if(!current)return 'First run a scan, then ask me again to download the report.';showView('reports');downloadReport();return 'I opened Reports and started the current assessment PDF download.'}
  const lookup=context||question;for(const [pattern,answer] of guideGlossary){if(pattern.test(lookup))return answer}
  if(context){const heading=document.querySelector('.view:not(.hidden) h1,.view:not(.hidden) h2')?.textContent||'this section';return `You selected “${context.slice(0,90)}${context.length>90?'…':''}” in ${heading}. I don’t have a built-in explanation for that exact phrase yet. Ask me about RSA, X.509, AES, TLS, Mosca, data lifetime, CBOM, ML-KEM, ML-DSA or SLH-DSA.`}
  if(/\b(what can you|help|how do i|what does this page|what is aegisq)\b/.test(q))return 'AegisQ scans readable source/config references, shows an evidence-linked inventory, compares X+Y against a shared Z horizon, and offers PQC planning directions. Try “open risk assessment” or “run the demo scan”.';
  return 'I can explain AegisQ terms and features or navigate the page. Try “What is X.509?”, “explain Mosca”, “open migration roadmap”, or “download report”. I use built-in page guidance and work offline.';
}
function guideAsk(question,context=''){if(!question.trim()&&!context)return;const visible=question.trim()||`Explain: “${context}”`;guideMessage(visible,'user');const answer=guideReply(visible,context);setTimeout(()=>guideMessage(answer),120);guideInput.value='';guideContextText='';guideContext.classList.add('hidden')}
$('#guideToggle').addEventListener('click',()=>{if(!guidePanel.classList.contains('hidden')){guideClose();return}const selected=window.getSelection()?.toString().trim();guideOpen(selected);if(selected)guideAsk('',selected)});
$('#guideClose').addEventListener('click',guideClose);$('#guideForm').addEventListener('submit',(event)=>{event.preventDefault();guideAsk(guideInput.value,guideContextText)});
$$('.guide-quick button').forEach((button)=>button.addEventListener('click',()=>guideAsk(button.dataset.ask)));
function clickedWord(event){let range;if(document.caretRangeFromPoint)range=document.caretRangeFromPoint(event.clientX,event.clientY);else if(document.caretPositionFromPoint){const pos=document.caretPositionFromPoint(event.clientX,event.clientY);if(pos){range=document.createRange();range.setStart(pos.offsetNode,pos.offset);range.collapse(true)}}if(!range||range.startContainer.nodeType!==Node.TEXT_NODE)return '';const text=range.startContainer.textContent,offset=range.startOffset;let start=offset,end=offset;while(start>0&&/[\w.+-]/.test(text[start-1]))start--;while(end<text.length&&/[\w.+-]/.test(text[end]))end++;return text.slice(start,end).trim()}
document.querySelector('main').addEventListener('click',(event)=>{if(event.target.closest('button,input,select,textarea,a,label,.guide-widget'))return;const selected=window.getSelection()?.toString().trim();const term=selected||clickedWord(event);if(term.length>1){guideOpen(term);guideAsk('',term)}});
