/* interface.js - sidebar behavior + chat logic */

/* ---------- Config / state ---------- */
const FAQ_ITEMS = [
  "What is phishing?",
  "How to protect from phishing?",
  "How to report phishing?",
  "How does the URL classifier work?",
  "What is 2FA and why enable it?"
];
const CATEGORIES = ["Email scams","SMS/OTP scams","Fake websites","Social engineering","Training"];

const sidebar = document.getElementById('sidebar');
const pinBtn = document.getElementById('pinBtn');
const menu = document.getElementById('menu');

let pinned = false;            // manual collapse/pin state
let rememberedOpen = new Set(); // (not used: kept for extension)
let conversations = [];        // session only
let activeIdx = null;

/* ---------- Helpers ---------- */
function el(q){ return document.querySelector(q); }
function els(q){ return Array.from(document.querySelectorAll(q)); }
function now(){ return new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); }
function downloadFile(name, content){ const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([content], {type:'application/json'})); a.download = name; a.click(); }

/* ---------- Populate FAQ & categories ---------- */
function populateStatic(){
  const faqList = document.getElementById('faqList');
  FAQ_ITEMS.forEach(q=>{
    const a = document.createElement('a');
    a.href = '#';
    a.className = 'dropdown-item';
    a.textContent = q;
    a.addEventListener('click', (ev)=>{ ev.preventDefault(); sendPredefined(q); });
    faqList.appendChild(a);
  });

  const catList = document.getElementById('catList');
  CATEGORIES.forEach(c=>{
    const d = document.createElement('div');
    d.className = 'cat';
    d.textContent = c;
    d.addEventListener('click', ()=>{ quickCategory(c); });
    catList.appendChild(d);
  });
}

/* ---------- Sidebar behavior (A2,B1,C1,D1,X2) ---------- */

// helper close all dropdowns
function closeAllDropdowns(){
  els('.section').forEach(s=> s.classList.remove('open'));
  els('.dropdown').forEach(d=> d.setAttribute('aria-hidden','true'));
}

// update composer left (in case of CSS layout requiring it)
function updateComposer(){ /* optional: not needed when layout uses flex; placeholder */ }

// Pin/unpin (manual collapse only)
pinBtn.addEventListener('click', ()=>{
  pinned = !pinned;
  if(pinned){
    sidebar.classList.remove('collapsed');
    pinBtn.setAttribute('aria-pressed','true');
  } else {
    sidebar.classList.add('collapsed');
    pinBtn.setAttribute('aria-pressed','false');
    closeAllDropdowns(); // close all when collapsed
  }
  updateComposer();
});

// wire section titles (only one open at a time)
els('.section').forEach(sec=>{
  const title = sec.querySelector('.section-title');
  const id = sec.dataset.id || '';
  if(!title) return;

  title.addEventListener('click', (ev)=>{
    // New chat: start a new conversation instead of opening a panel
    if(id === 'newchat'){
      startNewChat();
      return;
    }

    // If collapsed, expand & pin so user can see content (this avoids "click does nothing")
    if(sidebar.classList.contains('collapsed')){
      sidebar.classList.remove('collapsed');
      pinned = true;
      pinBtn.setAttribute('aria-pressed','true');
    }

    // Only one dropdown open at a time (C1)
    const willOpen = !sec.classList.contains('open');
    closeAllDropdowns();
    if(willOpen){
      sec.classList.add('open');
      const dd = sec.querySelector('.dropdown');
      if(dd) dd.setAttribute('aria-hidden','false');
    }
    updateComposer();
  });
});

/* ---------- Chat: session-only conversations, typing indicator ---------- */

function renderMessages(){
  const messages = document.getElementById('messages');
  messages.innerHTML = '';
  if(activeIdx === null) return;
  const conv = conversations[activeIdx];
  conv.messages.forEach(m=>{
    if(m.from === 'user'){
      const b = document.createElement('div'); b.className = 'msg user'; b.innerHTML = `<div>${escapeHtml(m.text)}</div><div class="meta">${m.time}</div>`;
      messages.appendChild(b);
    } else if(m.from === 'bot'){
      if(m.status === 'typing'){
        // typing placeholder with dots
        const wrap = document.createElement('div'); wrap.className = 'msg bot typing';
        wrap.innerHTML = `<div class="typing"><div class="dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div></div><div class="meta">${m.time}</div>`;
        messages.appendChild(wrap);
      } else {
        const b = document.createElement('div'); b.className = 'msg bot'; b.innerHTML = `<div>${escapeHtml(m.text)}</div><div class="meta">${m.time}</div>`;
        messages.appendChild(b);
      }
    }
  });
  messages.scrollTop = messages.scrollHeight;
}

function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function startNewChat(){
  const conv = { id: Date.now(), title: 'Chat '+(conversations.length+1), messages: [] };
  conversations.unshift(conv);
  activeIdx = 0;
  renderMessages();
  appendBot("New chat started. Ask about phishing or paste a URL to check.");
}

function appendUser(text){
  if(activeIdx === null) startNewChat();
  conversations[activeIdx].messages.push({ from:'user', text, time: now(), status:'sent' });
  renderMessages();
}

function appendBot(text, status='sent'){
  if(activeIdx === null) startNewChat();
  const conv = conversations[activeIdx];
  // remove typing placeholder if present
  for(let i=conv.messages.length-1;i>=0;i--){
    if(conv.messages[i].from==='bot' && conv.messages[i].status==='typing'){
      conv.messages.splice(i,1);
    }
  }
  conv.messages.push({ from:'bot', text, time: now(), status });
  renderMessages();
}

function setBotTyping(on=true){
  if(activeIdx === null) startNewChat();
  const conv = conversations[activeIdx];
  if(on){
    // avoid duplicate typing placeholders
    const last = conv.messages[conv.messages.length-1];
    if(!last || last.from!=='bot' || last.status!=='typing'){
      conv.messages.push({ from:'bot', text:'', time: now(), status:'typing' });
    } else {
      last.time = now();
    }
  } else {
    for(let i=conv.messages.length-1;i>=0;i--){
      if(conv.messages[i].from==='bot' && conv.messages[i].status==='typing'){
        conv.messages.splice(i,1);
      }
    }
  }
  renderMessages();
}

/* ---------- Send to backend (chat_api) ---------- */
async function sendToServer(text){
  try{
    setBotTyping(true);
    const resp = await fetch('/chat_api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ message: text }) });
    const j = await resp.json();
    setBotTyping(false);
    const reply = j.reply || j.result || JSON.stringify(j);
    appendBot(reply,'sent');
  }catch(err){
    setBotTyping(false);
    appendBot('Error contacting server: ' + err, 'sent');
  }
}

/* composer submit handler */
function appOnSend(e){
  if(e) e.preventDefault();
  const el = document.getElementById('inputText');
  const text = el.value.trim();
  if(!text) return false;
  appendUser(text);
  el.value = '';
  // If you want to treat plain URL specially, you could call /api/check_url directly here.
  sendToServer(text);
  return false;
}

/* Quick send predefined FAQ question */
function sendPredefined(q){
  appendUser(q);
  sendToServer(q);
}

/* Quick category action */
function quickCategory(cat){
  appendUser(`Show resources for ${cat}`);
  sendToServer(`Resources for ${cat}`);
}

/* Quick URL check UI */
document.getElementById('btnQuickCheck').addEventListener('click', async ()=>{
  const url = document.getElementById('quickUrl').value.trim();
  const out = document.getElementById('quickOut');
  if(!url){ out.textContent = 'Enter a URL first'; return; }
  out.textContent = 'Checking…';
  try{
    const r = await fetch('/api/check_url', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ url }) });
    const j = await r.json();
    out.textContent = j.message || JSON.stringify(j);
  }catch(e){
    out.textContent = 'Error: ' + e;
  }
});
document.getElementById('btnClearQuick').addEventListener('click', ()=>{ document.getElementById('quickUrl').value=''; document.getElementById('quickOut').textContent=''; });

/* Admin: reload model (prompt token) */
document.getElementById('btnReload').addEventListener('click', async ()=>{
  const token = prompt('Enter admin token to reload:');
  if(!token) return;
  const out = document.getElementById('adminResp');
  out.textContent = 'Reloading...';
  try{
    const r = await fetch('/admin/reload-model', { method:'POST', headers:{ 'Authorization':'Bearer '+token }});
    const j = await r.json();
    out.textContent = JSON.stringify(j, null, 2);
    // refresh model info
    await loadModelInfo();
  }catch(e){
    out.textContent = 'Reload error: ' + e;
  }
});

/* Export chats */
document.getElementById('btnExport').addEventListener('click', exportChats);
document.getElementById('btnSave').addEventListener('click', exportChats);
function exportChats(){
  const payload = { exported_at: new Date().toISOString(), conversations };
  downloadFile('astral_chats_' + Date.now() + '.json', JSON.stringify(payload, null, 2));
}

/* Load model info */
async function loadModelInfo(){
  try{
    const r = await fetch('/admin/model-info');
    const j = await r.json();
    const box = document.getElementById('modelInfo');
    box.textContent = JSON.stringify(j, null, 2);
    // optional: open model panel if loaded
    if(j.model_loaded){
      const sec = document.querySelector('[data-id="modelinfo"]');
      if(sec) {
        closeAllDropdowns();
        sec.classList.add('open');
        const dd = sec.querySelector('.dropdown');
        if(dd) dd.setAttribute('aria-hidden','false');
      }
    }
  }catch(e){
    const box = document.getElementById('modelInfo');
    box.textContent = 'Error loading model info: ' + e;
  }
}

/* Init */
populateStatic();
startNewChat();
loadModelInfo();
closeAllDropdowns();
