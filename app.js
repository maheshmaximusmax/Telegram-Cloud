// ═══════════════════════════════════════════════════════════
// TeleVault — Encrypted Cloud Storage powered by Telegram
// ═══════════════════════════════════════════════════════════

// ─── STORAGE KEYS ───
const SK = {
  vault: 'tv_vault',      // { salt, verifier, iv }
  config: 'tv_config',    // { botToken, chatId, ghUser, ghRepo, ghToken }
  meta: 'tv_meta',        // { files: {}, folders: [] }
  theme: 'tv_theme',
  view: 'tv_view',        // 'grid' | 'list'
  ghSha: 'tv_gh_sha',     // SHA of cloud_meta.json on GitHub
};

function store(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch(e){} }
function load(k) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : null; } catch(e) { return null; } }

// ─── STATE ───
let cryptoKey = null;        // Derived AES-256-GCM key (in memory only)
let currentFolder = '/';
let viewMode = load(SK.view) || 'grid';
let selectedFiles = new Set();
let ctxTarget = null;        // file ID for context menu
let allMeta = null;          // { files: {}, folders: ['/'] }
let searchQuery = '';
let dragCounter = 0;

// ═══════════════════════════════════════════════════════════
// CRYPTO — Web Crypto API (PBKDF2 + AES-256-GCM)
// ═══════════════════════════════════════════════════════════

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i/2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function randomBytes(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(key, data) {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: bytesToHex(iv), data: new Uint8Array(encrypted) };
}

async function decryptData(key, ivHex, encryptedData) {
  const iv = hexToBytes(ivHex);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedData);
  return new Uint8Array(decrypted);
}

// Create a verifier: encrypt known string to confirm password later
async function createVerifier(key) {
  const data = new TextEncoder().encode('TELEVAULT_VERIFY_OK');
  const { iv, data: enc } = await encryptData(key, data);
  return { iv, data: btoa(String.fromCharCode(...enc)) };
}

async function checkVerifier(key, verifier) {
  try {
    const encBytes = Uint8Array.from(atob(verifier.data), c => c.charCodeAt(0));
    const dec = await decryptData(key, verifier.iv, encBytes);
    return new TextDecoder().decode(dec) === 'TELEVAULT_VERIFY_OK';
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════════
// TELEGRAM BOT API
// ═══════════════════════════════════════════════════════════

function tgAPI(method, params) {
  const cfg = load(SK.config) || {};
  return `https://api.telegram.org/bot${cfg.botToken}/${method}`;
}

async function tgSendDocument(fileBlob, filename, caption) {
  const cfg = load(SK.config) || {};
  const fd = new FormData();
  fd.append('chat_id', cfg.chatId);
  fd.append('document', fileBlob, filename);
  if (caption) fd.append('caption', caption);
  
  const r = await fetch(tgAPI('sendDocument'), { method: 'POST', body: fd });
  const j = await r.json().catch(() => ({}));
  
  if (!r.ok || !j.ok) {
    throw new Error(j.description || `Telegram upload failed: ${r.status}`);
  }
  return j.result.document.file_id;
}

async function tgGetFileUrl(fileId) {
  const cfg = load(SK.config) || {};
  const r = await fetch(tgAPI('getFile') + `?file_id=${fileId}`);
  const j = await r.json();
  if (!j.ok) throw new Error(j.description || 'getFile failed');
  return `https://api.telegram.org/file/bot${cfg.botToken}/${j.result.file_path}`;
}

async function tgDownloadFile(fileId) {
  const url = await tgGetFileUrl(fileId);
  const r = await fetch(url);
  if (!r.ok) throw new Error('Download failed');
  return new Uint8Array(await r.arrayBuffer());
}

async function tgTestConnection() {
  const cfg = load(SK.config) || {};
  const r = await fetch(`https://api.telegram.org/bot${cfg.botToken}/getMe`);
  const j = await r.json();
  return j;
}

async function tgDeleteMessage(messageId) {
  const cfg = load(SK.config) || {};
  try {
    await fetch(tgAPI('deleteMessage'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: cfg.chatId, message_id: messageId })
    });
  } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// GITHUB API — Metadata Sync
// ═══════════════════════════════════════════════════════════

async function ghReadMeta() {
  const cfg = load(SK.config) || {};
  if (!cfg.ghUser || !cfg.ghRepo || !cfg.ghToken) return null;
  
  const url = `https://api.github.com/repos/${cfg.ghUser}/${cfg.ghRepo}/contents/cloud_meta.json`;
  const r = await fetch(url, {
    headers: { 'Authorization': `Bearer ${cfg.ghToken}`, 'Accept': 'application/vnd.github+json' }
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub read error: ${r.status}`);
  const j = await r.json();
  store(SK.ghSha, j.sha);
  return JSON.parse(atob(j.content.replace(/\n/g, '')));
}

async function ghWriteMeta(data) {
  const cfg = load(SK.config) || {};
  if (!cfg.ghUser || !cfg.ghRepo || !cfg.ghToken) return;
  
  const url = `https://api.github.com/repos/${cfg.ghUser}/${cfg.ghRepo}/contents/cloud_meta.json`;
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(data, null, 2))));
  const body = { message: 'TeleVault: sync metadata', content };
  
  const sha = load(SK.ghSha);
  if (sha) body.sha = sha;
  
  const r = await fetch(url, {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${cfg.ghToken}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.message || `GitHub write error: ${r.status}`);
  }
  const j = await r.json();
  store(SK.ghSha, j.content.sha);
}

// ═══════════════════════════════════════════════════════════
// META DATA MANAGEMENT
// ═══════════════════════════════════════════════════════════

const CHUNK_SIZE = 19 * 1024 * 1024; // 19MB per chunk (under 20MB download limit)

function getMeta() {
  if (!allMeta) allMeta = load(SK.meta) || { files: {}, folders: ['/'] };
  return allMeta;
}

function saveMeta() {
  store(SK.meta, allMeta);
  syncToGitHubQuiet();
}

function genId() { return Date.now().toString(36) + Math.random().toString(36).substr(2, 8); }

function getFileIcon(type, name) {
  if (!type) type = '';
  const ext = (name || '').split('.').pop().toLowerCase();
  if (type.startsWith('image/')) return '🖼️';
  if (type.startsWith('video/')) return '🎬';
  if (type.startsWith('audio/')) return '🎵';
  if (type === 'application/pdf' || ext === 'pdf') return '📕';
  if (type.includes('zip') || type.includes('rar') || type.includes('7z') || ext === 'zip' || ext === 'rar') return '📦';
  if (type.includes('word') || ext === 'doc' || ext === 'docx') return '📘';
  if (type.includes('excel') || type.includes('sheet') || ext === 'xls' || ext === 'xlsx' || ext === 'csv') return '📗';
  if (type.includes('presentation') || ext === 'ppt' || ext === 'pptx') return '📙';
  if (type.startsWith('text/') || ['txt','md','json','xml','html','css','js','py','java','c','cpp','h','rs','go','ts','jsx','tsx','yaml','yml','toml','ini','cfg','log','sh','bat','sql'].includes(ext)) return '📄';
  if (ext === 'apk') return '📱';
  if (ext === 'exe' || ext === 'msi') return '💿';
  return '📎';
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
  return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
}

// ═══════════════════════════════════════════════════════════
// FILE OPERATIONS
// ═══════════════════════════════════════════════════════════

async function uploadFile(file, folder) {
  const id = genId();
  const meta = getMeta();
  
  // Show in upload panel
  showUploadItem(id, file.name, 'Encrypting...');
  
  try {
    // Read file
    updateUploadItem(id, 'Reading file...', 10);
    const fileData = new Uint8Array(await file.arrayBuffer());
    
    // Encrypt
    updateUploadItem(id, 'Encrypting...', 25);
    const { iv, data: encrypted } = await encryptData(cryptoKey, fileData);
    
    // Chunk and upload
    const totalChunks = Math.ceil(encrypted.length / CHUNK_SIZE) || 1;
    const chunkIds = [];
    
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, encrypted.length);
      const chunk = encrypted.slice(start, end);
      const pct = 30 + Math.floor((i / totalChunks) * 60);
      
      updateUploadItem(id, `Uploading chunk ${i + 1}/${totalChunks}...`, pct);
      
      const chunkBlob = new Blob([chunk], { type: 'application/octet-stream' });
      const chunkName = `tv_${id}_${i}.enc`;
      const fileId = await tgSendDocument(chunkBlob, chunkName, `🔐 TeleVault | ${file.name} | Chunk ${i+1}/${totalChunks}`);
      chunkIds.push(fileId);
    }
    
    // Save metadata
    meta.files[id] = {
      name: file.name,
      size: file.size,
      type: file.type || 'application/octet-stream',
      folder: folder || '/',
      iv: iv,
      chunks: chunkIds,
      uploadedAt: new Date().toISOString(),
      encryptedSize: encrypted.length
    };
    allMeta = meta;
    saveMeta();
    
    updateUploadItem(id, 'Done ✓', 100, true);
    toast(`✅ ${file.name} uploaded`, 'success');
    renderAll();
    
  } catch(err) {
    updateUploadItem(id, `Error: ${err.message}`, 0, false, true);
    toast(`❌ Upload failed: ${err.message}`, 'error');
    console.error('Upload error:', err);
  }
}

async function downloadFile(fileId) {
  const meta = getMeta();
  const file = meta.files[fileId];
  if (!file) return toast('File not found', 'error');
  
  toast(`📥 Downloading ${file.name}...`, 'info');
  
  try {
    // Download all chunks
    const chunks = [];
    for (let i = 0; i < file.chunks.length; i++) {
      const chunkData = await tgDownloadFile(file.chunks[i]);
      chunks.push(chunkData);
    }
    
    // Reassemble
    const totalLen = chunks.reduce((a, c) => a + c.length, 0);
    const encrypted = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      encrypted.set(chunk, offset);
      offset += chunk.length;
    }
    
    // Decrypt
    const decrypted = await decryptData(cryptoKey, file.iv, encrypted);
    
    // Save
    const blob = new Blob([decrypted], { type: file.type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast(`✅ ${file.name} downloaded`, 'success');
  } catch(err) {
    toast(`❌ Download failed: ${err.message}`, 'error');
    console.error('Download error:', err);
  }
}

async function deleteFile(fileId) {
  const meta = getMeta();
  const file = meta.files[fileId];
  if (!file) return;
  
  if (!confirm(`Delete "${file.name}" permanently? The encrypted data on Telegram will remain but metadata will be removed.`)) return;
  
  delete meta.files[fileId];
  allMeta = meta;
  saveMeta();
  selectedFiles.delete(fileId);
  renderAll();
  toast(`🗑 ${file.name} deleted`, 'info');
}

async function previewFile(fileId) {
  const meta = getMeta();
  const file = meta.files[fileId];
  if (!file) return;
  
  document.getElementById('preview-title').textContent = `👁 ${file.name}`;
  document.getElementById('preview-dl').onclick = () => downloadFile(fileId);
  
  const info = document.getElementById('preview-info');
  info.innerHTML = `
    <div class="pm-kv"><b>Name:</b> ${file.name}</div>
    <div class="pm-kv"><b>Size:</b> ${formatSize(file.size)}</div>
    <div class="pm-kv"><b>Type:</b> ${file.type}</div>
    <div class="pm-kv"><b>Uploaded:</b> ${new Date(file.uploadedAt).toLocaleString()}</div>
    <div class="pm-kv"><b>Chunks:</b> ${file.chunks.length}</div>
    <div class="pm-kv"><b>Encrypted:</b> ${formatSize(file.encryptedSize || file.size)}</div>
  `;
  
  const content = document.getElementById('preview-content');
  
  // For images and text, try to decrypt and preview
  if (file.type.startsWith('image/') || file.type.startsWith('text/') || file.type === 'application/json') {
    content.innerHTML = `<div style="text-align:center;padding:20px"><div class="spinner spinner-lg" style="color:var(--accent)"></div><div style="margin-top:8px;font-size:12px;color:var(--tx3)">Decrypting for preview...</div></div>`;
    openModal('preview-modal');
    
    try {
      const chunks = [];
      for (const cid of file.chunks) {
        chunks.push(await tgDownloadFile(cid));
      }
      const totalLen = chunks.reduce((a, c) => a + c.length, 0);
      const encrypted = new Uint8Array(totalLen);
      let off = 0;
      for (const c of chunks) { encrypted.set(c, off); off += c.length; }
      const decrypted = await decryptData(cryptoKey, file.iv, encrypted);
      
      if (file.type.startsWith('image/')) {
        const blob = new Blob([decrypted], { type: file.type });
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<img class="pm-img" src="${url}" alt="${file.name}">`;
      } else {
        const text = new TextDecoder().decode(decrypted);
        content.innerHTML = `<pre class="pm-text">${escapeHtml(text.substring(0, 50000))}</pre>`;
      }
    } catch(err) {
      content.innerHTML = `<div class="danger-box">Preview failed: ${err.message}</div>`;
    }
  } else {
    content.innerHTML = `
      <div style="text-align:center;padding:30px">
        <div style="font-size:48px;margin-bottom:8px">${getFileIcon(file.type, file.name)}</div>
        <div style="font-size:13px;color:var(--tx3)">Preview not available for this file type</div>
        <button class="btn btn-primary btn-sm" style="margin-top:12px" onclick="downloadFile('${fileId}');closeModal('preview-modal')">📥 Download to view</button>
      </div>
    `;
    openModal('preview-modal');
  }
}

function escapeHtml(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

// ═══════════════════════════════════════════════════════════
// UI RENDERING
// ═══════════════════════════════════════════════════════════

function renderAll() {
  renderBreadcrumb();
  renderFiles();
  renderFolders();
  renderCounts();
}

function getFilteredFiles() {
  const meta = getMeta();
  let files = Object.entries(meta.files);
  
  // Filter by current folder or virtual folder
  if (currentFolder === '/') {
    // Show all files in root
    files = files.filter(([_, f]) => f.folder === '/');
  } else if (currentFolder === '__recent') {
    files.sort((a, b) => new Date(b[1].uploadedAt) - new Date(a[1].uploadedAt));
    files = files.slice(0, 20);
  } else if (currentFolder === '__images') {
    files = files.filter(([_, f]) => f.type && f.type.startsWith('image/'));
  } else if (currentFolder === '__docs') {
    files = files.filter(([_, f]) => {
      const ext = f.name.split('.').pop().toLowerCase();
      return f.type === 'application/pdf' || f.type.includes('word') || f.type.includes('excel') || f.type.startsWith('text/') || ['doc','docx','pdf','txt','md','csv','xls','xlsx','ppt','pptx'].includes(ext);
    });
  } else if (currentFolder === '__videos') {
    files = files.filter(([_, f]) => f.type && (f.type.startsWith('video/') || f.type.startsWith('audio/')));
  } else {
    files = files.filter(([_, f]) => f.folder === currentFolder);
  }
  
  // Search
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    files = files.filter(([_, f]) => f.name.toLowerCase().includes(q));
  }
  
  // Sort
  const sort = document.getElementById('sort-select')?.value || 'date-desc';
  files.sort((a, b) => {
    switch (sort) {
      case 'name-asc': return a[1].name.localeCompare(b[1].name);
      case 'name-desc': return b[1].name.localeCompare(a[1].name);
      case 'date-desc': return new Date(b[1].uploadedAt) - new Date(a[1].uploadedAt);
      case 'date-asc': return new Date(a[1].uploadedAt) - new Date(b[1].uploadedAt);
      case 'size-desc': return b[1].size - a[1].size;
      case 'size-asc': return a[1].size - b[1].size;
      default: return 0;
    }
  });
  
  return files;
}

function renderFiles() {
  const area = document.getElementById('file-area');
  const files = getFilteredFiles();
  const meta = getMeta();
  
  // Show subfolders if we're in a real folder
  const subfolders = currentFolder.startsWith('__') ? [] : 
    meta.folders.filter(f => {
      if (f === currentFolder) return false;
      if (currentFolder === '/') return f !== '/' && f.split('/').filter(Boolean).length === 1;
      return f.startsWith(currentFolder + '/') && f.replace(currentFolder + '/', '').split('/').filter(Boolean).length === 1;
    });
  
  if (files.length === 0 && subfolders.length === 0) {
    area.innerHTML = `
      <div class="empty-state">
        <div class="es-icon">📂</div>
        <div class="es-title">${searchQuery ? 'No files found' : 'This folder is empty'}</div>
        <div class="es-sub">${searchQuery ? 'Try a different search term' : 'Upload files or create folders to get started. Your files are encrypted with AES-256 before upload.'}</div>
        ${!searchQuery ? '<button class="btn btn-primary" onclick="openUploadModal()">⬆ Upload Files</button>' : ''}
      </div>`;
    return;
  }
  
  if (viewMode === 'grid') {
    let html = '<div class="file-grid">';
    
    // Folders first
    for (const folder of subfolders) {
      const name = folder.split('/').filter(Boolean).pop();
      const count = Object.values(meta.files).filter(f => f.folder === folder).length;
      html += `
        <div class="file-card" ondblclick="navTo('${folder}')" onclick="navTo('${folder}')">
          <span class="fc-icon">📁</span>
          <div class="fc-name">${escapeHtml(name)}</div>
          <div class="fc-meta"><span>${count} files</span></div>
        </div>`;
    }
    
    // Files
    for (const [id, f] of files) {
      const sel = selectedFiles.has(id) ? ' selected' : '';
      html += `
        <div class="file-card${sel}" data-id="${id}" onclick="toggleSelect('${id}',event)" ondblclick="previewFile('${id}')" oncontextmenu="showCtx(event,'${id}')">
          <div class="fc-encrypt">🔒</div>
          <div class="fc-check">${sel ? '✓' : ''}</div>
          <span class="fc-icon">${getFileIcon(f.type, f.name)}</span>
          <div class="fc-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</div>
          <div class="fc-meta"><span>${formatSize(f.size)}</span><span>${formatDate(f.uploadedAt)}</span></div>
        </div>`;
    }
    
    html += '</div>';
    area.innerHTML = html;
  } else {
    let html = '<div class="file-list">';
    html += `<div class="file-list-header"><div></div><div>Name</div><div>Size</div><div>Type</div><div>Modified</div><div></div></div>`;
    
    // Folders
    for (const folder of subfolders) {
      const name = folder.split('/').filter(Boolean).pop();
      html += `<div class="file-list-row" ondblclick="navTo('${folder}')" onclick="navTo('${folder}')"><div></div><div class="fl-name"><span>📁</span><span>${escapeHtml(name)}</span></div><div class="fl-size">—</div><div class="fl-type">Folder</div><div class="fl-date">—</div><div></div></div>`;
    }
    
    // Files
    for (const [id, f] of files) {
      const sel = selectedFiles.has(id) ? ' selected' : '';
      const ext = f.name.split('.').pop().toUpperCase();
      html += `
        <div class="file-list-row${sel}" data-id="${id}" onclick="toggleSelect('${id}',event)" ondblclick="previewFile('${id}')" oncontextmenu="showCtx(event,'${id}')">
          <div class="fl-check" onclick="event.stopPropagation();toggleSelect('${id}')">${sel ? '✓' : ''}</div>
          <div class="fl-name"><span>${getFileIcon(f.type, f.name)}</span><span>${escapeHtml(f.name)}</span></div>
          <div class="fl-size">${formatSize(f.size)}</div>
          <div class="fl-type">${ext}</div>
          <div class="fl-date">${formatDate(f.uploadedAt)}</div>
          <div class="fl-actions"><button class="btn-icon" style="width:24px;height:24px;font-size:11px" onclick="event.stopPropagation();showCtx(event,'${id}')">⋮</button></div>
        </div>`;
    }
    
    html += '</div>';
    area.innerHTML = html;
  }
}

function renderBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  const title = document.getElementById('page-title');
  
  if (currentFolder.startsWith('__')) {
    const labels = { '__recent': '🕐 Recent', '__images': '🖼️ Images', '__docs': '📄 Documents', '__videos': '🎬 Videos' };
    title.textContent = labels[currentFolder] || currentFolder;
    bc.innerHTML = `<span onclick="navTo('/')">🏠 All Files</span><span class="bc-sep">›</span><span>${labels[currentFolder]}</span>`;
    return;
  }
  
  const parts = currentFolder.split('/').filter(Boolean);
  let html = `<span onclick="navTo('/')">🏠 All Files</span>`;
  let path = '';
  for (const part of parts) {
    path += '/' + part;
    const p = path;
    html += `<span class="bc-sep">›</span><span onclick="navTo('${p}')">${escapeHtml(part)}</span>`;
  }
  bc.innerHTML = html;
  title.textContent = parts.length ? parts[parts.length - 1] : 'All Files';
}

function renderFolders() {
  const meta = getMeta();
  const fl = document.getElementById('folder-list');
  const topFolders = meta.folders.filter(f => f !== '/' && f.split('/').filter(Boolean).length === 1);
  
  if (topFolders.length === 0) {
    fl.innerHTML = `<div style="font-size:11px;color:var(--tx3);padding:8px 10px">No folders yet</div>`;
    return;
  }
  
  fl.innerHTML = topFolders.map(f => {
    const name = f.split('/').filter(Boolean).pop();
    const active = currentFolder === f ? ' active' : '';
    const count = Object.values(meta.files).filter(file => file.folder === f).length;
    return `<div class="sidebar-item${active}" onclick="navTo('${f}')" data-folder="${f}"><span class="si-icon">📁</span>${escapeHtml(name)}<span class="si-count">${count}</span></div>`;
  }).join('');
  
  // Update upload folder select
  const sel = document.getElementById('upload-folder');
  if (sel) {
    sel.innerHTML = meta.folders.map(f => `<option value="${f}"${f === currentFolder ? ' selected' : ''}>${f === '/' ? '/ (Root)' : f}</option>`).join('');
  }
  const moveSel = document.getElementById('move-folder');
  if (moveSel) {
    moveSel.innerHTML = meta.folders.map(f => `<option value="${f}">${f === '/' ? '/ (Root)' : f}</option>`).join('');
  }
}

function renderCounts() {
  const meta = getMeta();
  const files = Object.values(meta.files);
  
  document.getElementById('count-all').textContent = files.length;
  document.getElementById('count-img').textContent = files.filter(f => f.type?.startsWith('image/')).length;
  document.getElementById('count-doc').textContent = files.filter(f => {
    const ext = f.name.split('.').pop().toLowerCase();
    return f.type === 'application/pdf' || f.type?.startsWith('text/') || ['doc','docx','pdf','txt','md','csv','xls','xlsx'].includes(ext);
  }).length;
  document.getElementById('count-vid').textContent = files.filter(f => f.type?.startsWith('video/') || f.type?.startsWith('audio/')).length;
  
  const totalSize = files.reduce((a, f) => a + (f.size || 0), 0);
  document.getElementById('storage-used').textContent = formatSize(totalSize);
  // Arbitrary cap display for visual (Telegram is unlimited)
  const pct = Math.min(totalSize / (2 * 1024 * 1024 * 1024) * 100, 100);
  document.getElementById('storage-pct').textContent = formatSize(totalSize);
  document.getElementById('storage-fill').style.width = Math.max(pct, 1) + '%';
  
  // Update sidebar active
  document.querySelectorAll('.sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.folder === currentFolder);
  });
}

// ═══════════════════════════════════════════════════════════
// UI INTERACTIONS
// ═══════════════════════════════════════════════════════════

function navTo(folder) {
  currentFolder = folder;
  selectedFiles.clear();
  hideCtx();
  renderAll();
}

function setView(mode, btn) {
  viewMode = mode;
  store(SK.view, mode);
  document.querySelectorAll('.view-toggle button').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderFiles();
}

function filterFiles() {
  searchQuery = document.getElementById('search-input').value.trim();
  renderFiles();
}

function sortFiles() { renderFiles(); }

function toggleSelect(id, e) {
  if (e) e.stopPropagation();
  if (selectedFiles.has(id)) selectedFiles.delete(id);
  else selectedFiles.add(id);
  renderFiles();
}

// Context menu
function showCtx(e, id) {
  e.preventDefault();
  e.stopPropagation();
  ctxTarget = id;
  const menu = document.getElementById('ctx-menu');
  menu.style.left = Math.min(e.clientX, window.innerWidth - 200) + 'px';
  menu.style.top = Math.min(e.clientY, window.innerHeight - 250) + 'px';
  menu.classList.add('show');
}
function hideCtx() { document.getElementById('ctx-menu').classList.remove('show'); }
function ctxAction(action) {
  hideCtx();
  if (!ctxTarget) return;
  const id = ctxTarget;
  switch (action) {
    case 'download': downloadFile(id); break;
    case 'preview': previewFile(id); break;
    case 'rename':
      const meta = getMeta();
      document.getElementById('rename-input').value = meta.files[id]?.name || '';
      openModal('rename-modal');
      document.getElementById('rename-input').focus();
      break;
    case 'move': openModal('move-modal'); break;
    case 'share':
      const m = getMeta();
      const f = m.files[id];
      if (f) {
        const shareInfo = `🔐 TeleVault Encrypted File\n📄 ${f.name}\n📦 ${formatSize(f.size)}\n🔗 Chunks: ${f.chunks.length}\n\nTo download: Use TeleVault with the same vault password.`;
        navigator.clipboard?.writeText(shareInfo);
        toast('📋 File info copied to clipboard', 'info');
      }
      break;
    case 'delete': deleteFile(id); break;
  }
}

function doRename() {
  if (!ctxTarget) return;
  const name = document.getElementById('rename-input').value.trim();
  if (!name) return toast('Name cannot be empty', 'error');
  const meta = getMeta();
  if (meta.files[ctxTarget]) {
    meta.files[ctxTarget].name = name;
    allMeta = meta;
    saveMeta();
    renderAll();
    toast('✏️ Renamed', 'success');
  }
  closeModal('rename-modal');
}

function doMove() {
  if (!ctxTarget) return;
  const folder = document.getElementById('move-folder').value;
  const meta = getMeta();
  if (meta.files[ctxTarget]) {
    meta.files[ctxTarget].folder = folder;
    allMeta = meta;
    saveMeta();
    renderAll();
    toast('📂 Moved', 'success');
  }
  closeModal('move-modal');
}

// Folder creation
function openNewFolder() { openModal('folder-modal'); document.getElementById('new-folder-name').value = ''; document.getElementById('new-folder-name').focus(); }
function createFolder() {
  const name = document.getElementById('new-folder-name').value.trim().replace(/[\/\\:*?"<>|]/g, '');
  if (!name) return toast('Folder name required', 'error');
  const meta = getMeta();
  const path = currentFolder.startsWith('__') ? '/' + name : (currentFolder === '/' ? '/' + name : currentFolder + '/' + name);
  if (meta.folders.includes(path)) return toast('Folder already exists', 'error');
  meta.folders.push(path);
  allMeta = meta;
  saveMeta();
  closeModal('folder-modal');
  renderAll();
  toast(`📁 Folder "${name}" created`, 'success');
}

// Upload
function openUploadModal() {
  const meta = getMeta();
  const sel = document.getElementById('upload-folder');
  sel.innerHTML = meta.folders.map(f => `<option value="${f}"${f === currentFolder && !currentFolder.startsWith('__') ? ' selected' : ''}>${f === '/' ? '/ (Root)' : f}</option>`).join('');
  openModal('upload-modal');
}

function handleFileSelect(e) {
  const files = e.target.files;
  if (!files.length) return;
  const folder = document.getElementById('upload-folder').value;
  closeModal('upload-modal');
  
  document.getElementById('upload-panel').classList.add('show');
  
  for (const file of files) {
    uploadFile(file, folder);
  }
  e.target.value = '';
}

// Upload progress UI
function showUploadItem(id, name, status) {
  const list = document.getElementById('upload-list');
  const icon = getFileIcon('', name);
  list.insertAdjacentHTML('afterbegin', `
    <div class="upload-item" id="up-${id}">
      <div class="ui-icon">${icon}</div>
      <div class="ui-info">
        <div class="ui-name">${escapeHtml(name)}</div>
        <div class="ui-status">${status}</div>
        <div class="ui-bar"><div class="ui-bar-fill" style="width:0%"></div></div>
      </div>
    </div>`);
  updateUploadCount();
}

function updateUploadItem(id, status, pct, done, error) {
  const el = document.getElementById(`up-${id}`);
  if (!el) return;
  el.querySelector('.ui-status').textContent = status;
  el.querySelector('.ui-bar-fill').style.width = pct + '%';
  if (done) {
    el.querySelector('.ui-bar-fill').style.background = 'var(--green)';
    el.querySelector('.ui-status').style.color = 'var(--green)';
  }
  if (error) {
    el.querySelector('.ui-bar-fill').style.background = 'var(--red)';
    el.querySelector('.ui-status').style.color = 'var(--red)';
  }
  updateUploadCount();
}

function updateUploadCount() {
  const items = document.querySelectorAll('.upload-item');
  document.getElementById('upload-count').textContent = items.length ? `(${items.length})` : '';
}

// ═══════════════════════════════════════════════════════════
// DRAG & DROP
// ═══════════════════════════════════════════════════════════

document.addEventListener('dragenter', e => { e.preventDefault(); dragCounter++; document.getElementById('dropzone').classList.add('active'); });
document.addEventListener('dragleave', e => { e.preventDefault(); dragCounter--; if (dragCounter <= 0) { dragCounter = 0; document.getElementById('dropzone').classList.remove('active'); } });
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => {
  e.preventDefault();
  dragCounter = 0;
  document.getElementById('dropzone').classList.remove('active');
  
  if (!cryptoKey) return;
  const files = e.dataTransfer.files;
  if (!files.length) return;
  
  document.getElementById('upload-panel').classList.add('show');
  const folder = currentFolder.startsWith('__') ? '/' : currentFolder;
  for (const file of files) uploadFile(file, folder);
});

// ═══════════════════════════════════════════════════════════
// MODALS & TOAST
// ═══════════════════════════════════════════════════════════

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.addEventListener('click', () => hideCtx());

// Close modals on backdrop click
document.querySelectorAll('.modal-bg').forEach(bg => {
  bg.addEventListener('click', e => { if (e.target === bg) bg.classList.remove('open'); });
});

let toastTimer;
function toast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast toast-${type || 'info'} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ═══════════════════════════════════════════════════════════
// THEME
// ═══════════════════════════════════════════════════════════

function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  store(SK.theme, t);
  const btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = t === 'dark' ? '🌙' : '☀️';
}
function toggleTheme() { setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'); }

// ═══════════════════════════════════════════════════════════
// PASSWORD TOGGLE
// ═══════════════════════════════════════════════════════════

function togglePW(id, btn) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  if (btn) btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

// ═══════════════════════════════════════════════════════════
// SETUP FLOW
// ═══════════════════════════════════════════════════════════

function showSetupErr(msg) {
  const el = document.getElementById('setup-err');
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

function setupUpdateDots(step) {
  document.querySelectorAll('#setup-dots .step-dot').forEach((d, i) => {
    d.className = 'step-dot' + (i < step ? ' done' : '') + (i === step ? ' active' : '');
  });
}

// Password strength
document.addEventListener('DOMContentLoaded', () => {
  const pw = document.getElementById('setup-pw');
  if (pw) pw.addEventListener('input', () => {
    const v = pw.value;
    let s = 0;
    if (v.length >= 8) s++;
    if (v.length >= 12) s++;
    if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
    if (/[0-9]/.test(v)) s++;
    if (/[^A-Za-z0-9]/.test(v)) s++;
    const colors = ['var(--red)', 'var(--red)', 'var(--yellow)', 'var(--yellow)', 'var(--green)', 'var(--green)'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
    const fill = document.getElementById('setup-str');
    fill.style.width = (s / 5 * 100) + '%';
    fill.style.background = colors[s];
    document.getElementById('setup-str-txt').textContent = v ? labels[s] : '';
  });
});

function setupStep2() {
  const pw = document.getElementById('setup-pw').value;
  const pw2 = document.getElementById('setup-pw2').value;
  showSetupErr('');
  if (pw.length < 8) return showSetupErr('Password must be at least 8 characters');
  if (pw !== pw2) return showSetupErr('Passwords do not match');
  
  document.getElementById('setup-s1').style.display = 'none';
  document.getElementById('setup-s2').style.display = 'block';
  setupUpdateDots(1);
}

function setupStep3() {
  const bot = document.getElementById('setup-bot').value.trim();
  const chat = document.getElementById('setup-chat').value.trim();
  showSetupErr('');
  if (!bot) return showSetupErr('Bot Token is required');
  if (!chat) return showSetupErr('Storage Chat ID is required');
  
  document.getElementById('setup-s2').style.display = 'none';
  document.getElementById('setup-s3').style.display = 'block';
  setupUpdateDots(2);
}

function setupBack(step) {
  showSetupErr('');
  if (step === 1) {
    document.getElementById('setup-s2').style.display = 'none';
    document.getElementById('setup-s1').style.display = 'block';
    setupUpdateDots(0);
  } else if (step === 2) {
    document.getElementById('setup-s3').style.display = 'none';
    document.getElementById('setup-s2').style.display = 'block';
    setupUpdateDots(1);
  }
}

async function finishSetup(skipGH) {
  showSetupErr('');
  const pw = document.getElementById('setup-pw').value;
  const bot = document.getElementById('setup-bot').value.trim();
  const chat = document.getElementById('setup-chat').value.trim();
  
  try {
    // Derive key
    const salt = randomBytes(32);
    const key = await deriveKey(pw, salt);
    const verifier = await createVerifier(key);
    
    // Save vault info
    store(SK.vault, { salt: bytesToHex(salt), verifier });
    
    // Save config
    const cfg = { botToken: bot, chatId: chat };
    if (!skipGH) {
      cfg.ghUser = document.getElementById('setup-ghu').value.trim();
      cfg.ghRepo = document.getElementById('setup-ghr').value.trim();
      cfg.ghToken = document.getElementById('setup-ght').value.trim();
    }
    store(SK.config, cfg);
    
    // Initialize metadata
    allMeta = { files: {}, folders: ['/'] };
    store(SK.meta, allMeta);
    
    // Try GitHub sync
    if (cfg.ghUser && cfg.ghRepo && cfg.ghToken) {
      try { await ghWriteMeta(allMeta); } catch(e) { console.warn('GitHub sync failed:', e); }
    }
    
    // Enter app
    cryptoKey = key;
    showScreen('app');
    renderAll();
    toast('🎉 Vault created! Start uploading files.', 'success');
    
  } catch(err) {
    showSetupErr('Setup failed: ' + err.message);
  }
}

// ═══════════════════════════════════════════════════════════
// UNLOCK FLOW
// ═══════════════════════════════════════════════════════════

async function doUnlock() {
  const pw = document.getElementById('unlock-pw').value;
  const errEl = document.getElementById('unlock-err');
  errEl.style.display = 'none';
  
  if (!pw) { errEl.textContent = 'Enter your password'; errEl.style.display = 'block'; return; }
  
  const btn = document.getElementById('unlock-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Unlocking...';
  
  try {
    const vault = load(SK.vault);
    const salt = hexToBytes(vault.salt);
    const key = await deriveKey(pw, salt);
    const ok = await checkVerifier(key, vault.verifier);
    
    if (!ok) {
      errEl.textContent = '🔒 Incorrect password. Try again.';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.innerHTML = '🔓 Unlock Vault';
      return;
    }
    
    cryptoKey = key;
    
    // Try to sync from GitHub
    const cfg = load(SK.config) || {};
    if (cfg.ghUser && cfg.ghRepo && cfg.ghToken) {
      try {
        const remote = await ghReadMeta();
        if (remote) {
          allMeta = remote;
          store(SK.meta, allMeta);
        }
      } catch(e) { console.warn('GitHub sync on unlock:', e); }
    }
    
    showScreen('app');
    renderAll();
    toast('🔓 Vault unlocked', 'success');
    
  } catch(err) {
    errEl.textContent = 'Unlock failed: ' + err.message;
    errEl.style.display = 'block';
  }
  
  btn.disabled = false;
  btn.innerHTML = '🔓 Unlock Vault';
}

function lockVault() {
  cryptoKey = null;
  allMeta = null;
  showScreen('unlock');
  document.getElementById('unlock-pw').value = '';
}

// ═══════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════

function openSettings() {
  const cfg = load(SK.config) || {};
  document.getElementById('s-bot').value = cfg.botToken || '';
  document.getElementById('s-chat').value = cfg.chatId || '';
  document.getElementById('s-ghu').value = cfg.ghUser || '';
  document.getElementById('s-ghr').value = cfg.ghRepo || '';
  document.getElementById('s-ght').value = cfg.ghToken || '';
  openModal('settings-modal');
}

function settingsTab(tab, btn) {
  document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`settings-${tab}`).classList.add('active');
}

function saveSettings() {
  const cfg = {
    botToken: document.getElementById('s-bot').value.trim(),
    chatId: document.getElementById('s-chat').value.trim(),
    ghUser: document.getElementById('s-ghu').value.trim(),
    ghRepo: document.getElementById('s-ghr').value.trim(),
    ghToken: document.getElementById('s-ght').value.trim(),
  };
  store(SK.config, cfg);
  toast('💾 Settings saved', 'success');
}

async function testTelegram() {
  const res = document.getElementById('tg-test-res');
  res.innerHTML = '<span class="spinner" style="color:var(--accent)"></span> Testing...';
  try {
    saveSettings();
    const r = await tgTestConnection();
    if (r.ok) {
      res.innerHTML = `<span style="color:var(--green)">✅ Connected! Bot: @${r.result.username}</span>`;
    } else {
      res.innerHTML = `<span style="color:var(--red)">❌ Failed: ${r.description}</span>`;
    }
  } catch(err) {
    res.innerHTML = `<span style="color:var(--red)">❌ ${err.message}</span>`;
  }
}

async function syncToGitHub() {
  const res = document.getElementById('gh-sync-res');
  res.innerHTML = '<span class="spinner" style="color:var(--accent)"></span> Syncing...';
  try {
    saveSettings();
    await ghWriteMeta(getMeta());
    res.innerHTML = `<span style="color:var(--green)">✅ Synced successfully!</span>`;
    toast('🔄 Synced to GitHub', 'success');
  } catch(err) {
    res.innerHTML = `<span style="color:var(--red)">❌ ${err.message}</span>`;
  }
}

// Quiet sync (background, no UI)
let syncTimer = null;
function syncToGitHubQuiet() {
  clearTimeout(syncTimer);
  syncTimer = setTimeout(async () => {
    const cfg = load(SK.config) || {};
    if (cfg.ghUser && cfg.ghRepo && cfg.ghToken) {
      try { await ghWriteMeta(getMeta()); } catch(e) { console.warn('Background sync failed:', e); }
    }
  }, 2000);
}

async function changePassword() {
  const oldPw = document.getElementById('s-oldpw').value;
  const newPw = document.getElementById('s-newpw').value;
  const newPw2 = document.getElementById('s-newpw2').value;
  
  if (!oldPw || !newPw) return toast('Fill in all password fields', 'error');
  if (newPw.length < 8) return toast('New password must be at least 8 characters', 'error');
  if (newPw !== newPw2) return toast('New passwords do not match', 'error');
  
  try {
    // Verify old password
    const vault = load(SK.vault);
    const oldSalt = hexToBytes(vault.salt);
    const oldKey = await deriveKey(oldPw, oldSalt);
    const ok = await checkVerifier(oldKey, vault.verifier);
    if (!ok) return toast('Current password is incorrect', 'error');
    
    // Create new vault with new password
    const newSalt = randomBytes(32);
    const newKey = await deriveKey(newPw, newSalt);
    const newVerifier = await createVerifier(newKey);
    
    store(SK.vault, { salt: bytesToHex(newSalt), verifier: newVerifier });
    cryptoKey = newKey;
    
    toast('🔑 Password changed successfully', 'success');
    document.getElementById('s-oldpw').value = '';
    document.getElementById('s-newpw').value = '';
    document.getElementById('s-newpw2').value = '';
  } catch(err) {
    toast('Password change failed: ' + err.message, 'error');
  }
}

// ═══════════════════════════════════════════════════════════
// SCREEN MANAGEMENT
// ═══════════════════════════════════════════════════════════

function showScreen(name) {
  document.getElementById('setup-screen').style.display = 'none';
  document.getElementById('unlock-screen').style.display = 'none';
  document.getElementById('app').style.display = 'none';
  
  if (name === 'setup') document.getElementById('setup-screen').style.display = 'flex';
  else if (name === 'unlock') document.getElementById('unlock-screen').style.display = 'flex';
  else if (name === 'app') document.getElementById('app').style.display = 'block';
}

// ═══════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════

function init() {
  // Apply theme
  const theme = load(SK.theme) || 'dark';
  setTheme(theme);
  
  // Check if vault exists
  const vault = load(SK.vault);
  if (!vault) {
    showScreen('setup');
  } else {
    showScreen('unlock');
    // Auto-focus password field
    setTimeout(() => document.getElementById('unlock-pw')?.focus(), 100);
  }
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-bg.open').forEach(m => m.classList.remove('open'));
    hideCtx();
    selectedFiles.clear();
    renderFiles();
  }
  if (e.key === 'Delete' && selectedFiles.size > 0 && cryptoKey) {
    if (confirm(`Delete ${selectedFiles.size} selected file(s)?`)) {
      const meta = getMeta();
      for (const id of selectedFiles) delete meta.files[id];
      allMeta = meta;
      saveMeta();
      selectedFiles.clear();
      renderAll();
      toast('🗑 Files deleted', 'info');
    }
  }
  // Ctrl+U for upload
  if (e.ctrlKey && e.key === 'u' && cryptoKey) {
    e.preventDefault();
    openUploadModal();
  }
});

// Download preview file helper
function downloadPreviewFile() {
  if (ctxTarget) downloadFile(ctxTarget);
}

init();
