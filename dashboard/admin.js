/* ==========================================================================
   HomeHub Admin Console — Enterprise v3.0
   Full SPA Router + Deploy Center + Security + Backup + Observability
   ========================================================================== */

'use strict';

(function gateLiveDeployCard() {
  const css = '#live-deploy-card:not(.deploy-card-open){display:none!important}';
  const apply = () => {
    if (document.getElementById('hh-live-deploy-card-gate')) return;
    const style = document.createElement('style');
    style.id = 'hh-live-deploy-card-gate';
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
    const card = document.getElementById('live-deploy-card');
    if (card) card.classList.remove('deploy-card-open');
  };
  if (document.head || document.body) apply();
  else document.addEventListener('DOMContentLoaded', apply);
})();

// ── State ──────────────────────────────────────────────────────────────────
var HH_ME = null;          // identidade + permissões do usuário logado (hoisted)
var HUB_USERS = [];        // cache da lista de usuários (hoisted)
var TERM_SESSIONS = [];    // cache das sessões do terminal (hoisted)
var hubUsersList = [];
let isAuthenticated = false;
let latestSshCmd = '';
let latestPublicUrl = '';
let latestTerminalUrl = '';
let currentPage = 'overview';
let currentDeployTab = 'new';
let lastStatusData = null;
let sidebarCollapsed = false;
let activeDeployEventSource = null;
let activeDeployJobId = null;
let activeDeployAppName = '';
let deployStreamRetryTimer = null;
const DEPLOY_JOB_KEY = 'hh-active-deploy';
let selectedDeployFile = null;

// ── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // NOTA: não chamamos hideDeployProgressCard()/forgetDeployJob() aqui,
  // pois isso apagaria o deploy em andamento ao dar F5. A restauração
  // acontece via maybeRestoreActiveDeploy() após autenticação.

  checkAdminSession();
  setupDragAndDrop();
  setupGithubBranchPicker();
  ensureDeployCardDismiss();
  HHNotify.init();

  setInterval(() => {
    if (!isAuthenticated) return;
    fetchStatus();
  }, 3500);
});

// ── Auth ────────────────────────────────────────────────────────────────────
async function checkAdminSession() {
  try {
    const res = await fetch('/api/session');
    if (!res.ok) throw new Error();
    const data = await res.json();
    if (data.authenticated) {
      showDashboard(data.is_default_password);
      fetchStatus();
      fetchAdminProjects();
      maybeRestoreActiveDeploy();
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }
}

function showLogin() {
  isAuthenticated = false;
  if (typeof BackupWatcher !== 'undefined' && BackupWatcher.stop) BackupWatcher.stop();
  document.getElementById('admin-login-view').classList.remove('hidden');
  document.getElementById('admin-dashboard-view').classList.add('hidden');
  const u = document.getElementById('admin-user-input');
  if (u) u.focus();
}

function showDashboard(isDefaultPassword) {
  isAuthenticated = true;
  if (typeof BackupWatcher !== 'undefined' && BackupWatcher.start) BackupWatcher.start();
  document.getElementById('admin-login-view').classList.add('hidden');
  document.getElementById('admin-dashboard-view').classList.remove('hidden');
  hideDeployProgressCard();
  void applyRoleBasedUI();
  bootRestorePage();
}

// Re-anexa o deploy em execução ao recarregar a página ( F5)/relogar: primeiro
// tenta o job lembrado no localStorage; senão, o job ativo reportado pelo servidor..
async function maybeRestoreActiveDeploy() {
  let job = null;
  let storedName = '';
  try {
    const st = JSON.parse(localStorage.getItem(DEPLOY_JOB_KEY) || 'null');
    if (st && st.jobId) storedName = st.appName || '';
    if (st && st.jobId) {
      const r = await fetch(`/api/deploy/jobs/${encodeURIComponent(st.jobId)}/status`);
      if (r.ok) { const j = await r.json(); if (j && j.id) job = j; }
    }
    if (!job || !['pending', 'running'].includes(job.status)) {
      const r2 = await fetch('/api/deploy/jobs/active');
      if (r2.ok) { const d = await r2.json(); if (d && d.job) job = d.job; }
    }
  } catch {}
  if (job && job.id && ['pending', 'running'].includes(job.status)) {
    const name = job.app_name || storedName || 'deploy';
    showDeployProgressCard(job.id, name, 'github');
    startDeployLogStream(job.id, name);
  }
}

async function submitLogin() {
  const btn = document.getElementById('btn-login-submit');
  const errEl = document.getElementById('login-error-msg');
  const user = document.getElementById('admin-user-input').value.trim();
  const pass = document.getElementById('admin-pass-input').value;
  const totpInput = document.getElementById('admin-totp-input');
  const totp = totpInput ? totpInput.value.trim() : '';

  btn.disabled = true;
  btn.textContent = 'Verificando...';
  errEl.classList.add('hidden');

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass, totp: totp }),
    });
    const data = await res.json();
    if (data.needs_totp) {
      const row = document.getElementById('totp-login-row');
      if (row) row.classList.remove('hidden');
      if (totpInput) { totpInput.value = ''; totpInput.focus(); }
      errEl.textContent = data.error || 'Informe o código 2FA.';
      errEl.classList.remove('hidden');
      btn.disabled = false;
      btn.textContent = 'Enviar código 2FA';
      return;
    }
    if (data.success) {
      showDashboard(data.is_default_password);
      fetchStatus();
      fetchAdminProjects();
    } else {
      errEl.textContent = data.error || 'Credenciais incorretas.';
      errEl.classList.remove('hidden');
    }
  } catch {
    errEl.textContent = 'Falha de conexão com o servidor.';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Acessar Painel';
  }
}

// ── 2FA management (TOTP) ────────────────────────────────────────────────────
async function fetch2faStatus() {
  const box = document.getElementById('twofa-box');
  if (!box) return;
  try {
    const r = await fetch('/api/2fa/status');
    const d = await r.json();
    if (d.enabled) {
      box.innerHTML = `
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
          <span style="font-size:1.05em">🔒 Autenticação em 2 etapas <b>ativa</b></span>
          <button class="btn btn-danger btn-sm" id="btn-2fa-disable">Desativar 2FA</button>
        </div>`;
      document.getElementById('btn-2fa-disable').onclick = disable2fa;
    } else {
      box.innerHTML = `
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
          <span style="font-size:1.05em">⚠️ 2FA <b>desativada</b> — recomendado ativar</span>
          <button class="btn btn-primary btn-sm" id="btn-2fa-setup">Ativar 2FA</button>
        </div>
        <div id="twofa-setup" class="hidden" style="margin-top:16px;border-top:1px solid var(--border-card,#e5e7eb);padding-top:14px"></div>`;
      document.getElementById('btn-2fa-setup').onclick = begin2faSetup;
    }
  } catch { box.innerHTML = '<p>Erro ao consultar o status do 2FA.</p>'; }
}

function twofaPassword() {
  return prompt('Confirme sua senha atual para continuar:') || '';
}

async function begin2faSetup() {
  const pwd = twofaPassword();
  if (!pwd) return;
  try {
    const r = await fetch('/api/2fa/setup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd }),
    });
    const d = await r.json();
    if (!d.success) { alert(d.error || 'Falha ao iniciar o setup.'); return; }
    const box = document.getElementById('twofa-setup');
    if (!box) return;
    box.innerHTML = `
      <p><b>1.</b> Adicione no seu app autenticador (Google Authenticator, Ente Auth, 1Password…) usando esta chave:</p>
      <pre class="mono-text" style="user-select:all;background:var(--bg-elevated,#f3f4f6);padding:10px 14px;border-radius:8px;display:inline-block">${d.secret}</pre>
      <p style="margin-top:8px"><b>2.</b> Digite o código de 6 dígitos gerado pelo app para confirmar:</p>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input type="text" id="twofa-code" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" maxlength="6" style="width:130px" />
        <button class="btn btn-primary btn-sm" id="btn-2fa-confirm">Ativar 2FA</button>
      </div>`;
    box.classList.remove('hidden');
    document.getElementById('btn-2fa-confirm').onclick = () => confirm2fa(pwd, d.secret);
  } catch { alert('Erro de conexão.'); }
}

async function confirm2fa(pwd, secret) {
  const code = (document.getElementById('twofa-code')?.value || '').trim();
  if (!code) { alert('Digite o código de 6 dígitos.'); return; }
  try {
    const r = await fetch('/api/2fa/confirm', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd, code }),
    });
    const d = await r.json();
    if (d.success) { alert('✅ 2FA ativado! A partir de agora o login exigirá o código.'); fetch2faStatus(); }
    else alert(d.error || 'Falha ao ativar.');
  } catch { alert('Erro de conexão.'); }
}

async function disable2fa() {
  const pwd = twofaPassword();
  if (!pwd) return;
  const code = prompt('Digite um código 2FA atual de 6 dígitos:') || '';
  if (!code) return;
  try {
    const r = await fetch('/api/2fa/disable', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd, code }),
    });
    const d = await r.json();
    if (d.success) { alert('2FA desativado.'); fetch2faStatus(); }
    else alert(d.error || 'Falha ao desativar.');
  } catch { alert('Erro de conexão.'); }
}

async function performLogout() {
  try { await fetch('/api/logout', { method: 'POST' }); } catch {}
  showLogin();
}

// ── SPA Router ──────────────────────────────────────────────────────────────
const PAGE_META = {
  overview:     { title: 'Visão Geral',          subtitle: 'Status do servidor e telemetria em tempo real' },
  server:       { title: 'Servidor',              subtitle: 'Recursos de hardware e containers isolados' },
  deploy:       { title: '🚀 Deploy Center',     subtitle: 'Build automático, containerização e publicação segura' },
  applications: { title: 'Portal Público',        subtitle: 'Gerenciamento do catálogo de aplicações' },
  services:     { title: 'Serviços & Infra',     subtitle: 'Bancos de dados e ferramentas ativas' },
  network:      { title: 'Rede & Conectividade', subtitle: 'IPs, tunnels HTTPS e credenciais SSH' },
  security:     { title: '🛡️ Segurança',         subtitle: 'Auditoria contínua e status de proteção' },
  files:        { title: '📁 Arquivos',            subtitle: 'Gerenciador de arquivos do servidor' },
  backup:       { title: '💾 Backup Google Drive', subtitle: 'Disaster Recovery completo & Restic criptografado' },
  audit:        { title: '📜 Auditoria',          subtitle: 'Trilha de logs administrativos e ações' },
  users:        { title: '👥 Administradores & Acessos', subtitle: 'Gestão de contas com RBAC, convites corporativos e auditoria' },
  settings:     { title: 'Configurações',         subtitle: 'Parâmetros da plataforma e links rápidos' },
};

function navigateTo(page) {
  currentPage = page;

  try {
    if ((history.state && history.state.page) !== page) history.pushState({ page: page }, '', '#' + page);
  } catch {}
  try { localStorage.setItem('hh_admin_page', page); } catch {}

  // Deactivate all sections + nav items
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar-nav-item').forEach(b => b.classList.remove('active'));

  // Activate target
  const section = document.getElementById(`page-${page}`);
  if (section) section.classList.add('active');
  const navBtn = document.querySelector(`[data-page="${page}"]`);
  if (navBtn) navBtn.classList.add('active');

  // Update header
  const meta = PAGE_META[page] || {};
  document.getElementById('content-page-title').textContent = meta.title || page;
  document.getElementById('content-page-subtitle').textContent = meta.subtitle || '';

  // Trigger page-specific fetches
  if (page === 'deploy') {
    fetchDeployData();
  }
  if (page === 'applications') fetchAdminProjects();
  if (page === 'security') { runSecurityAudit(); fetch2faStatus(); }
  if (page === 'files') loadFiles('');
  if (page === 'backup') { fetchBackupStatus(); fetchBackupSnapshots(); BackupWatcher.start(); }
  if (page === 'audit') { fetchAuditLogs(); fetchTerminalAuditLogs(); }
  if (page === 'users') loadUsersPage();
}

function toggleSidebar() {
  const sidebar = document.getElementById('admin-sidebar');
  sidebarCollapsed = !sidebarCollapsed;
  sidebar.classList.toggle('sidebar-collapsed', sidebarCollapsed);
}

// ── Deploy Center Tabs ──────────────────────────────────────────────────────
function switchDeployTab(tab, btn) {
  currentDeployTab = tab;
  document.querySelectorAll('.deploy-sub-view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.deploy-tab-btn').forEach(b => b.classList.remove('active'));

  const target = document.getElementById(`deploy-view-${tab}`);
  if (target) target.classList.add('active');

  if (btn) btn.classList.add('active');
  else {
    const matchingBtn = Array.from(document.querySelectorAll('.deploy-tab-btn')).find(b => b.textContent.toLowerCase().includes(tab === 'new' ? 'novo' : (tab === 'apps' ? 'aplicações' : 'histórico')));
    if (matchingBtn) matchingBtn.classList.add('active');
  }

  if (tab === 'apps') fetchDeployedApps();
  if (tab === 'history') fetchDeployHistory();
}

function fetchDeployData() {
  if (currentDeployTab === 'apps') fetchDeployedApps();
  else if (currentDeployTab === 'history') fetchDeployHistory();
}

function switchDeploySource(source, button) {
  document.querySelectorAll('.deploy-source-option').forEach(el => el.classList.toggle('active', el.dataset.source === source));
  document.querySelectorAll('[data-source-panel]').forEach(el => el.classList.toggle('active', el.dataset.sourcePanel === source));
  document.querySelectorAll('.error-banner').forEach(el => el.classList.add('hidden'));
  if (button) button.focus();
}

// ── Drag & Drop & Upload ────────────────────────────────────────────────────
function setupDragAndDrop() {
  const dropZone = document.getElementById('drop-zone');
  if (!dropZone) return;

  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('drag-over'); });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length) handleSelectedFile(files[0]);
  });
}

function handleDeployFileSelect(input) {
  if (input.files && input.files.length) {
    handleSelectedFile(input.files[0]);
  }
}

function handleSelectedFile(file) {
  selectedDeployFile = file;
  const chip = document.getElementById('selected-file-badge');
  const nameEl = document.getElementById('selected-file-name');
  const sizeEl = document.getElementById('selected-file-size');
  const nameInput = document.getElementById('deploy-app-name');

  if (chip && nameEl && sizeEl) {
    chip.classList.remove('hidden');
    nameEl.textContent = file.name;
    sizeEl.textContent = `(${(file.size / (1024 * 1024)).toFixed(2)} MB)`;
  }

  // Pre-fill app name if empty
  if (nameInput && !nameInput.value) {
    const rawName = file.name.replace(/\.(zip|tar\.gz|tgz)$/i, '');
    nameInput.value = rawName.charAt(0).toUpperCase() + rawName.slice(1);
  }
}

async function startDeployUpload() {
  const errEl = document.getElementById('deploy-upload-error');
  const btn = document.getElementById('btn-start-deploy');
  errEl.classList.add('hidden');

  if (!selectedDeployFile) {
    errEl.textContent = 'Selecione um arquivo ZIP ou TAR.GZ para deploy.';
    errEl.classList.remove('hidden');
    return;
  }

  const appName = document.getElementById('deploy-app-name').value.trim();
  if (!appName) {
    errEl.textContent = 'Informe o nome da aplicação.';
    errEl.classList.remove('hidden');
    return;
  }

  const formData = new FormData();
  formData.append('file', selectedDeployFile);
  formData.append('name', appName);
  formData.append('category', document.getElementById('deploy-app-category').value.trim());
  formData.append('icon', document.getElementById('deploy-app-icon').value.trim() || '🚀');
  formData.append('description', document.getElementById('deploy-app-desc').value.trim());
  formData.append('publish_to_portal', document.getElementById('deploy-publish-portal').checked);
  formData.append('featured', document.getElementById('deploy-featured-portal').checked);

  // Custom environment vars (upload form)
  const customEnvVarsUpload = document.getElementById('deploy-upload-custom-env-vars').value.trim();
  if (customEnvVarsUpload) {
    formData.append('custom_env_vars', customEnvVarsUpload);
  }

  // Extra networks (upload form)
  const extraNetworksUpload = document.getElementById('deploy-upload-extra-networks').value.trim();
  if (extraNetworksUpload) {
    formData.append('extra_networks', extraNetworksUpload);
  }

  btn.disabled = true;
  const fileSizeMb = (selectedDeployFile.size / (1024 * 1024)).toFixed(1);
  btn.innerHTML = `Enviando pacote (${fileSizeMb} MB)...`;

  try {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/deploy/upload', true);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        btn.innerHTML = `Enviando: ${pct}% (${(e.loaded/(1024*1024)).toFixed(1)} / ${fileSizeMb} MB)`;
      }
    };

    xhr.onload = () => {
      btn.disabled = false;
      btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Iniciar Deploy Seguro';
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status === 200 && data.success) {
          showDeployProgressCard(data.job_id, appName, 'upload');
          startDeployLogStream(data.job_id);
        } else {
          errEl.textContent = data.error || `Erro ${xhr.status}: ${xhr.statusText || 'Falha no processamento'}`;
          errEl.classList.remove('hidden');
        }
      } catch (ex) {
        errEl.textContent = `Erro ${xhr.status}: Resposta inesperada do servidor.`;
        errEl.classList.remove('hidden');
      }
    };

    xhr.onerror = () => {
      btn.disabled = false;
      btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Iniciar Deploy Seguro';
      errEl.textContent = 'Falha de comunicação no upload. Verifique sua conexão e tente novamente.';
      errEl.classList.remove('hidden');
    };

    xhr.send(formData);
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Iniciar Deploy Seguro';
    errEl.textContent = 'Erro ao iniciar envio: ' + err.message;
    errEl.classList.remove('hidden');
  }
}

let githubBranchTimer = null;
let githubBranchAbort = null;

function githubRepoUrlLooksValid(url) {
  return /^https?:\/\/github\.com\/[^/\s]+\/[^/\s?#]+/i.test((url || '').trim());
}

function ensureGithubBranchSelect() {
  const el = document.getElementById('github-branch');
  if (!el) return null;
  if (el.tagName === 'SELECT') return el;
  const sel = document.createElement('select');
  sel.id = 'github-branch';
  sel.className = el.className;
  sel.name = el.name || 'github-branch';
  sel.required = true;
  sel.innerHTML = '<option value="">Cole o link do repositório para listar as branches</option>';
  el.replaceWith(sel);
  return sel;
}

function setGithubBranchOptions(branches, selected) {
  const sel = ensureGithubBranchSelect();
  if (!sel) return;
  const list = Array.isArray(branches) && branches.length ? branches : ['main'];
  const pick = selected && list.includes(selected) ? selected : list[0];
  sel.innerHTML = list.map((name) => {
    const safe = escapeHtml(name);
    return `<option value="${safe}"${name === pick ? ' selected' : ''}>${safe}</option>`;
  }).join('');
  sel.disabled = false;
}

function setGithubBranchStatus(message, disabled) {
  const sel = ensureGithubBranchSelect();
  if (!sel) return;
  sel.disabled = !!disabled;
  sel.innerHTML = `<option value="">${escapeHtml(message)}</option>`;
}

async function loadGithubBranches() {
  const urlEl = document.getElementById('github-repo-url');
  const tokenEl = document.getElementById('github-token');
  const errorEl = document.getElementById('deploy-github-error');
  const nameEl = document.getElementById('github-app-name');
  if (!urlEl) return;
  const repoUrl = urlEl.value.trim();
  if (!githubRepoUrlLooksValid(repoUrl)) {
    setGithubBranchStatus('Cole o link do repositório para listar as branches', true);
    return;
  }
  const parsed = repoUrl.match(/github\.com\/([^/\s]+)\/([^/\s?#]+)/i);
  if (parsed && nameEl && !nameEl.value.trim()) {
    const repoName = parsed[2].replace(/\.git$/i, '').replace(/[-_]/g, ' ');
    nameEl.value = repoName;
  }
  setGithubBranchStatus('Buscando branches…', true);
  if (githubBranchAbort) githubBranchAbort.abort();
  githubBranchAbort = new AbortController();
  try {
    const savedKeyEl = document.getElementById('github-saved-key');
    const response = await fetch('/api/deploy/github-branches', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_url: repoUrl,
        saved_key: savedKeyEl ? savedKeyEl.value.trim() : '',
        token: tokenEl ? tokenEl.value.trim() : ''
      }),
      signal: githubBranchAbort.signal
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
      setGithubBranchStatus(data.error || 'Não foi possível listar as branches', true);
      if (errorEl) {
        errorEl.textContent = data.error || 'Não foi possível listar as branches.';
        errorEl.classList.remove('hidden');
      }
      return;
    }
    if (errorEl) errorEl.classList.add('hidden');
    setGithubBranchOptions(data.branches, data.selected || data.default_branch);
  } catch (err) {
    if (err && err.name === 'AbortError') return;
    setGithubBranchStatus('Falha ao buscar branches', true);
  }
}

function setupGithubBranchPicker() {
  const urlEl = document.getElementById('github-repo-url');
  const tokenEl = document.getElementById('github-token');
  if (!urlEl) return;
  ensureGithubBranchSelect();
  const schedule = () => {
    clearTimeout(githubBranchTimer);
    githubBranchTimer = setTimeout(loadGithubBranches, 450);
  };
  urlEl.addEventListener('input', schedule);
  urlEl.addEventListener('change', () => loadGithubBranches());
  urlEl.addEventListener('paste', () => setTimeout(loadGithubBranches, 0));
  if (tokenEl) {
    tokenEl.addEventListener('change', () => {
      if (githubRepoUrlLooksValid(urlEl.value)) loadGithubBranches();
    });
  }
  if (githubRepoUrlLooksValid(urlEl.value)) loadGithubBranches();
  loadGithubKeys();
}

// ── Chaves do GitHub salvas (reutilizáveis) ─────────────────────────────────
async function loadGithubKeys() {
  const sel = document.getElementById('github-saved-key');
  if (!sel) return;
  try {
    const r = await fetch('/api/deploy/github-keys');
    if (!r.ok) return;
    const d = await r.json();
    const keys = Array.isArray(d.keys) ? d.keys : [];
    const prev = sel.value;
    sel.innerHTML = '<option value="">— Usar token manual —</option>' +
      keys.map(k => `<option value="${escapeHtml(k.name)}">${escapeHtml(k.name)}${k.hint ? ' (' + escapeHtml(k.hint) + ')' : ''}</option>`).join('');
    if (prev) sel.value = prev;
  } catch {}
}

function onGithubSavedKeyChange() {
  const sel = document.getElementById('github-saved-key');
  const tokenEl = document.getElementById('github-token');
  if (sel && tokenEl && sel.value) tokenEl.value = '';
  const urlEl = document.getElementById('github-repo-url');
  if (urlEl && githubRepoUrlLooksValid(urlEl.value)) loadGithubBranches();
}

async function saveGithubKey() {
  const nameEl = document.getElementById('github-key-name');
  const tokenEl = document.getElementById('github-token');
  const sel = document.getElementById('github-saved-key');
  const name = nameEl ? nameEl.value.trim() : '';
  const token = tokenEl ? tokenEl.value.trim() : '';
  if (!name || !token) { showToast('Informe um nome e o token para salvar a chave.', 'error'); return; }
  try {
    const r = await fetch('/api/deploy/github-keys', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, token })
    });
    const d = await r.json();
    if (d.success) {
      showToast('Chave salva com sucesso.', 'success');
      if (tokenEl) tokenEl.value = '';
      if (nameEl) nameEl.value = '';
      await loadGithubKeys();
      if (sel) sel.value = name;
    } else {
      showToast(d.error || 'Erro ao salvar a chave.', 'error');
    }
  } catch { showToast('Erro ao salvar a chave.', 'error'); }
}

async function deleteGithubKey() {
  const sel = document.getElementById('github-saved-key');
  const name = sel ? sel.value : '';
  if (!name) { showToast('Selecione uma chave para remover.', 'error'); return; }
  try {
    const r = await fetch('/api/deploy/github-keys/' + encodeURIComponent(name), { method: 'DELETE' });
    const d = await r.json();
    if (d.success) {
      showToast('Chave removida.', 'success');
      if (sel) sel.value = '';
      await loadGithubKeys();
    } else {
      showToast(d.error || 'Erro ao remover a chave.', 'error');
    }
  } catch { showToast('Erro ao remover a chave.', 'error'); }
}

async function startGithubDeploy() {
  const errorEl = document.getElementById('deploy-github-error');
  const button = document.getElementById('btn-start-github-deploy');
  errorEl.classList.add('hidden');
  const repoUrl = document.getElementById('github-repo-url').value.trim();
  const name = document.getElementById('github-app-name').value.trim();
  if (!repoUrl || !name) {
    errorEl.textContent = 'Informe a URL do repositório e o nome da aplicação.';
    errorEl.classList.remove('hidden');
    return;
  }
  const branchEl = document.getElementById('github-branch');
  const branch = (branchEl && branchEl.value ? branchEl.value : '').trim();
  if (!branch) {
    errorEl.textContent = 'Cole o link do repositório e selecione uma branch.';
    errorEl.classList.remove('hidden');
    return;
  }
  const savedKeyEl = document.getElementById('github-saved-key');
  const keyNameEl = document.getElementById('github-key-name');
  const payload = {
    repo_url: repoUrl,
    branch,
    name,
    category: document.getElementById('github-category').value.trim() || 'Geral',
    icon: document.getElementById('github-icon').value.trim() || '🚀',
    description: document.getElementById('github-description').value.trim(),
    saved_key: savedKeyEl ? savedKeyEl.value.trim() : '',
    key_name: keyNameEl ? keyNameEl.value.trim() : '',
    save_token: false,
    token: document.getElementById('github-token').value.trim(),
    publish_to_portal: document.getElementById('github-publish-portal').checked,
    featured: document.getElementById('github-featured-portal').checked
  };

  // Custom environment vars (github form)
  const customEnvVarsGithub = document.getElementById('deploy-github-custom-env-vars').value.trim();
  if (customEnvVarsGithub) {
    payload.custom_env_vars = customEnvVarsGithub;
  }

  // Extra networks (github form)
  const extraNetworksGithub = document.getElementById('deploy-github-extra-networks').value.trim();
  if (extraNetworksGithub) {
    payload.extra_networks = extraNetworksGithub;
  }
  button.disabled = true;
  button.textContent = 'Clonando repositório...';
  try {
    const response = await fetch('/api/deploy/from-github', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.error || 'Não foi possível iniciar o deploy.');
    document.getElementById('github-token').value = '';
    showDeployProgressCard(data.job_id, name, 'github');
    startDeployLogStream(data.job_id);
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove('hidden');
  } finally {
    button.disabled = false;
    button.textContent = 'Deploy do GitHub';
  }
}

let deploySuccessMarked = false;

function rememberDeployJob(jobId, appName) {
  activeDeployJobId = jobId;
  if (appName) activeDeployAppName = appName;
  try { localStorage.setItem(DEPLOY_JOB_KEY, JSON.stringify({ jobId, appName: appName || '' })); } catch {}
}

function forgetDeployJob() {
  activeDeployJobId = null;
  try { localStorage.removeItem(DEPLOY_JOB_KEY); } catch {}
}

function hideDeployProgressCard() {
  const card = document.getElementById('live-deploy-card');
  if (card) {
    card.classList.add('hidden');
    card.classList.remove('deploy-card-open');
  }
  if (activeDeployEventSource) {
    activeDeployEventSource.close();
    activeDeployEventSource = null;
  }
  if (deployStreamRetryTimer) {
    clearTimeout(deployStreamRetryTimer);
    deployStreamRetryTimer = null;
  }
  forgetDeployJob();
}

function ensureDeployCardDismiss() {
  const card = document.getElementById('live-deploy-card');
  if (!card || document.getElementById('btn-dismiss-deploy-card')) return;
  const btn = document.createElement('button');
  btn.id = 'btn-dismiss-deploy-card';
  btn.type = 'button';
  btn.className = 'btn-dismiss-deploy';
  btn.textContent = 'Fechar';
  btn.addEventListener('click', hideDeployProgressCard);
  const badge = document.getElementById('deploy-status-badge');
  if (badge && badge.parentNode) badge.parentNode.appendChild(btn);
  else card.prepend(btn);
}

function showDeployProgressCard(jobId, appName, source) {
  const card = document.getElementById('live-deploy-card');
  if (!card) return;
  ensureDeployCardDismiss();
  card.classList.remove('hidden');
  card.classList.add('deploy-card-open');
  document.getElementById('deploy-progress-title').textContent = `🚀 Deploy: ${appName}`;
  document.getElementById('deploy-progress-subtitle').textContent = `Job ID: ${jobId}`;
  deploySuccessMarked = false;
  rememberDeployJob(jobId, appName);
  const badge = document.getElementById('deploy-status-badge');
  if (badge) {
    badge.className = 'status-chip status-chip-blue';
    badge.textContent = 'Executando';
  }
  resetPipelineStepper(source === 'upload');
  clearDeployLogs();
  resetDeployPercent();
  card.scrollIntoView({ behavior: 'smooth' });
}

function resetPipelineStepper(activateUpload) {
  for (let i = 1; i <= 9; i++) {
    const stepEl = document.getElementById(`step-${i}`);
    if (stepEl) stepEl.className = 'step-item';
  }
  if (activateUpload) updateStepState(1, 'active');
}

function updateStepState(stepIndex, state) {
  const stepEl = document.getElementById(`step-${stepIndex}`);
  if (!stepEl) return;
  stepEl.classList.remove('step-active', 'step-done', 'step-failed');
  if (state === 'active') stepEl.classList.add('step-active');
  if (state === 'done') stepEl.classList.add('step-done');
  if (state === 'failed') stepEl.classList.add('step-failed');
}

function startDeployLogStream(jobId, appName) {
  rememberDeployJob(jobId, appName || activeDeployAppName);
  if (deployStreamRetryTimer) {
    clearTimeout(deployStreamRetryTimer);
    deployStreamRetryTimer = null;
  }
  if (activeDeployEventSource) {
    activeDeployEventSource.close();
    activeDeployEventSource = null;
  }

  const source = new EventSource(`/api/deploy/jobs/${jobId}/logs/stream`);
  activeDeployEventSource = source;

  source.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (applyDeployPercent(data.message)) {
        return;
      }
      appendDeployLog(data.message, data.level);

      const msg = (data.message || '').toLowerCase();
      if (msg.includes('validado')) { updateStepState(1, 'done'); updateStepState(2, 'active'); }
      if (msg.includes('stack detectada') || msg.includes('repositório baixado') || msg.includes('arquivos encontrados')) {
        updateStepState(1, 'done');
      }
      if (msg.includes('stack detectada')) { updateStepState(2, 'done'); updateStepState(3, 'done'); updateStepState(4, 'active'); }
      if (msg.includes('dockerfile')) { updateStepState(4, 'done'); updateStepState(5, 'active'); }
      if (msg.includes('container iniciado')) { updateStepState(5, 'done'); updateStepState(6, 'done'); updateStepState(7, 'active'); }
      if (msg.includes('respondendo com sucesso')) { updateStepState(7, 'done'); updateStepState(8, 'active'); }
      // IMPORTANTE: NÃO marcar sucesso por qualquer mensagem que contenha URL
      // (ex.: o link do repositório que aparece no início do download). O
      // sucesso só é confirmado realmente via evento "done" (status success
      // definido servidor-side após todos os passos) abaixo.
    } catch {}
  };

  source.addEventListener('done', async (e) => {
    try {
      const job = JSON.parse(e.data);
      if (job.status === 'success') markDeploySuccess(await getDeployOpenHref(jobId));
      if (job.status === 'failed') {
        const badge = document.getElementById('deploy-status-badge');
        if (badge) {
          badge.className = 'status-chip status-chip-red';
          badge.textContent = 'Falhou';
        }
        forgetDeployJob();
      }
    } catch {}
    source.close();
    if (activeDeployEventSource === source) activeDeployEventSource = null;
  });

  source.onerror = () => {
    if (deploySuccessMarked) return;
    if (source.readyState !== EventSource.CLOSED) return;
    if (activeDeployEventSource === source) activeDeployEventSource = null;
    deployStreamRetryTimer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/deploy/jobs/${jobId}/status`);
        if (!res.ok) return;
        const job = await res.json();
        if (job.status === 'pending' || job.status === 'running') {
          startDeployLogStream(jobId, appName);
        } else if (job.status === 'success') {
          markDeploySuccess(await getDeployOpenHref(jobId));
        }
      } catch {}
    }, 1500);
  };
}

function extractDeployHref(msg) {
  const m = String(msg || '').match(/https?:\/\/[^\s]+|\/apps\/[^\s]+/);
  return m ? m[0] : '';
}

// Busca o link real de "Concluído" nos logs do job (a linha "🔗 Concluído <url>"
// só é gravada servidor-side quando o deploy terminou de verdade). Assim o badge
// abre a URL direta correta e nunca marca sucesso antes da hora.
async function getDeployOpenHref(jobId) {
  try {
    const r = await fetch(`/api/deploy/jobs/${encodeURIComponent(jobId)}/logs`);
    if (!r.ok) return '';
    const d = await r.json();
    const lines = (d.logs || []).map(l => (l && l.message) || '');
    for (let i = lines.length - 1; i >= 0; i--) {
      if (/concluído/i.test(lines[i])) return extractDeployHref(lines[i]);
    }
  } catch {}
  return '';
}

function ensureDeployProgressBar() {
  if (document.getElementById('deploy-pct-wrap')) return;
  const terminal = document.getElementById('deploy-terminal-logs');
  if (!terminal || !terminal.parentNode) return;
  const wrap = document.createElement('div');
  wrap.id = 'deploy-pct-wrap';
  wrap.innerHTML = `
    <div class="deploy-pct-label" id="deploy-pct-label">Aguardando…</div>
    <div class="deploy-pct-track"><div class="deploy-pct-fill" id="deploy-pct-fill"></div></div>
    <div class="deploy-pct-num" id="deploy-pct-num">0%</div>`;
  terminal.parentNode.insertBefore(wrap, terminal);
}

function resetDeployPercent() {
  ensureDeployProgressBar();
  const fill = document.getElementById('deploy-pct-fill');
  const num = document.getElementById('deploy-pct-num');
  const label = document.getElementById('deploy-pct-label');
  if (fill) fill.style.width = '0%';
  if (num) num.textContent = '0%';
  if (label) label.textContent = 'Aguardando…';
  const line = document.getElementById('deploy-progress-line');
  if (line) line.remove();
}

function applyDeployPercent(msg) {
  const m = String(msg || '').match(/^PROGRESS\s+(\d+)%\s*(.*)$/i);
  if (!m) return false;
  const pct = Math.max(0, Math.min(100, parseInt(m[1], 10) || 0));
  const label = (m[2] || 'Em andamento').trim();
  ensureDeployProgressBar();
  const fill = document.getElementById('deploy-pct-fill');
  const num = document.getElementById('deploy-pct-num');
  const lab = document.getElementById('deploy-pct-label');
  if (fill) fill.style.width = `${pct}%`;
  if (num) num.textContent = `${pct}%`;
  if (lab) lab.textContent = label;
  const badge = document.getElementById('deploy-status-badge');
  if (badge && !deploySuccessMarked) {
    badge.className = 'status-chip status-chip-blue';
    badge.textContent = `${pct}%`;
  }
  const terminal = document.getElementById('deploy-terminal-logs');
  if (terminal) {
    let line = document.getElementById('deploy-progress-line');
    if (!line) {
      line = document.createElement('div');
      line.id = 'deploy-progress-line';
      line.className = 'log-line';
      terminal.appendChild(line);
    }
    line.textContent = `[${new Date().toLocaleTimeString()}] ${pct}% ${label}`;
    terminal.scrollTop = terminal.scrollHeight;
  }
  return true;
}

function markDeploySuccess(href) {
  updateStepState(8, 'done');
  updateStepState(9, 'done');
  applyDeployPercent('PROGRESS 100% Deploy finalizado');
  const badge = document.getElementById('deploy-status-badge');
  const existing = badge && badge.querySelector('a') ? badge.querySelector('a').getAttribute('href') : '';
  const openHref = href ? (catalogAppHref(href) || href) : existing;
  if (badge) {
    badge.className = 'status-chip status-chip-green';
    if (openHref) {
      badge.innerHTML = `<a href="${escapeHtml(openHref)}" target="_blank" rel="noopener noreferrer" class="deploy-done-link">Concluído ↗</a>`;
    } else {
      badge.textContent = 'Concluído';
    }
  }
  if (deploySuccessMarked) return;
  deploySuccessMarked = true;
  forgetDeployJob();
  showToast(openHref ? 'Deploy concluído. Clique em Concluído para abrir o site.' : 'Deploy concluído!', 'success');
  fetchDeployedApps();
  fetchAdminProjects();
}

function appendDeployLog(msg, level) {
  const terminal = document.getElementById('deploy-terminal-logs');
  if (!terminal) return;
  const line = document.createElement('div');
  line.className = `log-line ${level === 'ERROR' ? 'log-err' : (level === 'BUILD' ? 'log-build' : '')}`;
  const stamp = `[${new Date().toLocaleTimeString()}] `;
  const href = extractDeployHref(msg);
  if (href) {
    const safe = escapeHtml(msg).replace(
      /(https?:\/\/[^\s]+|\/apps\/[^\s]+)/g,
      (url) => `<a href="${escapeHtml(catalogAppHref(url) || url)}" target="_blank" rel="noopener noreferrer" class="catalog-url-link">Concluído ↗ ${escapeHtml(url)}</a>`
    );
    line.innerHTML = stamp + safe;
  } else {
    line.textContent = stamp + msg;
  }
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearDeployLogs() {
  const terminal = document.getElementById('deploy-terminal-logs');
  if (terminal) terminal.innerHTML = '';
}

// ── Deployed Apps List ──────────────────────────────────────────────────────

function portalHref(app) {
  try { document.cookie = 'hh-app-slug=' + (app.slug || '') + '; path=/; max-age=86400'; } catch (e) {}

  // Public URL when published via the portal proxy; fallback to direct port.
  if (app && app.publish_to_portal && (app.portal_path || app.slug)) {
    return app.portal_path || ('/apps/' + app.slug + '/');
  }
  return 'http://' + window.location.hostname + ':' + (app.port || 80);
}
window.portalHref = portalHref;

async function fetchDeployedApps() {
  const container = document.getElementById('deployed-apps-grid');
  if (!container) return;

  try {
    const res = await fetch('/api/deploy/apps');
    const data = await res.json();
    const apps = data.apps || [];

    if (!apps.length) {
      container.innerHTML = `
        <div class="empty-state-inline" style="grid-column:1/-1;padding:48px">
          <div>🚀</div>
          <div>Nenhuma aplicação deployada pelo Deploy Center</div>
          <button class="btn btn-primary btn-sm" onclick="switchDeployTab('new')">Fazer Primeiro Deploy</button>
        </div>`;
      return;
    }

    container.innerHTML = apps.map(app => {
      const isRunning = app.status === 'running';
      const statusClass = isRunning ? 'status-chip-green' : 'status-chip-amber';
      const statusText = isRunning ? '🟢 Rodando' : '⏸ Parado';
      return `
        <div class="deployed-app-card">
          <div class="dac-header">
            <span class="dac-icon">${escapeHtml(app.icon || '🚀')}</span>
            <div class="dac-title-group">
              <h3>${escapeHtml(app.name)}</h3>
              <span class="stack-pill">${escapeHtml(app.stack || 'Docker')}</span>
            </div>
            <span class="status-chip ${statusClass}">${statusText}</span>
          </div>

          <div class="dac-meta-grid">
            <div><span class="dac-label">Porta:</span> <span class="mono-text">:${app.port || '--'}</span></div>
            <div><span class="dac-label">Versão Atual:</span> <span class="mono-text">v${app.current_version || 1}</span></div>
            <div><span class="dac-label">Container:</span> <span class="mono-text">${escapeHtml(app.container_name || '--')}</span></div>
            <div><span class="dac-label">Portal:</span> <span>${app.publish_to_portal ? '✓ Publicado' : '✗ Não'}</span></div>
          </div>

          <div class="dac-actions">
            <button class="btn btn-sm btn-outline" onclick="restartDeployedApp('${app.id}')" title="Reiniciar container">🔄 Reiniciar</button>
            <button class="btn btn-sm btn-outline" onclick="${isRunning ? `stopDeployedApp('${app.id}')` : `startDeployedApp('${app.id}')`}">${isRunning ? '⏸ Parar' : '▶ Iniciar'}</button>
            <button class="btn btn-sm btn-outline" onclick="openAppVersionsModal('${app.id}', '${jsStr(app.name)}')">📋 Versões</button>
            <button class="btn btn-sm btn-danger" onclick="deleteDeployedApp('${app.id}', '${jsStr(app.name)}')">Excluir</button>
            <a href="${portalHref(app)}" target="_blank" class="btn btn-sm btn-primary">Abrir ↗</a>
          </div>
        </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<div class="td-loading">Falha ao carregar aplicações.</div>';
  }
}

async function restartDeployedApp(id) {
  showToast('Reiniciando container...', 'info');
  try {
    const res = await fetch(`/api/deploy/apps/${id}/restart`, { method: 'POST' });
    const data = await res.json();
    if (data.success) { showToast('Aplicação reiniciada com sucesso!', 'success'); fetchDeployedApps(); }
    else showToast(data.error || 'Falha ao reiniciar', 'error');
  } catch { showToast('Erro de conexão', 'error'); }
}

async function stopDeployedApp(id) {
  try {
    await fetch(`/api/deploy/apps/${id}/stop`, { method: 'POST' });
    showToast('Container parado.', 'info');
    fetchDeployedApps();
  } catch {}
}

async function startDeployedApp(id) {
  try {
    await fetch(`/api/deploy/apps/${id}/start`, { method: 'POST' });
    showToast('Container iniciado.', 'success');
    fetchDeployedApps();
  } catch {}
}

async function deleteDeployedApp(id, name) {
  name = decodeURIComponent(name);
  if (!confirm(`Excluir "${name}" do Deploy Center e remover o container Docker?`)) return;
  showToast('Removendo aplicação, Docker e portal...', 'info');
  try {
    const res = await fetch(`/api/deploy/apps/${id}/delete`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast('Aplicação removida do Docker e do Deploy Center.', 'success');
      fetchDeployedApps();
      fetchDeployHistory();
      fetchAdminProjects();
    } else {
      showToast(data.error || 'Falha ao excluir', 'error');
    }
  } catch {
    showToast('Erro de conexão', 'error');
  }
}

// ── Versions & Rollback Modal ───────────────────────────────────────────────
async function openAppVersionsModal(appId, appName) {
  appName = decodeURIComponent(appName || '');
  const modal = document.getElementById('versions-modal');
  const title = document.getElementById('versions-modal-title');
  const tbody = document.getElementById('app-versions-tbody');
  title.textContent = `Versões — ${appName}`;
  tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Carregando versões...</td></tr>';
  modal.classList.add('active');

  try {
    const res = await fetch(`/api/deploy/apps/${appId}/versions`);
    const data = await res.json();
    const versions = data.versions || [];

    if (!versions.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Nenhuma versão arquivada</td></tr>';
      return;
    }

    tbody.innerHTML = versions.map(v => {
      const isCurrent = v.is_current;
      const dateStr = v.built_at ? new Date(v.built_at * 1000).toLocaleString('pt-BR') : '--';
      return `
        <tr>
          <td><strong>v${v.version_num}</strong> ${isCurrent ? '<span class="status-chip status-chip-green">Atual</span>' : ''}</td>
          <td>${dateStr}</td>
          <td class="mono-text">:${v.port}</td>
          <td>${v.health_ok ? '🟢 Saudável' : '🔴 Falhou'}</td>
          <td>
            ${!isCurrent ? `<button class="btn btn-sm btn-outline" onclick="performRollback('${appId}', ${v.version_num})">⏪ Rollback</button>` : '<span class="text-muted">Em Produção</span>'}
          </td>
        </tr>`;
    }).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Erro ao carregar histórico de versões.</td></tr>';
  }
}

function closeVersionsModal() {
  document.getElementById('versions-modal').classList.remove('active');
}

async function performRollback(appId, versionNum) {
  if (!confirm(`Deseja realizar o rollback para a versão v${versionNum}?`)) return;
  showToast(`Executando rollback para v${versionNum}...`, 'info');

  try {
    const res = await fetch(`/api/deploy/apps/${appId}/rollback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: versionNum })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Rollback para v${versionNum} concluído com sucesso!`, 'success');
      closeVersionsModal();
      fetchDeployedApps();
    } else {
      showToast(data.error || 'Falha no rollback', 'error');
    }
  } catch {
    showToast('Erro de conexão', 'error');
  }
}

// ── Deploy History Tab ──────────────────────────────────────────────────────
async function fetchDeployHistory() {
  const tbody = document.getElementById('deploy-history-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/deploy/apps');
    const data = await res.json();
    const apps = data.apps || [];

    if (!apps.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Nenhum deploy realizado ainda.</td></tr>';
      return;
    }

    tbody.innerHTML = apps.map(app => {
      const dateStr = app.created_at ? new Date(app.created_at * 1000).toLocaleString('pt-BR') : '--';
      return `
        <tr>
          <td><strong>${escapeHtml(app.name)}</strong></td>
          <td><span class="mono-text">v${app.current_version || 1}</span></td>
          <td>${dateStr}</td>
          <td class="mono-text">:${app.port || '--'}</td>
          <td><span class="status-chip status-chip-green">🟢 Saudável</span></td>
          <td><span class="status-chip status-chip-blue">${escapeHtml(app.status)}</span></td>
          <td>
            <div style="display:flex;gap:6px">
              <button class="btn btn-sm btn-outline" onclick="openAppVersionsModal('${app.id}', '${jsStr(app.name)}')">Ver Versões</button>
              <button class="btn btn-sm btn-danger" onclick="deleteDeployedApp('${app.id}', '${jsStr(app.name)}')">Excluir</button>
            </div>
          </td>
        </tr>`;
    }).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Erro ao carregar histórico.</td></tr>';
  }
}

// ── Security Dashboard ──────────────────────────────────────────────────────
async function runSecurityAudit() {
  const list = document.getElementById('security-checks-list');
  if (!list) return;
  list.innerHTML = '<div class="td-loading">Executando verificações de segurança...</div>';

  try {
    const res = await fetch('/api/security/status');
    if (!res.ok) {
      if (res.status === 401) {
        list.innerHTML = '<div class="td-loading">Sessão expirada. Faça login novamente para ver a auditoria.</div>';
        showLogin();
      } else {
        list.innerHTML = `<div class="td-loading">Erro do servidor (HTTP ${res.status}). Tente novamente em instantes.</div>`;
      }
      return;
    }
    const data = await res.json();
    const checks = data.checks || [];
    if (!checks.length) {
      list.innerHTML = '<div class="td-loading">Nenhuma verificação disponível no momento.</div>';
      return;
    }
    const checkedAt = data.checked_at ? ` — atualizado ${new Date(data.checked_at * 1000).toLocaleTimeString('pt-BR')}` : '';
    list.innerHTML = checks.map(c => {
      const badgeClass = c.status === 'ok' ? 'status-chip-green' : (c.status === 'warning' ? 'status-chip-amber' : 'status-chip-red');
      const badgeIcon = c.status === 'ok' ? '🟢 Seguro' : (c.status === 'warning' ? '🟡 Atenção' : '🔴 Crítico');
      return `
        <div class="security-check-card status-${c.status}">
          <div class="scc-header">
            <span class="scc-title">${escapeHtml(c.name)}</span>
            <span class="status-chip ${badgeClass}">${badgeIcon}</span>
          </div>
          <div class="scc-desc">${escapeHtml(c.description)}</div>
          ${c.action ? `<div class="scc-action">💡 <strong>Ação Recomendada:</strong> <code>${escapeHtml(c.action)}</code></div>` : ''}
        </div>`;
    }).join('') + (checkedAt ? `<div class="text-muted" style="margin-top:12px;font-size:.85rem">${checkedAt}</div>` : '');
  } catch {
    list.innerHTML = '<div class="td-loading">Falha ao executar auditoria. Verifique sua conexão e tente novamente.</div>';
  }
}

// ── Backup & Recovery (Terabox + Restic) ────────────────────────────────────
const BKB_JOBS_TZ = 'America/Sao_Paulo';
const BKB_DAY_NAMES = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
const BKB_MAX_JOBS = 8;

let backupJobs = [];
let backupJobsDirty = false;

function bkbFmtBytes(bytes) {
  const n = parseFloat(bytes);
  if (!isFinite(n) || n <= 0) return '--';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function bkbFmtTs(ts) {
  const n = parseFloat(ts);
  if (!n) return null;
  try {
    return new Date(n * 1000).toLocaleString('pt-BR', { timeZone: BKB_JOBS_TZ });
  } catch {
    return new Date(n * 1000).toLocaleString('pt-BR');
  }
}

function bkbNextRun(job, from = new Date()) {
  if (!job || job.enabled === false) return null;
  const days = Array.isArray(job.days) && job.days.length ? job.days : [0];
  // Os jobs rodam no fuso America/Sao_Paulo; o navegador pode estar em outro
  // fuso (ex. UTC). Calcula o "hoje" de SP a partir do horario de SP.
  const spNow = new Date(new Date(from.getTime()).toLocaleString('en-US', { timeZone: BKB_JOBS_TZ }));
  for (let add = 0; add <= 7; add++) {
    const d = new Date(spNow.getTime());
    d.setDate(d.getDate() + add);
    if (!days.includes(d.getDay())) continue;
    const cand = new Date(d.getFullYear(), d.getMonth(), d.getDate(), job.hour || 0, job.minute || 0, 0, 0);
    // cand esta em hora local do navegador; compara contra o agora-SP
    // convertido p/ mesma base local.
    if (cand.getTime() <= spNow.getTime()) continue;
    return cand;
  }
  return null;
}

function bkbNextRunLabel(jobs) {
  let best = null;
  (jobs || []).forEach(j => {
    const c = bkbNextRun(j);
    if (c && (!best || c < best.date)) best = { date: c, job: j };
  });
  if (!best) return 'Sem agendamento ativo';
  const sameDay = new Date().toDateString() === best.date.toDateString();
  const hhmm = best.date.toLocaleTimeString('pt-BR', { timeZone: BKB_JOBS_TZ, hour: '2-digit', minute: '2-digit' });
  return sameDay
    ? `Hoje às ${hhmm} (${best.job.name})`
    : `${BKB_DAY_NAMES[best.date.getDay()]} às ${hhmm} (${best.job.name})`;
}

let isTerminalOpen = false;
let terminalPollTimer = null;

function updateBackupTelemetryUI(data) {
  const isRunning = !!data.running;
  const pct = isRunning ? Math.max(5, parseInt(data.percent || 0)) : (data.success || data.last_backup_status === 'success' ? 100 : 0);
  const stepName = data.step_name || (isRunning ? 'Processando backup...' : (pct === 100 ? 'Backup concluído com sucesso' : 'Pronto para iniciar'));

  // 1. Progress Bar & Percentage
  const fill = document.getElementById('bkb-progress-fill');
  if (fill) fill.style.width = pct + '%';
  setTextSafe('bkb-progress-pct', pct + '%');
  setTextSafe('bkb-current-step-name', stepName);

  const pulse = document.getElementById('bkb-pulse-indicator');
  if (pulse) {
    pulse.style.background = isRunning ? '#38bdf8' : (pct === 100 ? '#34d399' : '#94a3b8');
  }

  // 2. Direct Stats
  setTextSafe('bkb-eta', isRunning ? (data.eta || '~ 1m 30s') : (pct === 100 ? '0s (Concluído)' : '--'));
  setTextSafe('bkb-speed', isRunning ? (data.speed || 'Calculando...') : '--');
  setTextSafe('bkb-transferred', data.transferred || (data.archive_bytes ? bkbFmtBytes(data.archive_bytes) : '--'));

  // 3. Status Badge
  const badge = document.getElementById('backup-onedrive-badge');
  if (badge) {
    if (isRunning) {
      badge.className = 'status-chip status-chip-blue';
      badge.textContent = `🔵 Em Execução (${pct}%)`;
    } else if (data.success || data.last_backup_status === 'success') {
      badge.className = 'status-chip status-chip-emerald';
      badge.textContent = '🟢 Concluído';
    } else {
      badge.className = 'status-chip status-chip-amber';
      badge.textContent = 'Pronto';
    }
  }

  // 4. Action button
  const btnNow = document.getElementById('btn-backup-now');
  if (btnNow) {
    btnNow.disabled = isRunning;
    btnNow.innerHTML = isRunning 
      ? '<span class="spinner-sm" style="display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite;"></span> Executando Backup...'
      : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg> Fazer Backup Agora';
  }

  setTextSafe('bkb-last-date', bkbFmtTs(data.last_backup) || 'Nunca');
  setTextSafe('bkb-last-size', bkbFmtBytes(data.repo_bytes ?? data.last_backup_size));

  const msgEl = document.getElementById('bkb-message');
  if (msgEl) {
    msgEl.textContent = isRunning ? (data.message || 'Sincronizando com a nuvem...') : (data.message || '');
  }

  if (isTerminalOpen && isRunning) {
    fetchLiveBackupLogs();
  }
}

async function fetchBackupStatus() {
  try {
    const res = await fetch('/api/backup/status');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    updateBackupTelemetryUI(data);
    if (Array.isArray(data.jobs)) { backupJobs = data.jobs; renderBackupJobs(); }
  } catch (e) {
    console.error('fetchBackupStatus:', e);
    setTextSafe('bkb-message', 'Falha ao carregar status do backup — recarregue a página.');
  }
}

function toggleBackupTerminal() {
  isTerminalOpen = !isTerminalOpen;
  const wrap = document.getElementById('bkb-terminal-wrapper');
  const label = document.getElementById('btn-terminal-label');
  if (wrap) wrap.classList.toggle('hidden', !isTerminalOpen);
  if (label) label.textContent = isTerminalOpen ? 'Ocultar Terminal' : 'Ver Terminal em Tempo Real';
  if (isTerminalOpen) {
    fetchLiveBackupLogs();
  }
}

async function fetchLiveBackupLogs() {
  const pre = document.getElementById('bkb-live-log-content');
  const counter = document.getElementById('bkb-log-lines-count');
  if (!pre) return;
  try {
    const res = await fetch('/api/backup/live-logs');
    if (!res.ok) return;
    const data = await res.json();
    if (data.lines && Array.isArray(data.lines)) {
      pre.textContent = data.lines.join('');
      if (counter) counter.textContent = `${data.lines.length} linhas`;
      pre.scrollTop = pre.scrollHeight;
    }
  } catch {}
}function renderBackupJobs() {
  const box = document.getElementById('backup-jobs-list');
  if (!box) return;
  if (!backupJobs.length) {
    box.innerHTML = '<p class="section-card-desc bj-empty-hint">Nenhum agendamento configurado. Clique em “+ Novo horário”.</p>';
    return;
  }
  box.innerHTML = backupJobs.map((j, idx) => {
    const days = Array.isArray(j.days) ? j.days : [];
    const hh = String(j.hour ?? 0).padStart(2, '0');
    const mm = String(j.minute ?? 0).padStart(2, '0');
    const fixed = j.id === 'servidor';
    const dayChips = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom'].map((name, i) => {
      const d = (i + 1) % 7; // Seg=1..Sáb=6, Dom=0
      return `<button type="button" class="day-chip ${days.includes(d) ? 'on' : ''}" data-day="${d}">${name}</button>`;
    }).join('');
    return `
      <div class="bj-card" data-idx="${idx}" data-job-id="${escapeHtml(j.id || '')}">
        <div class="bj-card-head">
          <input type="text" class="bj-name" value="${escapeHtml(j.name || 'Backup')}" title="Nome do agendamento" />
          <label class="bj-switch" title="Ativar/desativar este agendamento">
            <input type="checkbox" class="bj-enabled" ${j.enabled !== false ? 'checked' : ''} /> ativo
          </label>
          <label class="bj-switch" title="Enviar para o Google Drive após backup local">
            <input type="checkbox" class="bj-cloud" ${j.cloud ? 'checked' : ''} /> nuvem
          </label>
          ${fixed
            ? '<span class="bj-locked" title="Protegido pelo sistema — não pode ser excluído">🔒 protegido</span>'
            : `<button type="button" class="bj-delete" onclick="removeBackupJob('${escapeHtml(j.id)}')">🗑 Excluir</button>`}
        </div>
        <div class="bj-fields">
          <div class="bj-field">
            <label>Dias</label>
            <div class="bj-days">${dayChips}</div>
          </div>
          <div class="bj-field">
            <label>Hora</label>
            <input type="number" class="bj-hour" min="0" max="23" value="${hh}" />
          </div>
          <div class="bj-field">
            <label>Min</label>
            <input type="number" class="bj-minute" min="0" max="59" value="${mm}" />
          </div>
          <div class="bj-field">
            <label>Manter (semanas)</label>
            <input type="number" class="bj-keep-weekly" min="1" max="12" value="${j.keep_weekly ?? 4}" />
          </div>
          <div class="bj-field">
            <label>Manter (meses)</label>
            <input type="number" class="bj-keep-monthly" min="1" max="12" value="${j.keep_monthly ?? 3}" />
          </div>
        </div>
      </div>`;
  }).join('');
}

function addBackupJob() {
  if (!backupJobs.length) {
    backupJobs = [{ id: 'servidor', name: 'Servidor completo', enabled: true, kind: 'restic-terabox', days: [0], hour: 23, minute: 0, keep_weekly: 4, keep_monthly: 3, cloud: true }];
  }
  if (backupJobs.length >= BKB_MAX_JOBS) {
    showToast(`Máximo de ${BKB_MAX_JOBS} agendamentos.`, 'error');
    return;
  }
  backupJobs.push({
    id: '', name: 'Novo backup', enabled: true, kind: 'restic-terabox',
    days: [1], hour: 12, minute: 0, keep_weekly: 4, keep_monthly: 3, cloud: true,
  });
  renderBackupJobs();
  markBackupJobsDirty();
}

function removeBackupJob(id) {
  if (id === 'servidor') {
    showToast('O job "Servidor completo" não pode ser apagado.', 'error');
    return;
  }
  backupJobs = backupJobs.filter(j => j.id !== id);
  renderBackupJobs();
  markBackupJobsDirty();
}

function collectBackupJobs() {
  const cards = document.querySelectorAll('#backup-jobs-list .bj-card');
  const out = [];
  cards.forEach((card) => {
    const jid = card.dataset.jobId || '';
    const base = backupJobs.find(b => (b.id || '') === jid) || backupJobs[Number(card.dataset.idx)] || {};
    const clamp = (v, lo, hi, def) => {
      const n = parseInt(v, 10);
      if (!Number.isFinite(n)) return def;
      return Math.min(hi, Math.max(lo, n));
    };
    const days = Array.from(card.querySelectorAll('.day-chip.on')).map(c => Number(c.dataset.day)).filter(d => Number.isFinite(d));
    out.push({
      id: jid || '',
      name: (card.querySelector('.bj-name')?.value || '').trim() || base.name || 'Backup',
      enabled: card.querySelector('.bj-enabled')?.checked ?? true,
      kind: 'restic-terabox',
      days: days.length ? days : [0],
      hour: clamp(card.querySelector('.bj-hour')?.value, 0, 23, base.hour ?? 23),
      minute: clamp(card.querySelector('.bj-minute')?.value, 0, 59, base.minute ?? 0),
      keep_weekly: clamp(card.querySelector('.bj-keep-weekly')?.value, 1, 12, base.keep_weekly ?? 4),
      keep_monthly: clamp(card.querySelector('.bj-keep-monthly')?.value, 1, 12, base.keep_monthly ?? 3),
      cloud: card.querySelector('.bj-cloud')?.checked ?? true,
    });
  });
  return out;
}

async function saveBackupConfig() {
  const jobs = collectBackupJobs();
  if (!jobs.length) {
    showToast('Nenhum agendamento para salvar.', 'error');
    return;
  }
  if (!jobs.some(j => j.id === 'servidor')) {
    showToast('O job "Servidor completo" não pode ser removido.', 'error');
    renderBackupJobs();
    return;
  }
  const btn = document.getElementById('btn-save-backup-jobs');
  if (btn) { btn.disabled = true; btn.textContent = 'Salvando…'; }
  try {
    const res = await fetch('/api/backup/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobs }),
    });
    const data = await res.json();
    if (data.success) {
      backupJobs = Array.isArray(data.jobs) && data.jobs.length ? data.jobs : jobs;
      backupJobsDirty = false;
      renderBackupJobs();
      if (btn) btn.textContent = 'Salvar agendamentos';
      showToast('Agendamentos salvos com sucesso!', 'success');
    } else {
      if (btn) btn.textContent = 'Salvar agendamentos •';
      showToast(data.error || 'Falha ao salvar agendamentos', 'error');
    }
  } catch (e) {
    console.error('saveBackupConfig:', e);
    if (btn) btn.textContent = 'Salvar agendamentos •';
    showToast('Erro de comunicação ao salvar agendamentos', 'error');
  } finally {
    if (btn) { btn.disabled = false; }
    if (typeof fetchBackupStatus === 'function') fetchBackupStatus();
  }
}

async function saveTeraboxCookie() {
  const el = document.getElementById('backup-terabox-cookie');
  if (!el) return;
  const cookie = el.value.trim();
  if (cookie.length < 8) {
    showToast('Cole o cookie (ndus) antes de salvar.', 'error');
    return;
  }
  try {
    const res = await fetch('/api/backup/terabox-cookie', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cookie }),
    });
    const data = await res.json();
    if (data.success) {
      el.value = '';
      showToast('Cookie salvo. A conexão será testada em até 1 minuto.', 'success');
    } else {
      showToast(data.error || 'Falha ao salvar cookie', 'error');
    }
  } catch (e) {
    console.error('saveTeraboxCookie:', e);
    showToast('Erro de comunicação ao salvar cookie', 'error');
  }
}

async function triggerManualBackup() {
  const btn = document.getElementById('btn-backup-now');
  if (btn) { btn.disabled = true; btn.textContent = 'Enfileirando…'; }
  try {
    const res = await fetch('/api/backup/trigger', { method: 'POST' });
    const data = await res.json();
    if (data.success) showToast(data.message || 'Backup enfileirado!', 'success');
    else showToast(data.error || 'Falha ao solicitar backup', 'error');
  } catch (e) {
    console.error('triggerManualBackup:', e);
    showToast('Erro de comunicação', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Fazer Backup Agora'; }
    setTimeout(fetchBackupStatus, 1500);
    BackupWatcher.start();
  }
}
// ── Audit Logs ──────────────────────────────────────────────────────────────
async function fetchAuditLogs() {
  const tbody = document.getElementById('audit-logs-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/audit');
    const data = await res.json();
    const logs = data.logs || [];

    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Nenhum evento registrado ainda</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const dateStr = l.timestamp ? new Date(l.timestamp * 1000).toLocaleString('pt-BR') : '--';
      return `
        <tr>
          <td class="mono-text">${dateStr}</td>
          <td><strong>${escapeHtml(l.username || 'admin')}</strong></td>
          <td><span class="status-chip status-chip-blue">${escapeHtml(l.action)}</span></td>
          <td>${escapeHtml(l.details || '')}</td>
          <td class="mono-text text-muted">${escapeHtml(l.ip_address || '--')}</td>
        </tr>`;
    }).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Falha ao carregar trilha de auditoria.</td></tr>';
  }
}

// ── Status Telemetry Polling ────────────────────────────────────────────────
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const data = await res.json();
    lastStatusData = data;
    updateDashboard(data);
  } catch {}
}

function updateDashboard(data) {
  const uptime = data.uptime || '--';
  setTextSafe('header-uptime-chip', uptime);
  setTextSafe('ov-uptime-val', uptime);

  // CPU
  const cpuPct = data.cpu_percent ?? 0;
  const cpuTemp = data.cpu_temp != null && data.cpu_temp != NaN ? `${data.cpu_temp}°C` : '--';
  setTextSafe('kpi-cpu-val', `${cpuPct}%`);
  setTextSafe('val-cpu-percent', `${cpuPct}%`);
  setBarWidth('kpi-cpu-bar', cpuPct);
  setTextSafe('kpi-cpu-meta', `Processamento atual: ${cpuPct}% · 🌡️ CPU ${cpuTemp}`);
  setTextSafe('cpu-badge', cpuTemp);
  setTextSafe('kpi-cpu-temp', cpuTemp);
  setGaugeValue('gauge-cpu-circle', cpuPct);

  // RAM
  const ramPct = data.ram_percent ?? 0;
  const ramUsed = data.ram_used_gb ?? '0';
  const ramTotal = data.ram_total_gb ?? '0';
  setTextSafe('kpi-ram-val', `${ramPct}%`);
  setTextSafe('val-ram-percent', `${ramPct}%`);
  setTextSafe('val-ram-text', `${ramUsed}/${ramTotal} GB`);
  setBarWidth('kpi-ram-bar', ramPct);
  setTextSafe('kpi-ram-meta', `${ramUsed} GB usados de ${ramTotal} GB`);
  setGaugeValue('gauge-ram-circle', ramPct);

  // Disk
  const diskPct = data.disk_percent ?? 0;
  const diskUsed = data.disk_used_gb ?? '0';
  const diskTotal = data.disk_total_gb ?? '0';
  setTextSafe('kpi-disk-val', `${diskPct}%`);
  setTextSafe('val-disk-percent', `${diskPct}%`);
  setTextSafe('val-disk-text', `${diskUsed}/${diskTotal} GB`);
  setBarWidth('kpi-disk-bar', diskPct);
  setTextSafe('kpi-disk-meta', `${diskUsed} GB usados de ${diskTotal} GB`);
  setGaugeValue('gauge-disk-circle', diskPct);

  // Network
  const netRx = prettyByteRate(data.net_rx_speed);
  const netTx = prettyByteRate(data.net_tx_speed);
  setTextSafe('kpi-net-val', netRx);
  setTextSafe('kpi-rx', netRx);
  setTextSafe('kpi-tx', netTx);
  setTextSafe('kpi-net-meta', `Total RX: ${prettyByteRate(data.net_rx_total)} · TX: ${prettyByteRate(data.net_tx_total)}`);

  // Containers
  const containers = data.containers || [];
  setTextSafe('ov-containers-count', containers.length);
  renderContainersTable('ov-containers-list', containers);
  renderContainersTable('server-containers-list', containers);

  // Services
  const services = data.services || [];
  setTextSafe('ov-services-count', services.length);
  renderAdminServices(services);

  // SSH — prioriza o túnel TCP do ngrok (acesso externo); Tailscale fica como
  // fallback LAN. O comando do modal e o botão "Copiar" usam o caminho ngrok.
  const tsIp = '100.92.242.64';
  const ngrokSshCmd = data.ngrok_ssh_cmd || (data.ngrok_ssh_host && data.ngrok_ssh_port ? `ssh decsv@${data.ngrok_ssh_host} -p ${data.ngrok_ssh_port}` : '') || (data.ngrok_ssh && data.ngrok_ssh.command ? data.ngrok_ssh.command : '') || 'ssh decsv@0.tcp.sa.ngrok.io -p 20015';
  latestSshCmd = ngrokSshCmd || `ssh decsv@${tsIp}`;
  setTextSafe('ip-ngrok-ssh-ext', ngrokSshCmd);
  setTextSafe('ip-ngrok-ssh', `ssh decsv@${tsIp}`);
  const modalCmd = document.getElementById('modal-ssh-cmd');
  if (modalCmd) modalCmd.textContent = latestSshCmd;

  // Gateway público — domínio fixo do ngrok (HomeHub) é o principal
  const ngrokUrl = data.ngrok_url || '';
  if (ngrokUrl) {
    latestPublicUrl = ngrokUrl;
    setTextSafe('ip-ngrok', ngrokUrl.replace(/^https?:\/\//, ''));
  } else if (!latestPublicUrl) {
    setTextSafe('ip-ngrok', 'Aguardando túnel ngrok…');
  }

  // Cloudflare (backup, porta 8000)
  const cfUrl = data.cf_url || '';
  if (cfUrl) {
    setTextSafe('ip-cf', cfUrl.replace(/^https?:\/\//, ''));
  } else {
    setTextSafe('ip-cf', 'Túnel offline');
  }

  // Terminal web (ttyd via Cloudflare)
  const termUrl = data.terminal_url || 'https://terminal.decamservice.com';
  latestTerminalUrl = termUrl;
  const cleanUrl = termUrl.replace(/^https?:\/\//, '');
  const termEl = document.getElementById('ip-terminal');
  if (termEl) {
    if (termUrl) {
      termEl.innerHTML = `<a href="${escapeHtml(termUrl)}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa; text-decoration:underline;">${escapeHtml(cleanUrl)}</a>`;
    } else {
      termEl.textContent = 'Aguardando túnel…';
    }
  }
  const openBtn = document.getElementById('btn-open-terminal');
  if (openBtn) {
    openBtn.href = termUrl;
    openBtn.style.display = 'inline-flex';
  }
}

function renderContainersTable(tbodyId, containers) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (!containers.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="td-loading">Nenhum container em execução</td></tr>';
    return;
  }
  tbody.innerHTML = containers.map(c => {
    const isUp = (c.status || '').toLowerCase().includes('up');
    return `
      <tr>
        <td><span class="mono-text">${escapeHtml(c.name || '--')}</span></td>
        <td class="text-muted">${escapeHtml(c.image || '--')}</td>
        <td><span class="status-chip ${isUp ? 'status-chip-green' : 'status-chip-red'}">${isUp ? '🟢 Rodando' : '🔴 Parado'}</span></td>
        <td class="mono-text text-muted">${escapeHtml(c.ports || '--')}</td>
      </tr>`;
  }).join('');
}

function renderAdminServices(services) {
  const grid = document.getElementById('infra-services-grid');
  if (!grid) return;
  if (!services.length) {
    grid.innerHTML = '<div class="empty-state-inline">Nenhum serviço detectado</div>';
    return;
  }
  grid.innerHTML = services.map(s => {
    const isOnline = s.status === 'online';
    return `
      <div class="infra-card">
        <div class="infra-card-header">
          <span class="infra-icon">${s.icon || '⚙️'}</span>
          <span class="status-chip ${isOnline ? 'status-chip-green' : 'status-chip-red'}">${isOnline ? 'Online' : 'Offline'}</span>
        </div>
        <div class="infra-name">${escapeHtml(s.name || 'Serviço')}</div>
        <div class="infra-desc">${escapeHtml(s.description || '')}</div>
        ${s.url ? `<a href="${s.url}" target="_blank" class="btn btn-sm btn-outline infra-btn">Acessar →</a>` : ''}
      </div>`;
  }).join('');
}

// ── Portal Projects Management ──────────────────────────────────────────────
async function fetchAdminProjects() {
  try {
    const res = await fetch('/api/projects');
    if (!res.ok) return;
    const data = await res.json();
    const projects = data.projects || [];
    setTextSafe('ov-apps-count', projects.length);
    renderAdminProjectsTable(projects);
  } catch {}
}

function renderAdminProjectsTable(projects) {
  const tbody = document.getElementById('admin-projects-list');
  if (!tbody) return;
  if (!projects.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="td-empty">Nenhuma aplicação cadastrada</td></tr>';
    return;
  }
  tbody.innerHTML = projects.map(p => {
    const href = catalogAppHref(p.url);
    const urlCell = href
      ? `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="catalog-url-link" title="Abrir no portal público">${escapeHtml(p.url)}</a>`
      : `<span class="text-muted">--</span>`;
    const openBtn = href
      ? `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary">Abrir ↗</a>`
      : '';
    return `
      <tr>
        <td style="font-size:1.5rem;text-align:center">${escapeHtml(p.icon || '🌐')}</td>
        <td><strong>${escapeHtml(p.name || '--')}</strong></td>
        <td><span class="cat-pill">${escapeHtml(p.category || 'Geral')}</span></td>
        <td class="mono-text">${urlCell}</td>
        <td><span class="status-chip ${p.status === 'online' ? 'status-chip-green' : 'status-chip-amber'}">${p.status || 'online'}</span></td>
        <td>${p.featured ? '⭐ Sim' : 'Não'}</td>
        <td>${p.published !== false ? '✓ Sim' : '✗ Não'}</td>
        <td>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${openBtn}
            <button class="btn btn-sm btn-outline" onclick="editProject('${escapeHtml(p.id)}')">Editar</button>
            <button class="btn btn-sm btn-danger" onclick="deleteProject('${escapeHtml(p.id)}')">Excluir</button>
          </div>
        </td>
      </tr>`;
  }).join('');
}

function prettyByteRate(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '0 B';
  const m = raw.match(/^([\d.]+)\s*([KMGT]?B)(?:\/s)?$/i);
  if (!m) return raw;
  let n = parseFloat(m[1]);
  if (!Number.isFinite(n) || n < 0) n = 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = Math.max(0, units.indexOf(m[2].toUpperCase()));
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  const text = i === 0
    ? `${Math.round(n)} ${units[i]}`
    : (n >= 100 ? `${n.toFixed(0)} ${units[i]}` : n >= 10 ? `${n.toFixed(1)} ${units[i]}` : `${n.toFixed(2)} ${units[i]}`);
  return /\/s$/i.test(raw) ? `${text}/s` : text;
}

function catalogAppHref(url) {
  const raw = String(url || '').trim();
  if (!raw) return '';
  const lower = raw.toLowerCase();
  if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('vbscript:')) return '';
  if (/^https?:\/\//i.test(raw)) return raw;
  if (raw.startsWith('//')) return window.location.protocol + raw;
  if (raw.startsWith('/')) return raw;
  return '/' + raw;
}

function openProjectModal() {
  document.getElementById('proj-id').value = '';
  document.getElementById('proj-name').value = '';
  document.getElementById('proj-category').value = 'Geral';
  document.getElementById('proj-icon').value = '🌐';
  document.getElementById('proj-url').value = '';
  document.getElementById('proj-desc').value = '';
  document.getElementById('proj-status').value = 'online';
  document.getElementById('proj-featured').checked = false;
  document.getElementById('proj-published').checked = true;
  document.getElementById('project-modal-title').textContent = 'Nova Aplicação';
  document.getElementById('project-modal').classList.add('active');
}

function editProject(id) {
  fetch('/api/projects').then(r => r.json()).then(data => {
    const p = (data.projects || []).find(x => x.id === id);
    if (!p) return;
    document.getElementById('proj-id').value = p.id;
    document.getElementById('proj-name').value = p.name || '';
    document.getElementById('proj-category').value = p.category || '';
    document.getElementById('proj-icon').value = p.icon || '🌐';
    document.getElementById('proj-url').value = p.url || '';
    document.getElementById('proj-desc').value = p.description || '';
    document.getElementById('proj-status').value = p.status || 'online';
    document.getElementById('proj-featured').checked = !!p.featured;
    document.getElementById('proj-published').checked = p.published !== false;
    document.getElementById('project-modal-title').textContent = 'Editar Aplicação';
    document.getElementById('project-modal').classList.add('active');
  });
}

function closeProjectModal() { document.getElementById('project-modal').classList.remove('active'); }

async function submitProjectSave() {
  const payload = {
    id: document.getElementById('proj-id').value,
    name: document.getElementById('proj-name').value.trim(),
    category: document.getElementById('proj-category').value.trim(),
    icon: document.getElementById('proj-icon').value.trim() || '🌐',
    url: document.getElementById('proj-url').value.trim(),
    description: document.getElementById('proj-desc').value.trim(),
    status: document.getElementById('proj-status').value,
    featured: document.getElementById('proj-featured').checked,
    published: document.getElementById('proj-published').checked,
  };

  try {
    const res = await fetch('/api/admin/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.success) {
      closeProjectModal();
      fetchAdminProjects();
      showToast('Aplicação salva com sucesso!', 'success');
    }
  } catch {}
}

async function deleteProject(id) {
  if (!confirm('Excluir esta aplicação do Portal, do Docker e do Deploy Center?')) return;
  try {
    const res = await fetch('/api/admin/projects/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const data = await res.json();
    fetchAdminProjects();
    fetchDeployedApps();
    fetchDeployHistory();
    if (data.success) {
      showToast('Aplicação removida do portal, Docker e Deploy Center.', 'success');
    } else {
      showToast(data.error || 'Falha ao excluir', 'error');
    }
  } catch {
    showToast('Erro de conexão', 'error');
  }
}

// ── Passwords & Helpers ─────────────────────────────────────────────────────
async function performChangePassword() {
  const oldPw = document.getElementById('old-password').value;
  const newPw = document.getElementById('new-password').value;
  const confirmPw = document.getElementById('confirm-password').value;
  const msgEl = document.getElementById('pw-change-msg');

  if (newPw !== confirmPw) {
    msgEl.textContent = 'As novas senhas não coincidem.';
    msgEl.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPw, new_password: newPw }),
    });
    const data = await res.json();
    if (data.success) {
      showToast('Senha alterada com sucesso!', 'success');
      document.getElementById('old-password').value = '';
      document.getElementById('new-password').value = '';
      document.getElementById('confirm-password').value = '';
      msgEl.classList.add('hidden');
    } else {
      msgEl.textContent = data.error || 'Erro ao alterar senha.';
      msgEl.classList.remove('hidden');
    }
  } catch {}
}

function openSshModal() { document.getElementById('ssh-modal').classList.add('active'); }
function closeSshModal() { document.getElementById('ssh-modal').classList.remove('active'); }
function copyNgrokSsh() {
  if (!latestSshCmd) {
    showToast('Túnel ngrok ainda não disponível.', 'error');
    return;
  }
  copyToClipboard(latestSshCmd);
}

function copyPublicUrl() {
  if (!latestPublicUrl) {
    showToast('Nenhuma URL pública disponível ainda.', 'error');
    return;
  }
  copyToClipboard(latestPublicUrl);
}

function copyTerminalUrl() {
  if (!latestTerminalUrl) {
    showToast('URL do terminal ainda não disponível.', 'error');
    return;
  }
  copyToClipboard(latestTerminalUrl);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
  });
  showToast('Copiado para a área de transferência!', 'success');
}

function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${type === 'success' ? '✓' : (type === 'error' ? '✕' : 'ℹ')}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-in'));
  setTimeout(() => {
    toast.classList.remove('toast-in');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function setTextSafe(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
function setBarWidth(id, pct) { const el = document.getElementById(id); if (el) el.style.width = `${Math.min(100, Math.max(0, pct))}%`; }
function setGaugeValue(id, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  const circ = 2 * Math.PI * 42;
  el.style.strokeDasharray = circ;
  el.style.strokeDashoffset = circ - (pct / 100) * circ;
}
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
// Safe embed for JS string literals inside onclick attributes: percent-encodes
// everything that could break out of quotes (' " < > % …). Decode with
// decodeURIComponent() inside the target function.
function jsStr(v) {
  return encodeURIComponent(String(v ?? ''));
}
// ── Notification Center ──────────────────────────────────────────────────────
const HHNotify = (() => {
  const STORAGE_KEY = 'hh_notifications';
  const UNREAD_KEY = 'hh_notif_unread';
  const EVENT_KEY = 'hh_notif_broadcast';
  const MAX_ITEMS = 50;
  let channel = null;
  let ready = false;
  const load = () => { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { return []; } };
  const save = (items) => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(items)); } catch {} };
  const getUnread = () => { const n = parseInt(localStorage.getItem(UNREAD_KEY) || '0', 10); return isNaN(n) ? 0 : n; };
  const setUnread = (n) => { try { localStorage.setItem(UNREAD_KEY, String(n)); } catch {} };
  function render() {
    const badge = document.getElementById('notif-badge');
    const count = getUnread();
    if (badge) { badge.textContent = count > 99 ? '99+' : String(count); badge.classList.toggle('hidden', count === 0); }
    const listEl = document.getElementById('notif-list');
    if (!listEl) return;
    const items = load();
    if (!items.length) { listEl.innerHTML = '<div class="notif-empty">Nenhuma notificação ainda</div>'; return; }
    listEl.innerHTML = items.map(function(n) {
      var iconMap = { success: '✓', error: '✕', info: 'ℹ' };
      var icon = iconMap[n.type] || 'ℹ';
      var time = new Date(n.ts).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
      return '<div class="notif-item ' + (n.type || 'info') + ' ' + (n.read ? '' : 'unread') + '"><div class="notif-item-icon">' + icon + '</div><div class="notif-item-body">' + (n.title ? '<div class="notif-item-title">' + escapeHtml(n.title) + '</div>' : '') + '<div class="notif-item-msg">' + escapeHtml(n.message) + '</div><div class="notif-item-time">' + escapeHtml(time) + '</div></div></div>';
    }).join('');
  }
  function ingest(payload) {
    var items = load();
    if (items.some(function(n) { return n.id === payload.id; })) return;
    items.unshift(payload);
    while (items.length > MAX_ITEMS) items.pop();
    save(items); setUnread(getUnread() + 1);
    showToast(payload.message, payload.type);
    render();
  }
  function show(opts) {
    var payload = { id: opts.eventId || ('n-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)), title: opts.title || '', message: opts.message || '', type: opts.type || 'info', persistent: !!opts.persistent, ts: Date.now(), read: false };
    var items = load();
    if (items.some(function(n) { return n.id === payload.id; })) return;
    items.unshift(payload);
    while (items.length > MAX_ITEMS) items.pop();
    save(items); setUnread(getUnread() + 1);
    showToast(payload.message, payload.type);
    render();
    try { localStorage.setItem(EVENT_KEY, JSON.stringify(payload)); } catch (e) {}
    try { if (channel) channel.postMessage(payload); } catch (e) {}
  }
  function init() {
    if (ready) return; ready = true;
    try { channel = new BroadcastChannel('homehub-notify'); channel.onmessage = function(e) { if (e.data && e.data.id) ingest(e.data); }; } catch (e) {}
    window.addEventListener('storage', function(e) { if (e.key === EVENT_KEY && e.newValue) { try { ingest(JSON.parse(e.newValue)); } catch (ex) {} } });
    document.addEventListener('click', function(e) { var w = document.querySelector('.notif-wrapper'); var c = document.getElementById('notif-center'); if (w && c && !w.contains(e.target)) c.classList.add('hidden'); });
    render();
  }
  function toggle() {
    var el = document.getElementById('notif-center');
    if (!el) return;
    if (el.classList.contains('hidden')) { el.classList.remove('hidden'); var items = load().map(function(n) { return Object.assign({}, n, { read: true }); }); save(items); setUnread(0); render(); }
    else { el.classList.add('hidden'); }
  }
  function markAllRead() { var items = load().map(function(n) { return Object.assign({}, n, { read: true }); }); save(items); setUnread(0); render(); }
  function clearAll() { save([]); setUnread(0); render(); }
  return { init: init, show: show, toggle: toggle, markAllRead: markAllRead, clearAll: clearAll, render: render };
})();


// ── Backup Status Watcher (continuous polling + completion detection) ─────────
const BackupWatcher = (() => {
  let pollTimer = null;
  let wasRunning = false;
  let lastTs = null;
  const POLL_MS = 2000;

  async function poll() {
    if (!isAuthenticated) return;
    try {
      const res = await fetch('/api/backup/status', { credentials: 'same-origin' });
      if (res.status === 401 || res.status === 403) {
        stop();
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      const isRunning = !!data.running;
      const ts = data.last_backup || 0;
      const startedAt = data.started_at || data.written_at || 0;

      // Detect start (only if started within last 30 min, to avoid stale "running" from old backups)
      if (isRunning && !wasRunning) {
        const recent = startedAt > (Date.now() / 1000 - 1800);
        if (recent) {
          HHNotify.show({ title: 'Backup', message: '🔄 Backup iniciado — acompanhe pelo painel ou por aqui.', type: 'info' });
        }
      }

      if (wasRunning && !isRunning) {
        const isNew = ts && ts !== lastTs && ts > (Date.now() / 1000 - 1800);
        if (isNew) {
          const success = data.local_ok || data.success || data.last_backup_status === 'success' || data.last_backup_status === 'partial';
          const partial = data.last_backup_status === 'partial' || !!data.exit_partial;
          const cloudOk = data.cloud === 'ok';
          const cloudSkipped = data.cloud === 'skipped';
          const cloudErr = data.cloud_error;
          var msg, ntype;
          if (success && cloudOk && partial) { msg = '⚠️ Backup concluído com avisos (prune/check) e enviado para o Google Drive. Veja o log.'; ntype = 'info'; }
          else if (success && cloudOk) { msg = '✅ Backup concluído com sucesso e enviado para o Google Drive!'; ntype = 'success'; }
          else if (success && cloudSkipped) { msg = '✅ Backup local concluído. Nuvem pulada (cookie ausente).'; ntype = 'success'; }
          else if (success) { msg = '✅ Backup local concluído.'; if (cloudErr) msg += ' Nuvem: ' + cloudErr; ntype = 'success'; }
          else { msg = '❌ Backup falhou. ' + (data.message || 'Verifique os logs.'); ntype = 'error'; }
          // Deterministic ID prevents duplicate notifications across tabs
          var eid = 'backup-done-' + Math.floor(ts);
          HHNotify.show({ eventId: eid, title: 'Backup concluído', message: msg, type: ntype, persistent: true });
          if (typeof fetchBackupSnapshots === 'function') setTimeout(fetchBackupSnapshots, 2500);
          if (typeof fetchBackupStatus === 'function') setTimeout(fetchBackupStatus, 1000);
        }
        stop();
      }

      wasRunning = isRunning;
      if (ts) lastTs = ts;
      updateBackupTelemetryUI(data);
      if (isRunning && !pollTimer) start();
    } catch (e) {
      console.error('BackupWatcher.poll:', e);
    }
  }

  function start() {
    if (!isAuthenticated) return;
    if (pollTimer) return;
    pollTimer = setInterval(poll, POLL_MS);
    poll();
  }

  function stop() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  return { start: start, stop: stop };
})();

(function injectCatalogLinkStyle() {
  if (document.getElementById('catalog-url-link-style')) return;
  const style = document.createElement('style');
  style.id = 'catalog-url-link-style';
  style.textContent = '.catalog-url-link{color:#60a5fa;text-decoration:none;border-bottom:1px dashed rgba(96,165,250,.6)}.catalog-url-link:hover{color:#93c5fd;border-bottom-color:#93c5fd}.deploy-done-link{color:inherit;text-decoration:none;font-weight:600}#deploy-pct-wrap{display:flex;align-items:center;gap:12px;margin:0 0 10px;padding:10px 12px;background:#0b1220;border:1px solid #1e3a5f;border-radius:10px}.deploy-pct-label{color:#94a3b8;font-size:.85rem;min-width:160px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.deploy-pct-track{flex:1;height:8px;background:#1e293b;border-radius:99px;overflow:hidden}.deploy-pct-fill{height:100%;width:0;background:linear-gradient(90deg,#3b82f6,#22d3ee);transition:width .25s ease}.deploy-pct-num{font-variant-numeric:tabular-nums;color:#93c5fd;min-width:3.2em;text-align:right;font-weight:600}#github-branch{width:100%;cursor:pointer}.btn-dismiss-deploy{margin-left:8px;background:transparent;border:1px solid #334155;color:#94a3b8;border-radius:8px;padding:4px 10px;cursor:pointer;font-size:.8rem}.btn-dismiss-deploy:hover{border-color:#64748b;color:#e2e8f0}';
  document.head.appendChild(style);
})();

function markBackupJobsDirty() {
  backupJobsDirty = true;
  const btn = document.getElementById('btn-save-backup-jobs');
  if (btn) btn.textContent = 'Salvar agendamentos •';
}

(function initBackupJobsEvents() {
  const box = document.getElementById('backup-jobs-list');
  if (!box) return;
  box.addEventListener('click', (e) => {
    const chip = e.target.closest('.day-chip');
    if (chip) { chip.classList.toggle('on'); markBackupJobsDirty(); }
  });
  box.addEventListener('input', markBackupJobsDirty);
  box.addEventListener('change', markBackupJobsDirty);
})();

// ── Persistência da página ativa (F5 volta onde estava) ─────────────────────
const VALID_PAGES = ['overview', 'server', 'deploy', 'applications', 'services', 'network', 'security', 'backup', 'audit', 'users', 'settings'];

function validPageKey(p) {
  const key = String(p || '').replace(/^#/, '');
  return VALID_PAGES.includes(key) ? key : null;
}

window.addEventListener('popstate', (e) => {
  const page = validPageKey(e.state && e.state.page) || validPageKey(location.hash) || 'overview';
  navigateTo(page);
});

function bootRestorePage() {
  let stored = null;
  try { stored = localStorage.getItem('hh_admin_page'); } catch {}
  const initial = validPageKey(location.hash) || validPageKey(stored) || 'overview';
  const known = document.getElementById(`page-${initial}`) ? initial : 'overview';
  if (known !== 'overview') navigateTo(known);
}

// ── Histórico & Restauração (Restic) ────────────────────────────────────────
let restoreState = { running: false, snapshotId: null, pollTimer: null, staleTimer: null };
let lastSnapshots = [];

async function fetchBackupSnapshots() {
  try {
    const res = await fetch('/api/backup/snapshots');
    if (!res.ok) return;
    const data = await res.json();
    lastSnapshots = data.snapshots || [];
    renderSnapshots(lastSnapshots);
    updateRestoreBanner(data.restore || {}, !!data.stale);
  } catch (e) {
    console.error('fetchBackupSnapshots:', e);
  }
}

function snapDate(ts) {
  if (!ts) return null;
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
  return isNaN(d) ? null : d;
}

function renderSnapshots(snapshots) {
  const tbody = document.getElementById('snapshots-tbody');
  if (!tbody) return;
  if (!snapshots.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="td-loading">Nenhum snapshot no histórico ainda — clique em “Fazer Backup Agora”.</td></tr>';
    return;
  }
  const sorted = snapshots.slice().sort((a, b) => (snapDate(b.time)?.getTime() || 0) - (snapDate(a.time)?.getTime() || 0));
  tbody.innerHTML = sorted.map(s => {
    const id = String(s.id || s.short_id || '');
    const dsn = snapDate(s.time);
    const when = dsn ? dsn.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) : '--';
    const paths = (s.paths || []).map(p => String(p).replace('/home/decsv/', '~/')).join(' · ');
    const host = s.hostname ? escapeHtml(s.hostname) : '';
    return `
      <tr>
        <td class="mono-text">${when}</td>
        <td class="mono-text mono-id" title="${escapeHtml(id)}">${escapeHtml(id.substring(0, 8))}</td>
        <td class="text-muted text-xs"><span title="${escapeHtml(paths)}">${escapeHtml(paths.substring(0, 64))}${paths.length > 64 ? '…' : ''}</span><br><span class="text-muted">${host}</span></td>
        <td class="mono-text">${s.size ? bkbFmtBytes(s.size) : '--'}</td>
        <td><button class="btn btn-outline btn-sm btn-restore" onclick="openRestoreModal('${escapeHtml(id)}', '${when}')" ${restoreState.running ? 'disabled' : ''}>↩ Restaurar</button></td>
      </tr>`;
  }).join('');
}

function refreshRestoreButtons() { renderSnapshots(lastSnapshots); }

function updateRestoreBanner(restore, stale) {
  const banner = document.getElementById('restore-active-banner');
  restoreState.running = !!restore.running;
  if (banner) {
    const isRecent = restore.written_at && ((Date.now() / 1000 - restore.written_at) < 120);
    if (restore.running) {
      banner.classList.remove('hidden');
      banner.innerHTML = '<span class="restore-spinner"></span>' + escapeHtml(restore.message || 'Restauração em andamento…');
    } else if (restore.message && isRecent) {
      banner.classList.remove('hidden');
      banner.textContent = (restore.success === false ? '⚠ ' : 'ℹ ') + restore.message;
    } else {
      banner.classList.add('hidden');
    }
  }
  const hint = document.getElementById('snapshots-hint');
  if (hint) {
    if (stale && !restore.running) {
      hint.textContent = 'Lista de snapshots desatualizada — atualizando no servidor…';
      hint.classList.remove('hidden');
      if (!restoreState.staleTimer) {
        restoreState.staleTimer = setTimeout(() => { restoreState.staleTimer = null; fetchBackupSnapshots(); }, 10000);
      }
    } else {
      hint.classList.add('hidden');
    }
  }
  if (restore.running && !restoreState.pollTimer) {
    restoreState.pollTimer = setInterval(() => {
      fetchBackupSnapshots();
      if (!restoreState.running && restoreState.pollTimer) {
        clearInterval(restoreState.pollTimer);
        restoreState.pollTimer = null;
      }
    }, 8000);
  }
  refreshRestoreButtons();
}

function openRestoreModal(id, when) {
  restoreState.snapshotId = id;
  const info = document.getElementById('restore-modal-info');
  if (info) {
    info.innerHTML = `Restaurar o snapshot <strong class="mono-text">${escapeHtml(id.substring(0, 8))}</strong> de <strong>${escapeHtml(when)}</strong>?` +
      '<br><span class="text-muted">Os arquivos do snapshot são copiados por cima dos atuais (nada é apagado). Após uma restauração completa, o painel é reiniciado automaticamente.</span>';
  }
  const inc = document.getElementById('restore-include');
  if (inc) inc.value = '';
  const dry = document.getElementById('restore-dryrun');
  if (dry) dry.checked = false;
  const err = document.getElementById('restore-modal-error');
  if (err) err.classList.add('hidden');
  document.getElementById('restore-modal').classList.add('active');
}

function closeRestoreModal() { document.getElementById('restore-modal').classList.remove('active'); }

async function confirmRestore() {
  const btn = document.getElementById('btn-confirm-restore');
  const errBox = document.getElementById('restore-modal-error');
  if (errBox) errBox.classList.add('hidden');
  const include = (document.getElementById('restore-include')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const dryRun = !!document.getElementById('restore-dryrun')?.checked;
  if (btn) { btn.disabled = true; btn.textContent = 'Enviando…'; }
  try {
    const res = await fetch('/api/backup/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ snapshot_id: restoreState.snapshotId, include, dry_run: dryRun }),
    });
    const data = await res.json();
    if (data.success) {
      closeRestoreModal();
      showToast(data.message || 'Restauração solicitada!', 'success');
      setTimeout(fetchBackupSnapshots, 1500);
    } else if (errBox) {
      errBox.textContent = data.error || 'Falha ao solicitar restauração';
      errBox.classList.remove('hidden');
    }
  } catch (e) {
    console.error('confirmRestore:', e);
    if (errBox) {
      errBox.textContent = 'Erro de comunicação com o servidor';
      errBox.classList.remove('hidden');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Confirmar restauração'; }
  }
}
// ══════════════════════════════════════════════════════════════════════════
// FILE MANAGER
// ══════════════════════════════════════════════════════════════════════════
let fmCurrent = '';
let fmSelected = new Set(); // paths selecionados da pasta atual

function fmSelCountLabel() {
  const btn = document.getElementById('fm-delete-selected');
  if (!btn) return;
  const n = fmSelected.size;
  btn.style.display = n > 0 ? '' : 'none';
  btn.textContent = '🗑 excluir selecionados (' + n + ')';
}

function fmSize(size) {
  if (size == null) return '';
  if (size < 1024) return size + ' B';
  if (size < 1024 * 1024) return (size / 1024).toFixed(1) + ' KB';
  if (size < 1024 * 1024 * 1024) return (size / (1024 * 1024)).toFixed(1) + ' MB';
  return (size / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function fmDate(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleString();
}

async function loadFiles(relPath) {
  const url = '/api/files?path=' + encodeURIComponent(relPath || '');
  const info = document.getElementById('fm-info');
  const list = document.getElementById('fm-list');
  if (!info || !list) return;
  fmSelected.clear();
  fmSelCountLabel();
  const allChk = document.getElementById('fm-check-all');
  if (allChk) allChk.checked = false;
  info.textContent = 'Carregando...';
  try {
    const resp = await fetch(url);
    const data = await resp.json();
    if (!data.success) {
      info.textContent = 'Erro: ' + (data.error || 'desconhecido');
      return;
    }
    fmCurrent = data.current || '';
    const pathInput = document.getElementById('fm-path');
    if (pathInput) pathInput.value = '/' + (data.current || '');
    info.textContent = 'Raiz: ' + data.root + '  |  Atual: ' + data.absolute;
    renderFiles(data);
  } catch (e) {
    info.textContent = 'Falha ao listar: ' + e;
  }
}

function renderFiles(data) {
  const list = document.getElementById('fm-list');
  if (!list) return;
  list.innerHTML = '';

  const allChk = document.getElementById('fm-check-all');
  if (allChk) { allChk.checked = false; allChk.onchange = null; }

  const downAllBtn = document.getElementById('fm-download-all');
  if (downAllBtn) {
    downAllBtn.textContent = (data.parent !== null && data.parent !== undefined)
      ? '⬇ baixar esta pasta (ZIP)'
      : '⬇ baixar tudo (ZIP)';
  }

  if (data.parent !== null && data.parent !== undefined) {
    const tr = document.createElement('tr');
    tr.className = 'fm-dir';
    tr.innerHTML = '<td></td><td class="fm-name">.. (voltar)</td><td>dir</td><td class="fm-size"></td><td class="fm-date"></td><td></td>';
    tr.querySelector('.fm-name').addEventListener('click', () => loadFiles(data.parent));
    list.appendChild(tr);
  }

  if (!data.items || data.items.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="6" class="fm-empty">Pasta vazia</td>';
    list.appendChild(tr);
    return;
  }

  data.items.forEach(item => {
    const tr = document.createElement('tr');
    const isSelected = fmSelected.has(item.path);
    if (item.type === 'dir') tr.className = 'fm-dir';
    if (isSelected) tr.classList.add('fm-row-selected');
    const icon = item.type === 'dir' ? '📁' : '📄';
    const sizeCell = item.type === 'dir' ? '' : fmSize(item.size);
    tr.innerHTML = [
      '<td><input type="checkbox" class="fm-check" data-path="' + encodeURIComponent(item.path) + '" ' + (isSelected ? 'checked' : '') + '/></td>',
      '<td class="fm-name">' + icon + ' ' + item.name + '</td>',
      '<td>' + item.type + '</td>',
      '<td class="fm-size">' + sizeCell + '</td>',
      '<td class="fm-date">' + fmDate(item.mtime) + '</td>',
      '<td class="fm-actions"></td>'
    ].join('');

    const nameCell = tr.querySelector('.fm-name');
    const chk = tr.querySelector('.fm-check');
    if (item.type === 'dir') {
      nameCell.addEventListener('click', () => loadFiles(item.path));
    }
    chk.addEventListener('change', () => {
      if (chk.checked) fmSelected.add(item.path);
      else fmSelected.delete(item.path);
      tr.classList.toggle('fm-row-selected', chk.checked);
      fmSelCountLabel();
    });

    const actions = tr.querySelector('.fm-actions');
    const dl = document.createElement('button');
    dl.className = 'dl';
    dl.textContent = item.type === 'dir' ? 'ZIP' : 'Baixar';
    dl.title = item.type === 'dir' ? 'Baixar pasta como ZIP' : 'Baixar arquivo';
    dl.addEventListener('click', () => {
      const url = item.type === 'dir'
        ? '/api/files/download-all?path=' + encodeURIComponent(item.path)
        : '/api/files/download?path=' + encodeURIComponent(item.path);
      window.open(url, '_blank');
    });
    actions.appendChild(dl);

    const del = document.createElement('button');
    del.className = 'del';
    del.textContent = 'Excluir';
    del.addEventListener('click', () => {
      if (confirm('Excluir permanentemente "' + item.name + '" (' +
          (item.type === 'dir' ? 'pasta e todo o conteúdo' : 'arquivo') + ')?\n' +
          item.path)) {
        deleteFiles([item.path]);
      }
    });
    actions.appendChild(del);

    list.appendChild(tr);
  });

  if (allChk) allChk.onchange = () => {
    const checked = allChk.checked;
    document.querySelectorAll('#fm-list .fm-check').forEach(c => {
      c.checked = checked;
      const path = decodeURIComponent(c.dataset.path);
      if (checked) fmSelected.add(path);
      else fmSelected.delete(path);
      c.closest('tr').classList.toggle('fm-row-selected', checked);
    });
    fmSelCountLabel();
  };
  fmSelCountLabel();
}

document.addEventListener('click', (e) => {
  const up = e.target.closest('#fm-up');
  const home = e.target.closest('#fm-home');
  const refresh = e.target.closest('#fm-refresh');
  const go = e.target.closest('#fm-go');
  const downAll = e.target.closest('#fm-download-all');
  const delSel = e.target.closest('#fm-delete-selected');
  if (up) {
    if (fmCurrent) { const p = fmCurrent.split('/'); p.pop(); loadFiles(p.join('/')); }
    else loadFiles('');
  } else if (home) {
    loadFiles('');
  } else if (refresh) {
    loadFiles(fmCurrent);
  } else if (downAll) {
    window.open('/api/files/download-all?path=' + encodeURIComponent(fmCurrent), '_blank');
  } else if (delSel) {
    if (fmSelected.size === 0) return;
    if (confirm('Excluir permanentemente ' + fmSelected.size + ' item(ns) selecionado(s)?')) {
      deleteFiles([...fmSelected]);
    }
  } else if (go) {
    const input = document.getElementById('fm-path');
    loadFiles(input ? (input.value || '').replace(/^\/+/, '') : '');
  }
});

function listenEnter() {
  const input = document.getElementById('fm-path');
  if (input) input.addEventListener('keypress', (ev) => {
    if (ev.key === 'Enter') { const go = document.getElementById('fm-go'); if (go) go.click(); }
  });
}
listenEnter();

async function deleteFiles(paths) {
  let errors = [];
  for (const path of paths) {
    try {
      const resp = await fetch('/api/files/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path })
      });
      const data = await resp.json();
      if (!data.success) errors.push((path || '/') + ': ' + (data.error || resp.status));
    } catch (e) {
      errors.push((path || '/') + ': ' + e);
    }
  }
  fmSelected.clear();
  if (errors.length) alert('Concluído com erros:\n' + errors.join('\n'));
  else if (paths.length) alert('Excluído(s) com sucesso.');
  loadFiles(fmCurrent);
}

// ═══════════════════════════════════════════════════════════════════════════
// USUÁRIOS & TERMINAIS (RBAC) — 05/09/2026
// Página Administração > Usuários: CRUD de usuários Hub, sessões do terminal
// (live) e auditoria do terminal. Permissões via /api/whoami.
// ═══════════════════════════════════════════════════════════════════════════
HH_ME = HH_ME || null;
HUB_USERS = HUB_USERS || [];
TERM_SESSIONS = TERM_SESSIONS || [];

const ROLE_BADGE = {
  root:      { label: 'ROOT',      cls: 'status-chip-red' },
  sysadmin:  { label: 'SYSADMIN',  cls: 'status-chip-amber' },
  developer: { label: 'DEVELOPER', cls: 'status-chip-blue' },
  user1:     { label: 'NÍVEL 1',   cls: '' },
};

async function fetchWhoami(force = false) {
  if (HH_ME && !force) return HH_ME;
  try {
    const res = await fetch('/api/whoami');
    const d = await res.json();
    if (d && d.success) { HH_ME = d; return HH_ME; }
  } catch {}
  return null;
}

// Esconde itens do menu sem permissão e protege a página atual.
async function applyRoleBasedUI() {
  const me = await fetchWhoami(true);
  if (!me) return;
  const perms = me.perms || {};
  const navPerms = {
    server: perms.docker,
    deploy: perms.deploy,
    backup: perms.backups,
    security: perms.security,
    audit: perms.audit_view,
    users: perms.users_manage,
  };
  Object.entries(navPerms).forEach(([page, allowed]) => {
    if (allowed === false) {
      const btn = document.querySelector(`.sidebar-nav-item[data-page="${page}"]`);
      if (btn) btn.style.display = 'none';
    }
  });
  const logoutBtn = document.querySelector('button[onclick="performLogout()"]');
  if (logoutBtn) logoutBtn.title = `Encerrar sessão (${me.name || me.username} · ${String(me.role || '').toUpperCase()})`;
  const cur = currentPage || 'overview';
  if (navPerms[cur] === false) navigateTo('overview');
}

async function loadUsersPage() {
  await fetchWhoami();
  loadHubUsers();
  loadTerminalSessions();
}

function hubUserById(id) { return HUB_USERS.find(u => u.id === id) || null; }

async function loadHubUsers() {
  try {
    const res = await fetch('/api/admin/hubusers');
    const data = await res.json();
    HUB_USERS = (data.success && data.users) ? data.users : [];
    renderHubUsers(HUB_USERS);
  } catch {
    const tbody = document.getElementById('users-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="td-loading">Falha ao carregar usuários.</td></tr>';
  }
}

function renderHubUsers(users) {
  const grid = document.getElementById('users-stats-grid');
  if (grid) {
    const active = users.filter(u => u.active).length;
    const admins = users.filter(u => ['root', 'sysadmin'].includes(u.role)).length;
    const sessions = users.reduce((a, u) => a + (u.active_sessions || 0), 0);
    grid.innerHTML = `
      <div class="user-stat"><span class="user-stat-label">Usuários</span><span class="user-stat-value">${users.length}</span></div>
      <div class="user-stat"><span class="user-stat-label">Ativos</span><span class="user-stat-value">${active}</span></div>
      <div class="user-stat"><span class="user-stat-label">Administradores</span><span class="user-stat-value">${admins}</span></div>
      <div class="user-stat"><span class="user-stat-label">Sessões de terminal</span><span class="user-stat-value">${sessions}</span></div>`;
  }
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="td-loading">Nenhum usuário cadastrado. Clique em "+ Criar usuário".</td></tr>';
    return;
  }
  tbody.innerHTML = users.map(u => {
    const rb = ROLE_BADGE[u.role] || ROLE_BADGE.user1;
    const isRoot = u.role === 'root';
    const statusChip = u.active
      ? '<span class="status-chip status-chip-green">Ativo</span>'
      : '<span class="status-chip status-chip-red">Inativo</span>';
    const sessBtn = `<button class="status-chip status-chip-blue" style="cursor:pointer;border:none" onclick="viewUserSessions('${u.id}')" title="Ver/encerrar sessões">${u.active_sessions || 0} ativa(s)</button>`;
    const actions = [];
    if (!isRoot) {
      actions.push(`<button class="btn btn-outline btn-sm" title="Editar usuário" onclick="openUserModalById('${u.id}')">✏️</button>`);
      actions.push(`<button class="btn btn-outline btn-sm" title="Redefinir senha" onclick="openUserPasswordModal('${u.id}')">🔑</button>`);
      actions.push(u.active
        ? `<button class="btn btn-outline btn-sm" title="Desativar login" onclick="toggleUserActive('${u.id}')">⏸</button>`
        : `<button class="btn btn-outline btn-sm" title="Ativar login" onclick="toggleUserActive('${u.id}')">▶️</button>`);
      if (HH_ME && HH_ME.perms && HH_ME.perms.users_delete) {
        actions.push(`<button class="btn btn-danger btn-sm" title="Excluir usuário" onclick="deleteHubUser('${u.id}')">🗑</button>`);
      }
    } else {
      actions.push('<span class="text-muted" title="Conta principal protegida">🔒 Protegido</span>');
    }
    return `<tr>
      <td><div class="mono-text"><strong>${escapeHtml(u.username)}</strong></div><div class="text-muted">${escapeHtml(u.name || '')}</div></td>
      <td><span class="status-chip ${rb.cls}">${rb.label}</span></td>
      <td class="text-muted">${escapeHtml(u.email || '—')}</td>
      <td class="text-muted">${escapeHtml(u.last_login || '—')}</td>
      <td>${sessBtn}</td>
      <td>${statusChip}</td>
      <td><div style="display:flex;gap:6px;flex-wrap:wrap">${actions.join('')}</div></td>
    </tr>`;
  }).join('');
}

// ── Modal criar/editar usuário ──────────────────────────────────────────────
function openUserModalById(id) { openUserModal(hubUserById(id)); }

function openUserModal(user) {
  const modal = document.getElementById('user-modal');
  if (!modal) return;
  const isEdit = !!(user && user.id);
  setTextSafe('user-modal-title', isEdit ? '✏️ Editar usuário' : '+ Criar usuário');
  const errBox = document.getElementById('user-modal-error');
  if (errBox) { errBox.classList.add('hidden'); errBox.textContent = ''; }
  document.getElementById('uf-id').value = isEdit ? user.id : '';
  document.getElementById('uf-name').value = isEdit ? (user.name || '') : '';
  const un = document.getElementById('uf-username');
  un.value = isEdit ? user.username : '';
  un.disabled = isEdit;
  document.getElementById('uf-email').value = isEdit ? (user.email || '') : '';
  const sel = document.getElementById('uf-role');
  // SYSADMIN só pode ser atribuído por quem tem level >= 4 (ROOT/SYSADMIN).
  const hasSys = [...sel.options].some(o => o.value === 'sysadmin');
  if (HH_ME && HH_ME.level >= 4) {
    if (!hasSys) {
      const opt = document.createElement('option');
      opt.value = 'sysadmin';
      opt.textContent = 'Sysadmin (administra usuários comuns)';
      sel.appendChild(opt);
    }
  } else if (hasSys && !(isEdit && user.role === 'sysadmin')) {
    [...sel.options].find(o => o.value === 'sysadmin').remove();
  }
  sel.value = isEdit ? user.role : 'user1';
  document.getElementById('uf-active').checked = isEdit ? !!user.active : true;
  document.getElementById('uf-password').value = '';
  setTextSafe('uf-password-label', isEdit
    ? 'Nova senha (opcional — em branco mantém a atual, mínimo 6)'
    : 'Senha * (mínimo 6 caracteres)');
  modal.classList.add('active');
}

function closeUserModal() {
  const modal = document.getElementById('user-modal');
  if (modal) modal.classList.remove('active');
}

function showUserModalError(msg) {
  const box = document.getElementById('user-modal-error');
  if (box) { box.textContent = msg; box.classList.remove('hidden'); }
  showToast(msg, 'error');
}

async function submitUserForm() {
  const id = document.getElementById('uf-id').value;
  const name = document.getElementById('uf-name').value.trim();
  const username = document.getElementById('uf-username').value.trim();
  const email = document.getElementById('uf-email').value.trim();
  const role = document.getElementById('uf-role').value;
  const active = document.getElementById('uf-active').checked;
  const password = document.getElementById('uf-password').value;
  const isEdit = !!id;

  if (!username) { showUserModalError('Informe o username.'); return; }
  if (!isEdit && !password) { showUserModalError('Informe a senha inicial.'); return; }
  if (password && password.length < 6) { showUserModalError('A senha deve ter pelo menos 6 caracteres.'); return; }

  try {
    if (!isEdit) {
      const res = await fetch('/api/admin/hubusers', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, username, email, role, password, active }),
      });
      const d = await res.json();
      if (!d.success) { showToast(d.error || 'Falha ao criar usuário.', 'error'); return; }
      showToast(`Usuário ${username} criado${d.terminal_synced ? '' : ' (terminal fora do ar — sincronize depois)'}.`);
    } else {
      const res = await fetch(`/api/admin/hubusers/${id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, role, active }),
      });
      const d = await res.json();
      if (!d.success) { showToast(d.error || 'Falha ao salvar usuário.', 'error'); return; }
      if (password) {
        const rp = await fetch(`/api/admin/hubusers/${id}/password`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });
        const dp = await rp.json();
        if (!dp.success) {
          showToast(dp.error || 'Usuário salvo, mas a senha não foi alterada.', 'error');
          closeUserModal(); loadHubUsers(); return;
        }
      }
      showToast('Usuário atualizado.');
    }
    closeUserModal();
    loadHubUsers();
  } catch {
    showToast('Erro de conexão.', 'error');
  }
}

async function toggleUserActive(uid) {
  const u = hubUserById(uid);
  if (!u) return;
  try {
    const res = await fetch(`/api/admin/hubusers/${uid}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: !u.active }),
    });
    const d = await res.json();
    if (!d.success) { showToast(d.error || 'Falha ao alterar status.', 'error'); return; }
    showToast(`Usuário ${u.username} ${!u.active ? 'ativado' : 'desativado'}.`);
    loadHubUsers();
  } catch { showToast('Erro de conexão.', 'error'); }
}

async function deleteHubUser(uid) {
  const u = hubUserById(uid);
  if (!u) return;
  if (!confirm(`Excluir o usuário "${u.username}"?\nAs sessões de terminal dele serão removidas.`)) return;
  try {
    const res = await fetch(`/api/admin/hubusers/${uid}`, { method: 'DELETE' });
    const d = await res.json();
    if (!d.success) { showToast(d.error || 'Falha ao excluir usuário.', 'error'); return; }
    showToast(`Usuário ${u.username} excluído.`);
    loadHubUsers();
  } catch { showToast('Erro de conexão.', 'error'); }
}



// ── Modais auxiliares (senha / sessões do usuário) ──────────────────────────
function ensureAuxModal() {
  let m = document.getElementById('hh-aux-modal');
  if (!m) {
    m = document.createElement('div');
    m.id = 'hh-aux-modal';
    m.className = 'modal-overlay';
    document.body.appendChild(m);
  }
  return m;
}

function closeAuxModal() {
  const m = document.getElementById('hh-aux-modal');
  if (m) m.classList.remove('active');
}

function openUserPasswordModal(uid) {
  const u = hubUserById(uid);
  if (!u) return;
  const m = ensureAuxModal();
  m.innerHTML = `
    <div class="modal-box">
      <div class="modal-head">
        <h3>Redefinir senha — ${escapeHtml(u.username)}</h3>
        <button class="modal-close" onclick="closeAuxModal()">✕</button>
      </div>
      <div class="modal-body">
        <p class="text-muted" style="margin:0">A mesma senha valerá para o HomeHub e para o Terminal Web.</p>
        <div class="form-field">
          <label for="up-password">Nova senha</label>
          <input type="password" id="up-password" autocomplete="new-password" placeholder="mínimo 6 caracteres" />
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-outline" onclick="closeAuxModal()">Cancelar</button>
        <button class="btn btn-primary" onclick="saveUserPassword('${u.id}')">Salvar senha</button>
      </div>
    </div>`;
  m.classList.add('active');
  setTimeout(() => { const i = document.getElementById('up-password'); if (i) i.focus(); }, 60);
}

async function saveUserPassword(uid) {
  const pw = (document.getElementById('up-password') || {}).value || '';
  if (pw.length < 6) { showToast('A senha deve ter pelo menos 6 caracteres.', 'error'); return; }
  try {
    const res = await fetch(`/api/admin/hubusers/${uid}/password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    const d = await res.json();
    if (!d.success) { showToast(d.error || 'Falha ao redefinir senha.', 'error'); return; }
    showToast('Senha redefinida com sucesso.');
    closeAuxModal();
  } catch { showToast('Erro de conexão.', 'error'); }
}

async function viewUserSessions(uid) {
  const u = hubUserById(uid);
  if (!u) return;
  const m = ensureAuxModal();
  m.innerHTML = `
    <div class="modal-box modal-lg">
      <div class="modal-head">
        <h3>Sessões — ${escapeHtml(u.username)}</h3>
        <button class="modal-close" onclick="closeAuxModal()">✕</button>
      </div>
      <div class="modal-body" id="user-sessions-body"><p class="text-muted" style="margin:0">Carregando...</p></div>
      <div class="modal-foot">
        <button class="btn btn-outline" onclick="closeAuxModal()">Fechar</button>
        <button class="btn btn-danger" id="btn-kill-user-sessions" onclick="killAllUserSessions('${u.id}')">Encerrar todas</button>
      </div>
    </div>`;
  m.classList.add('active');
  try {
    const res = await fetch(`/api/admin/hubusers/${uid}/sessions`);
    const d = await res.json();
    const box = document.getElementById('user-sessions-body');
    if (!box) return;
    if (!d.success) { box.innerHTML = `<p class="text-muted" style="margin:0">${escapeHtml(d.error || 'Falha ao listar sessões.')}</p>`; return; }
    const list = d.sessions || [];
    if (!list.length) {
      box.innerHTML = '<p class="text-muted" style="margin:0">Nenhuma sessão registrada para este usuário.</p>';
    } else {
      box.innerHTML = '<ul style="list-style:none;padding:0;margin:0;display:grid;gap:8px">' + list.map(s => `
        <li style="display:flex;justify-content:space-between;gap:10px;align-items:center;background:var(--bg-subtle);border:1px solid var(--border-base);border-radius:8px;padding:10px 12px">
          <div>
            <div class="mono-text">${escapeHtml(s.session)}</div>
            <div class="text-muted" style="font-size:0.8rem">criada ${s.created ? new Date(s.created * 1000).toLocaleString('pt-BR') : '--'} · ${escapeHtml(s.status)}</div>
          </div>
          ${s.connected ? '<span class="status-chip status-chip-green">Conectada</span>' : '<span class="status-chip">Encerrada</span>'}
        </li>`).join('') + '</ul>';
    }
    const killBtn = document.getElementById('btn-kill-user-sessions');
    if (killBtn) killBtn.style.display = list.some(s => s.connected) ? '' : 'none';
  } catch {
    const box = document.getElementById('user-sessions-body');
    if (box) box.innerHTML = '<p class="text-muted" style="margin:0">Erro de conexão.</p>';
  }
}

async function killAllUserSessions(uid) {
  const u = hubUserById(uid);
  if (!u) return;
  if (!confirm(`Encerrar TODAS as sessões de ${u.username}?`)) return;
  try {
    const res = await fetch(`/api/admin/hubusers/${uid}/sessions`, { method: 'DELETE' });
    const d = await res.json();
    if (!d.success) { showToast(d.error || 'Falha ao encerrar sessões.', 'error'); return; }
    showToast(`Sessões de ${u.username} encerradas.`);
    closeAuxModal();
    loadHubUsers();
    loadTerminalSessions();
  } catch { showToast('Erro de conexão.', 'error'); }
}


// ── Card Terminais (sessões live do Web Terminal) ───────────────────────────
async function loadTerminalSessions() {
  const tbody = document.getElementById('term-sessions-tbody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/admin/terminal/sessions');
    const d = await res.json();
    if (!d.success) {
      tbody.innerHTML = `<tr><td colspan="7" class="td-loading">${escapeHtml(d.error || 'Terminal indisponível.')}</td></tr>`;
      return;
    }
    TERM_SESSIONS = d.sessions || [];
    const link = document.getElementById('terminal-link');
    if (link && d.terminal_url) link.href = d.terminal_url;
    renderTerminalSessions();
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Falha ao consultar o terminal.</td></tr>';
  }
}

function hhDuration(totalSec) {
  const sec = Math.max(0, Math.floor(totalSec));
  const h = Math.floor(sec / 3600), min = Math.floor((sec % 3600) / 60);
  return h > 0 ? `${h}h ${min}min` : `${min}min`;
}

function renderTerminalSessions() {
  const tbody = document.getElementById('term-sessions-tbody');
  if (!tbody) return;
  if (!TERM_SESSIONS.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Nenhuma sessão registrada no terminal.</td></tr>';
    return;
  }
  tbody.innerHTML = TERM_SESSIONS.map(s => {
    const dur = s.created ? hhDuration(Date.now() / 1000 - s.created) : '—';
    const state = s.live
      ? '<span class="status-chip status-chip-green">Ao vivo</span>'
      : '<span class="status-chip">Encerrada</span>';
    const kill = s.live
      ? `<button class="btn btn-danger btn-sm" onclick="killTerminalSession('${encodeURIComponent(s.full_name || '')}')">Encerrar</button>`
      : '';
    return `<tr>
      <td class="mono-text">${escapeHtml(s.icon || '🐚')} ${escapeHtml(s.full_name || '')}</td>
      <td><strong>${escapeHtml(s.user || '?')}</strong></td>
      <td>${escapeHtml(s.label || s.type || 'shell')}</td>
      <td class="text-muted">${s.created ? new Date(s.created * 1000).toLocaleString('pt-BR') : '—'}</td>
      <td>${dur}</td>
      <td>${state}</td>
      <td>${kill}</td>
    </tr>`;
  }).join('');
}

async function killTerminalSession(fullNameEnc) {
  const fullName = decodeURIComponent(fullNameEnc);
  if (!confirm(`Encerrar a sessão ${fullName}?`)) return;
  try {
    const res = await fetch(`/api/admin/terminal/sessions/${encodeURIComponent(fullName)}/kill`, { method: 'POST' });
    const d = await res.json();
    if (!d.success) { showToast(d.error || 'Falha ao encerrar sessão.', 'error'); return; }
    showToast('Sessão encerrada.');
    loadTerminalSessions();
    loadHubUsers();
  } catch { showToast('Erro de conexão.', 'error'); }
}

// ── Auditoria do Terminal (audit.jsonl via /terminal-data) ──────────────────
async function fetchTerminalAuditLogs() {
  const tbody = document.getElementById('terminal-audit-tbody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/admin/terminal/audit');
    const data = await res.json();
    const logs = (data.success && data.logs) ? data.logs : [];
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Nenhum evento do terminal registrado.</td></tr>';
      return;
    }
    tbody.innerHTML = logs.map(l => {
      const ts = l.ts ? new Date(l.ts * 1000).toLocaleString('pt-BR') : '--';
      const resChip = (l.result || '') === 'OK'
        ? '<span class="status-chip status-chip-green">OK</span>'
        : `<span class="status-chip status-chip-red">${escapeHtml(l.result || '')}</span>`;
      return `<tr>
        <td class="mono-text">${ts}</td>
        <td><strong>${escapeHtml(l.user || '')}</strong></td>
        <td><span class="status-chip status-chip-blue">${escapeHtml(l.action || '')}</span></td>
        <td>${escapeHtml(l.detail || '')}</td>
        <td class="mono-text text-muted">${escapeHtml(l.session || '')}</td>
        <td class="mono-text text-muted">${escapeHtml(l.ip || '--')}</td>
        <td>${resChip}</td>
      </tr>`;
    }).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="td-loading">Falha ao carregar auditoria do terminal.</td></tr>';
  }
}



async function cleanServerRam(btn) {
  if (!btn) btn = document.getElementById('btn-clean-ram');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="clean-icon">⏳</span> Limpando...';
  }
  showToast('Limpando cache de memória RAM...', 'info');

  try {
    const res = await fetch('/api/system/clean-ram', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message || 'Cache de RAM liberado com sucesso!', 'success');
      // Atualiza valores nos cards imediatamente
      if (data.ram_percent != null) {
        setTextSafe('kpi-ram-val', `${data.ram_percent}%`);
        setTextSafe('val-ram-percent', `${data.ram_percent}%`);
        setBarWidth('kpi-ram-bar', data.ram_percent);
        setGaugeValue('gauge-ram-circle', data.ram_percent);
      }
      if (data.ram_used_gb != null && data.ram_total_gb != null) {
        setTextSafe('kpi-ram-meta', `${data.ram_used_gb} GB usados de ${data.ram_total_gb} GB`);
        setTextSafe('val-ram-text', `${data.ram_used_gb}/${data.ram_total_gb} GB`);
      }
    } else {
      showToast(data.error || 'Erro ao limpar cache de RAM.', 'error');
    }
  } catch (err) {
    showToast('Erro de conexão ao solicitar limpeza de RAM.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span class="clean-icon">🧹</span> Limpar';
    }
  }
}
window.cleanServerRam = cleanServerRam;

function copyTailscaleSsh() {
  copyToClipboard('ssh decsv@100.92.242.64');
  showToast('Comando SSH Tailscale copiado!', 'success');
}

window.copyTailscaleSsh = copyTailscaleSsh;
window.copyTerminalUrl = copyTerminalUrl;
window.submitLogin = submitLogin;


// ══════════════════════════════════════════════════════════════════════════════
// GESTÃO DE ADMINISTRADORES (Linear Grade) & ATIVAÇÃO POR E-MAIL
// ══════════════════════════════════════════════════════════════════════════════


// Global HTML Escape helper
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
window.esc = esc;

hubUsersList = [];

async function loadHubUsers() {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;
  
  tbody.innerHTML = '<tr><td colspan="6" class="td-loading"><span class="restore-spinner"></span> Carregando administradores…</td></tr>';
  
  try {
    const res = await fetch('/api/admin/hubusers', { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    
    hubUsersList = data.users || [];
    renderHubUsersTable(hubUsersList);
    
    const total = hubUsersList.length;
    const active = hubUsersList.filter(u => u.active && u.has_password).length;
    const pending = hubUsersList.filter(u => !u.has_password).length;
    const sessions = hubUsersList.reduce((acc, u) => acc + (u.active_sessions || 0), 0);
    
    setTextSafe('ustat-total', total);
    setTextSafe('ustat-active', active);
    setTextSafe('ustat-pending', pending);
    setTextSafe('ustat-sessions', sessions);
    
    // badge "1" removed per user preference
  } catch (e) {
    console.error('loadHubUsers:', e);
    tbody.innerHTML = '<tr><td colspan="6" class="td-empty text-muted">Falha ao carregar lista de administradores.</td></tr>';
    const msg = document.getElementById('users-msg');
    if (msg) {
      msg.textContent = 'Erro ao carregar administradores. Verifique se sua conta possui permissão ROOT ou SysAdmin.';
      msg.classList.remove('hidden');
    }
  }
}

function renderHubUsersTable(users) {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;
  
  if (!users || users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="td-empty text-muted">Nenhum administrador encontrado.</td></tr>';
    return;
  }
  
  const roleBadges = {
    root: '<span class="role-badge role-root">⚡ Super Admin (ROOT)</span>',
    sysadmin: '<span class="role-badge role-sysadmin">🛡️ SysAdmin</span>',
    developer: '<span class="role-badge role-developer">💻 Desenvolvedor</span>',
    user1: '<span class="role-badge role-user1">👤 Operador</span>'
  };
  
  tbody.innerHTML = users.map(u => {
    const initial = (u.name || u.username || 'A').trim().charAt(0).toUpperCase();
    const isRoot = u.role === 'root';
    const avatarClass = isRoot ? 'user-avatar-circle user-avatar-root' : 'user-avatar-circle';
    const roleBadge = roleBadges[u.role] || `<span class="role-badge">${esc(u.role)}</span>`;
    
    let statusPill = '';
    if (!u.has_password) {
      statusPill = '<span class="status-pill status-pill-pending" title="Aguardando ativação pelo link enviado por e-mail">🟡 Convite Enviado</span>';
    } else if (u.active) {
      statusPill = '<span class="status-pill status-pill-active">🟢 Ativo</span>';
    } else {
      statusPill = '<span class="status-pill status-pill-inactive">🔴 Inativo</span>';
    }
    
    const lastLogin = u.last_login ? bkbFmtTs(u.last_login) : '<span class="text-muted">Nunca acessou</span>';
    const sessions = u.active_sessions ? `<span style="color:#38bdf8;font-weight:600;">${u.active_sessions} ativa(s)</span>` : '<span class="text-muted">--</span>';
    
    let actionsHtml = '';
    if (u.email) {
      actionsHtml += `<button class="btn btn-outline btn-sm" title="Reenviar link para ${esc(u.email)}" onclick="resendAdminInvite('${esc(u.id)}', '${esc(u.email)}')">✉️ Reenviar Link</button>`;
    }
    if (!isRoot) {
      actionsHtml += `<button class="btn btn-outline btn-sm" style="color:#ef4444;border-color:rgba(239,68,68,0.3)" title="Remover administrador" onclick="deleteHubUser('${esc(u.id)}', '${esc(u.username)}')">🗑️</button>`;
    }
    
    return `
      <tr>
        <td>
          <div class="user-cell">
            <div class="${avatarClass}">${initial}</div>
            <div class="user-info-text">
              <span class="user-name-title">${esc(u.name || u.username)}</span>
              <span class="user-email-sub">${esc(u.email || '@sem-email')}</span>
            </div>
          </div>
        </td>
        <td>${roleBadge}</td>
        <td>${statusPill}</td>
        <td style="font-size:0.8125rem;">${lastLogin}</td>
        <td style="font-size:0.8125rem;">${sessions}</td>
        <td style="text-align:right;">
          <div style="display:flex;gap:6px;justify-content:flex-end;">
            ${actionsHtml}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function openInviteAdminModal() {
  const modal = document.getElementById('modal-invite-admin');
  if (modal) {
    document.getElementById('invite-admin-name').value = '';
    document.getElementById('invite-admin-email').value = '';
    document.getElementById('invite-admin-role').value = 'sysadmin';
    const err = document.getElementById('invite-admin-error');
    if (err) err.classList.add('hidden');
    modal.classList.add('active');
  }
}
function openUserModal() { openInviteAdminModal(); }

function closeInviteAdminModal() {
  const modal = document.getElementById('modal-invite-admin');
  if (modal) modal.classList.remove('active');
}
function closeUserModal() { closeInviteAdminModal(); }

async function submitInviteAdmin() {
  const name = document.getElementById('invite-admin-name').value.trim();
  const email = document.getElementById('invite-admin-email').value.trim();
  const role = document.getElementById('invite-admin-role').value;
  const btn = document.getElementById('btn-submit-invite');
  const err = document.getElementById('invite-admin-error');
  
  if (!name || !email) {
    if (err) { err.textContent = 'Preencha o nome e o e-mail corporativo.'; err.classList.remove('hidden'); }
    return;
  }
  
  if (err) err.classList.add('hidden');
  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="restore-spinner"></span> Enviando convite por e-mail…';
  
  try {
    const res = await fetch('/api/admin/users/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, role })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Falha ao enviar convite.');
    }
    
    closeInviteAdminModal();
    if (typeof HHNotify !== 'undefined') {
      HHNotify.show({
        title: 'Convite Enviado com Sucesso!',
        message: `O link para definir a senha foi enviado para ${email}.`,
        type: 'success',
        persistent: true
      });
    } else {
      alert(`Convite criado! E-mail enviado para ${email}.`);
    }
    loadHubUsers();
  } catch (e) {
    if (err) { err.textContent = e.message; err.classList.remove('hidden'); }
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}
function submitUserForm() { submitInviteAdmin(); }

async function resendAdminInvite(userId, email) {
  if (!confirm(`Deseja reenviar o e-mail de ativação e definição de senha para ${email}?`)) {
    return;
  }
  
  try {
    const res = await fetch(`/api/admin/users/${userId}/resend-invite`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Falha ao reenviar e-mail.');
    }
    if (typeof HHNotify !== 'undefined') {
      HHNotify.show({
        title: 'E-mail Reenviado!',
        message: `Novo link de ativação enviado para ${email}.`,
        type: 'success'
      });
    } else {
      alert(`E-mail reenviado com sucesso para ${email}!`);
    }
  } catch (e) {
    alert(`Erro ao reenviar e-mail: ${e.message}`);
  }
}

async function deleteHubUser(userId, username) {
  if (!confirm(`Tem certeza que deseja remover o administrador "${username}"?`)) {
    return;
  }
  
  try {
    const res = await fetch(`/api/admin/hubusers/${userId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Falha ao remover usuário.');
    }
    if (typeof HHNotify !== 'undefined') {
      HHNotify.show({ title: 'Usuário Removido', message: `O usuário ${username} foi removido.`, type: 'info' });
    }
    loadHubUsers();
  } catch (e) {
    alert(`Erro ao remover: ${e.message}`);
  }
}

async function performChangePassword() {
  const oldPwd = document.getElementById('old-password').value;
  const newPwd = document.getElementById('new-password').value;
  const confirmPwd = document.getElementById('confirm-password').value;
  const msg = document.getElementById('pw-change-msg');
  
  if (msg) msg.classList.add('hidden');
  if (newPwd !== confirmPwd) {
    if (msg) { msg.textContent = 'As senhas digitadas não coincidem.'; msg.classList.remove('hidden'); }
    return;
  }
  
  try {
    const res = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPwd, new_password: newPwd })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Falha ao alterar senha.');
    }
    if (typeof HHNotify !== 'undefined') {
      HHNotify.show({ title: 'Senha Atualizada', message: 'Sua senha foi alterada com sucesso!', type: 'success' });
    } else {
      alert('Senha alterada com sucesso!');
    }
    document.getElementById('old-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
  } catch (e) {
    if (msg) { msg.textContent = e.message; msg.classList.remove('hidden'); }
  }
}

function applyRoleBasedUI() {
  fetch('/api/session').then(r => r.json()).then(d => {
    if (d && d.authenticated) {
      const nameEl = document.querySelector('.sidebar-user-name');
      const roleEl = document.querySelector('.sidebar-user-role');
      const avatarEl = document.querySelector('.sidebar-user-avatar');
      if (nameEl) nameEl.textContent = d.name || d.username || 'Matheus Camílio';
      if (roleEl) roleEl.textContent = d.role === 'root' ? 'Super Administrador' : (d.role || 'Admin');
      if (avatarEl) avatarEl.textContent = (d.name || d.username || 'M').charAt(0).toUpperCase();
    }
  }).catch(() => {});
}

function checkPwStrength(val, prefix) {
  const fill = document.getElementById(`${prefix}-fill`);
  const label = document.getElementById(`${prefix}-label`);
  if (!fill || !label) return;
  
  let score = 0;
  if (val.length >= 6) score += 1;
  if (val.length >= 8) score += 1;
  if (/[A-Z]/.test(val)) score += 1;
  if (/[0-9]/.test(val)) score += 1;
  if (/[^A-Za-z0-9]/.test(val)) score += 1;
  
  if (val.length === 0) {
    fill.style.width = '0%';
    label.textContent = 'Força da senha';
    label.style.color = 'var(--text-3)';
  } else if (score <= 2) {
    fill.style.width = '30%';
    fill.style.backgroundColor = '#ef4444';
    label.textContent = 'Senha fraca';
    label.style.color = '#ef4444';
  } else if (score <= 3) {
    fill.style.width = '65%';
    fill.style.backgroundColor = '#f59e0b';
    label.textContent = 'Senha moderada';
    label.style.color = '#f59e0b';
  } else {
    fill.style.width = '100%';
    fill.style.backgroundColor = '#10b981';
    label.textContent = 'Senha forte e segura';
    label.style.color = '#10b981';
  }
}

async function submitSetPassword() {
  const token = document.getElementById('set-pw-token').value.trim();
  const newPassword = document.getElementById('set-pw-new').value;
  const confirmPassword = document.getElementById('set-pw-confirm').value;
  const btn = document.getElementById('btn-submit-set-pw');
  const err = document.getElementById('set-pw-error');
  const succ = document.getElementById('set-pw-success');
  
  if (err) err.classList.add('hidden');
  if (succ) succ.classList.add('hidden');
  
  if (!newPassword || newPassword.length < 6) {
    if (err) { err.textContent = 'A senha deve ter no mínimo 6 caracteres.'; err.classList.remove('hidden'); }
    return;
  }
  if (newPassword !== confirmPassword) {
    if (err) { err.textContent = 'As senhas digitadas não coincidem.'; err.classList.remove('hidden'); }
    return;
  }
  
  btn.disabled = true;
  btn.innerHTML = '<span class="restore-spinner"></span> Salvando senha segura…';
  
  try {
    const res = await fetch('/api/admin/set-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, new_password: newPassword })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Falha ao definir senha.');
    }
    
    if (succ) {
      succ.textContent = '✅ Senha definida com sucesso! Redirecionando para o painel…';
      succ.classList.remove('hidden');
    }
    setTimeout(() => {
      window.location.href = '/admin.html';
    }, 1800);
  } catch (e) {
    if (err) { err.textContent = e.message; err.classList.remove('hidden'); }
    btn.disabled = false;
    btn.textContent = 'Salvar Senha & Acessar Painel';
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const action = urlParams.get('action');
  const token = urlParams.get('token');
  
  if (action === 'set-password' && token) {
    const modal = document.getElementById('modal-set-password');
    const inputToken = document.getElementById('set-pw-token');
    if (modal && inputToken) {
      inputToken.value = token;
      modal.classList.add('active');
    }
  }
});


// ═══════════════════════════════════════════════════════════
// CLUSTER DE ALTA DISPONIBILIDADE & DUPLICIDADE 24/7 (v3)
// ═══════════════════════════════════════════════════════════

let clusterPollInterval = null;

function startClusterPolling() {
  fetchClusterStatus();
  if (clusterPollInterval) clearInterval(clusterPollInterval);
  clusterPollInterval = setInterval(fetchClusterStatus, 10000);
}

async function fetchClusterStatus() {
  const dot = document.getElementById('cluster-refresh-dot');
  if (dot) { dot.style.background = '#f59e0b'; dot.style.boxShadow = '0 0 6px #f59e0b'; }

  try {
    const res = await fetch('/api/cluster/status', { credentials: 'include' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderClusterStatus(data);
    if (dot) { dot.style.background = '#22c55e'; dot.style.boxShadow = '0 0 6px #22c55e'; }
  } catch (err) {
    console.warn('[Cluster] fetch error:', err);
    if (dot) { dot.style.background = '#ef4444'; dot.style.boxShadow = '0 0 6px #ef4444'; }
  }
}

function renderClusterStatus(data) {
  const { vostro, aws } = data;
  updateServerCard('vostro', vostro, { isPrimary: true });
  updateServerCard('aws', aws, { isPrimary: false });
}

function updateServerCard(server, d, ctx) {
  if (!d) return;
  const isVostro = server === 'vostro';
  const isOnline = d.status === 'online';

  const card = document.getElementById(`cluster-card-${server}`);
  if (card) {
    card.className = 'cluster-server-card ' + (isOnline ? 'is-active' : 'is-offline');
  }

  const badge = document.getElementById(`cluster-badge-${server}`);
  if (badge) {
    if (!isOnline) {
      badge.className = 'cluster-badge cluster-badge-offline';
      badge.textContent = '🔴 Indisponível';
    } else if (isVostro) {
      badge.className = 'cluster-badge cluster-badge-active';
      badge.textContent = '🟢 Servidor Primário (Local)';
    } else {
      badge.className = 'cluster-badge cluster-badge-active';
      badge.textContent = '🟢 Standby Ativo 24h (Nuvem)';
    }
  }

  if (isOnline) {
    const cpu  = d.cpu_percent  ?? 0;
    const ram  = d.ram_percent  ?? 0;
    const disk = d.disk_percent ?? 0;

    setClusterBar(`${server}-cpu-bar`,  cpu,  getBarColorClass(cpu));
    setClusterBar(`${server}-ram-bar`,  ram,  getBarColorClass(ram));
    setClusterBar(`${server}-disk-bar`, disk, getBarColorClass(disk));

    setEl(`${server}-cpu-val`,  `${cpu}%`);
    setEl(`${server}-ram-val`,  `${d.ram_used_gb ?? 0}/${d.ram_total_gb ?? 0} GB`);
    setEl(`${server}-disk-val`, `${d.disk_used_gb ?? 0}/${d.disk_total_gb ?? 0} GB`);
    setEl(`${server}-uptime`,   d.uptime ?? '--');

    if (isVostro && d.last_db_sync) {
      setEl('vostro-sync', `Sync: ${d.last_db_sync.substring(11,16)}`);
    }
    if (!isVostro) {
      setEl('aws-watchdog', 'Duplicidade: Sincronizado ✓');
    }
  }

  const chip = document.getElementById(`${server}-status-chip`);
  const txt  = document.getElementById(`${server}-status-text`);
  if (chip && txt) {
    if (!isOnline) {
      chip.className = 'cluster-info-chip cluster-status-chip offline';
      txt.textContent = '🔴 Offline';
    } else {
      chip.className = 'cluster-info-chip cluster-status-chip online';
      txt.textContent = '🟢 Online';
    }
  }
}

function getBarColorClass(pct) {
  if (pct >= 85) return 'cluster-fill-red';
  if (pct >= 65) return 'cluster-fill-purple';
  return 'cluster-fill-blue';
}

function setClusterBar(id, pct, cls) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(100, pct) + '%';
  el.className = el.className.replace(/cluster-fill-\S+/g, '').trim() + ' ' + cls;
}

function setEl(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// Auto-start polling on overview page
(function patchShowPage() {
  const original = window.showPage;
  if (!original) {
    let attempts = 0;
    const wait = setInterval(() => {
      if (++attempts > 20) clearInterval(wait);
      if (typeof window.showPage === 'function') {
        clearInterval(wait);
        patchShowPage();
      }
    }, 200);
    return;
  }
  window.showPage = function(pageId, ...args) {
    original.call(this, pageId, ...args);
    if (pageId === 'overview') startClusterPolling();
    else if (clusterPollInterval) { clearInterval(clusterPollInterval); clusterPollInterval = null; }
  };
})();

if (document.getElementById('page-overview')?.classList.contains('active')) {
  startClusterPolling();
}
