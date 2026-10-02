/* ==========================================================================
   Expresso Nepomuceno — Enterprise Application Portal Client Logic
   ========================================================================== */

let applicationsCatalog = [];
let activeCategory = "all";
let currentSearchQuery = "";
let secretClickCount = 0;
let secretClickTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  renderInitialSkeletons();
  fetchApplications();
  setupKeyboardShortcuts();
  setupSecretTrigger();
});

// --------------------------------------------------------------------------
// Theme Handling (Dark / Light Mode)
// --------------------------------------------------------------------------
function initTheme() {
  const savedTheme = localStorage.getItem("portal_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("portal_theme", next);
}

// --------------------------------------------------------------------------
// Initial Skeletons Rendering
// --------------------------------------------------------------------------
function renderInitialSkeletons() {
  const featuredGrid = document.getElementById("featured-cards-grid");
  const allGrid = document.getElementById("all-cards-grid");

  const skeletonHtml = `
    <div class="skeleton-card">
      <div class="skeleton-shimmer"></div>
      <div style="display: flex; justify-content: space-between;">
        <div class="skeleton-box sk-icon"></div>
        <div class="skeleton-box sk-badge"></div>
      </div>
      <div>
        <div class="skeleton-box sk-title"></div>
        <div class="skeleton-box sk-desc" style="margin-top: 8px;"></div>
        <div class="skeleton-box sk-desc-short" style="margin-top: 6px;"></div>
      </div>
      <div class="skeleton-box sk-btn"></div>
    </div>
  `;

  if (featuredGrid) featuredGrid.innerHTML = skeletonHtml + skeletonHtml;
  if (allGrid) allGrid.innerHTML = skeletonHtml + skeletonHtml;
}

// --------------------------------------------------------------------------
// Fetch Applications Catalog
// --------------------------------------------------------------------------
async function fetchApplications() {
  try {
    const res = await fetch("/api/projects");
    if (!res.ok) throw new Error("Erro na requisição");
    const data = await res.json();
    
    applicationsCatalog = data.projects || [];
    
    updateGlobalStatus(applicationsCatalog);
    renderCategoryTabs();
    renderAllViews();
  } catch (err) {
    console.error("Falha ao carregar catálogo:", err);
    showErrorState();
  }
}

// --------------------------------------------------------------------------
// Global Status Indicator Calculation
// --------------------------------------------------------------------------
function updateGlobalStatus(apps) {
  const indicator = document.getElementById("global-status-indicator");
  const statusText = document.getElementById("status-text");
  const statusDot = document.getElementById("status-dot");
  if (!indicator || !statusText) return;

  if (!apps.length) {
    statusText.textContent = "Sistemas em inicialização";
    return;
  }

  const anyOffline = apps.some(a => a.status === "offline" || a.status === "maintenance");
  if (anyOffline) {
    indicator.style.borderColor = "rgba(245, 158, 11, 0.3)";
    indicator.style.background = "rgba(245, 158, 11, 0.12)";
    indicator.style.color = "#f59e0b";
    statusDot.style.backgroundColor = "#f59e0b";
    statusDot.style.boxShadow = "0 0 8px #f59e0b";
    statusText.textContent = "Alguns sistemas apresentam instabilidade";
  } else {
    indicator.style.borderColor = "rgba(16, 185, 129, 0.25)";
    indicator.style.background = "rgba(16, 185, 129, 0.12)";
    indicator.style.color = "#10b981";
    statusDot.style.backgroundColor = "#10b981";
    statusDot.style.boxShadow = "0 0 8px #10b981";
    statusText.textContent = "Todos os sistemas operacionais";
  }
}

// --------------------------------------------------------------------------
// Category Navigation Tabs (Only Non-Empty Categories)
// --------------------------------------------------------------------------
function renderCategoryTabs() {
  const container = document.getElementById("category-tabs-container");
  if (!container) return;

  // Extract unique categories present in catalog
  const categories = Array.from(
    new Set(applicationsCatalog.map(a => a.category).filter(Boolean))
  );

  let tabsHtml = `
    <button class="cat-tab-btn ${activeCategory === 'all' ? 'active' : ''}" onclick="selectCategory('all', this)">
      <span>Todas</span>
      <span class="cat-tab-count">${applicationsCatalog.length}</span>
    </button>
  `;

  categories.forEach(cat => {
    const count = applicationsCatalog.filter(a => a.category === cat).length;
    tabsHtml += `
      <button class="cat-tab-btn ${activeCategory === cat ? 'active' : ''}" onclick="selectCategory('${escapeHtml(cat)}', this)">
        <span>${escapeHtml(cat)}</span>
        <span class="cat-tab-count">${count}</span>
      </button>
    `;
  });

  container.innerHTML = tabsHtml;
}

function selectCategory(cat, btn) {
  activeCategory = cat;
  document.querySelectorAll(".cat-tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  renderAllViews();
}

function handleSearch(val) {
  currentSearchQuery = (val || "").toLowerCase().trim();
  renderAllViews();
}

// --------------------------------------------------------------------------
// Render Views (Featured + All Applications)
// --------------------------------------------------------------------------
function renderAllViews() {
  let filtered = applicationsCatalog;

  if (activeCategory !== "all") {
    filtered = filtered.filter(a => a.category === activeCategory);
  }

  if (currentSearchQuery) {
    filtered = filtered.filter(a =>
      a.name.toLowerCase().includes(currentSearchQuery) ||
      (a.description && a.description.toLowerCase().includes(currentSearchQuery)) ||
      (a.badge && a.badge.toLowerCase().includes(currentSearchQuery)) ||
      (a.category && a.category.toLowerCase().includes(currentSearchQuery)) ||
      (a.tags && Array.isArray(a.tags) && a.tags.some(t => t.toLowerCase().includes(currentSearchQuery)))
    );
  }

  renderFeaturedSection(filtered);
  renderAllCatalogSection(filtered);
}

// 1. Featured Section
function renderFeaturedSection(list) {
  const featuredSection = document.getElementById("featured-section");
  const featuredGrid = document.getElementById("featured-cards-grid");
  if (!featuredGrid) return;

  // When searching, hide featured section to focus on search results
  if (currentSearchQuery || activeCategory !== "all") {
    if (featuredSection) featuredSection.style.display = "none";
    return;
  }

  const featuredApps = list.filter(a => a.featured || a.id === "ridecheck-web" || a.id === "decam");
  if (!featuredApps.length) {
    if (featuredSection) featuredSection.style.display = "none";
    return;
  }

  if (featuredSection) featuredSection.style.display = "block";

  featuredGrid.innerHTML = featuredApps.map(app => {
    const targetUrl = app.url || app.public_url || "#";
    const category = app.category || "Geral";
    const statusText = app.status === "maintenance" ? "MANUTENÇÃO" : (app.status === "offline" ? "INDISPONÍVEL" : "ONLINE");

    return `
      <article class="featured-card">
        <div>
          <div class="featured-card-top">
            <div class="featured-icon-box">
              ${app.icon || "⚡"}
            </div>
            <div class="meta-status-group">
              <span>${escapeHtml(category.toUpperCase())}</span>
              <span>&bull;</span>
              <span class="status-indicator-live">
                <span class="status-dot-mini"></span>
                ${statusText}
              </span>
            </div>
          </div>

          <div class="featured-card-body">
            <h3>${escapeHtml(app.name)}</h3>
            <p>${escapeHtml(app.description || "Aplicação corporativa oficial.")}</p>
          </div>
        </div>

        <a href="${targetUrl}" ${/^https?:\/\//i.test(targetUrl) ? 'target="_blank" rel="noopener noreferrer"' : ''} class="btn-access-app">
          <span>Acessar aplicação</span>
          <span class="btn-access-arrow">→</span>
        </a>
      </article>
    `;
  }).join("");
}

// 2. All Applications Grid
function renderAllCatalogSection(list) {
  const grid = document.getElementById("all-cards-grid");
  const counterPill = document.getElementById("catalog-count-pill");
  const catalogTitle = document.getElementById("catalog-title");
  if (!grid) return;

  if (counterPill) {
    counterPill.textContent = `${list.length} ${list.length === 1 ? 'aplicação disponível' : 'aplicações disponíveis'}`;
  }

  if (catalogTitle) {
    if (currentSearchQuery) {
      catalogTitle.textContent = `Resultados da busca ("${currentSearchQuery}")`;
    } else if (activeCategory !== "all") {
      catalogTitle.textContent = activeCategory;
    } else {
      catalogTitle.textContent = "Todas as Aplicações";
    }
  }

  if (!list.length) {
    grid.innerHTML = `
      <div class="empty-state-box">
        <div class="empty-state-icon">🔍</div>
        <h3>Nenhuma aplicação encontrada</h3>
        <p>Não encontramos ferramentas que correspondam à sua pesquisa ou filtro selecionado.</p>
        <button class="btn-clear-search" onclick="resetFilters()">Limpar busca e filtros</button>
      </div>
    `;
    return;
  }

  grid.innerHTML = list.map(app => {
    const targetUrl = app.url || app.public_url || "#";
    const category = app.category || "Geral";
    const statusText = app.status === "maintenance" ? "MANUTENÇÃO" : (app.status === "offline" ? "INDISPONÍVEL" : "ONLINE");

    return `
      <article class="app-card">
        <div>
          <div class="app-card-header">
            <div class="app-icon-wrap">
              ${app.icon || "💼"}
            </div>
            <div class="meta-status-group">
              <span>${escapeHtml(category.toUpperCase())}</span>
              <span>&bull;</span>
              <span class="status-indicator-live">
                <span class="status-dot-mini"></span>
                ${statusText}
              </span>
            </div>
          </div>

          <div class="app-card-body">
            <h3>${escapeHtml(app.name)}</h3>
            <p>${escapeHtml(app.description || "Ferramenta e microsserviço corporativo.")}</p>
          </div>
        </div>

        <a href="${targetUrl}" ${/^https?:\/\//i.test(targetUrl) ? 'target="_blank" rel="noopener noreferrer"' : ''} class="btn-app-action">
          <span>Acessar aplicação</span>
          <span>→</span>
        </a>
      </article>
    `;
  }).join("");
}

function resetFilters() {
  activeCategory = "all";
  currentSearchQuery = "";
  const headerSearch = document.getElementById("header-search-input");
  if (headerSearch) headerSearch.value = "";
  renderCategoryTabs();
  renderAllViews();
}

function showErrorState() {
  const grid = document.getElementById("all-cards-grid");
  if (grid) {
    grid.innerHTML = `
      <div class="empty-state-box">
        <div class="empty-state-icon">⚠️</div>
        <h3>Não foi possível carregar as aplicações</h3>
        <p>Houve uma falha de comunicação com o servidor. Tente recarregar a página.</p>
        <button class="btn-clear-search" onclick="fetchApplications()">Tentar novamente</button>
      </div>
    `;
  }
}

// --------------------------------------------------------------------------
// Keyboard Shortcuts & Secret Admin Trigger
// --------------------------------------------------------------------------
function setupKeyboardShortcuts() {
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement.tagName !== "INPUT") {
      e.preventDefault();
      const input = document.getElementById("header-search-input");
      if (input) {
        input.focus();
        input.select();
      }
    }

    if (e.key === "Escape") {
      resetFilters();
    }

    if (e.ctrlKey && e.shiftKey && (e.key === "A" || e.key === "a")) {
      e.preventDefault();
      window.location.href = "/admin";
    }
  });
}

function setupSecretTrigger() {
  const logo = document.getElementById("logo-secret-trigger");
  if (logo) {
    logo.addEventListener("click", () => {
      secretClickCount++;
      clearTimeout(secretClickTimer);
      secretClickTimer = setTimeout(() => { secretClickCount = 0; }, 2500);
      if (secretClickCount >= 5) {
        window.location.href = "/admin";
      }
    });
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
