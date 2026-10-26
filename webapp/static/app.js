"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  config: null,
  tasks: [],
  selectedTask: null,
  treeFiles: [],
  materialFiles: [],
  logs: [],
  eventSource: null,
  selectedSource: null,
  sourceHistory: [],
  currentDocument: null,
  selectedIssue: null,
  uploadFiles: [],
  selectedUploadPaths: new Set(),
  projectName: "",
  domainFiles: [],
  requirementFiles: [],
  requirementReview: null,
  requirementCategories: [],
  selectedRequirementCategory: null,
  requirementViewMode: "preview",
  requirementPreviewRequest: 0,
  newRequirementFiles: [],
  materialCategoryPayload: null,
  contentSearch: null,
  contentSearchTimer: null,
  contentSearchRequest: 0,
  durationTimer: null,
  panelResize: null,
};

const STATUS = {
  queued: "排队中", running: "验证中", cancelling: "停止中",
  completed: "验证完成", failed: "失败", cancelled: "已取消",
  preprocessing: "需求预处理中", awaiting_confirmation: "待确认设计意图",
  preprocess_failed: "预处理失败",
  domain_preprocessing: "领域规约整理中", awaiting_domain_confirmation: "待确认领域规约",
  domain_preprocess_failed: "领域规约整理失败",
};

const DOMAIN_STATUSES = new Set(["domain_preprocessing", "awaiting_domain_confirmation", "domain_preprocess_failed"]);
const REQUIREMENT_STATUSES = new Set(["preprocessing", "awaiting_confirmation", "preprocess_failed", ...DOMAIN_STATUSES]);
const isDomainReview = () => DOMAIN_STATUSES.has(state.selectedTask?.status);
const reviewRoute = () => isDomainReview() ? "domain" : "requirements";

const PHASE_STAGE = {
  "生成验证阶段计划": 1,
  "生成领域上下文": 2,
  "提取源码函数": 3,
  "收集待验证文件": 4,
  "生成调用层次": 5,
  "生成规约并验证": 6,
  "静态推理验证": 6,
};

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let payload;
  try { payload = await response.json(); } catch { payload = {}; }
  if (!response.ok) throw new Error(payload.error || `请求失败（${response.status}）`);
  return payload;
}

function toast(message, kind = "info") {
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => node.remove(), 4300);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

function shortDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : `${date.getMonth() + 1}/${date.getDate()} ${String(date.getHours()).padStart(2,"0")}:${String(date.getMinutes()).padStart(2,"0")}`;
}

function elapsed(task) {
  if (!task?.started_at) return "—";
  const start = new Date(task.started_at).getTime();
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "—";
  let seconds = Math.max(0, Math.floor((end - start) / 1000));
  const hours = Math.floor(seconds / 3600); seconds %= 3600;
  const minutes = Math.floor(seconds / 60); seconds %= 60;
  return hours ? `${hours}:${String(minutes).padStart(2,"0")}:${String(seconds).padStart(2,"0")}` : `${minutes}:${String(seconds).padStart(2,"0")}`;
}

async function boot() {
  bindEvents();
  try {
    const [config] = await Promise.all([api("/api/config"), loadTasks()]);
    state.config = config;
    $("#service-status").className = "service-status online";
    $("#service-status").innerHTML = "<i></i>服务正常";
    $("#concurrency-label").textContent = `并行上限 ${config.max_concurrent_tasks}`;
    $("#demo-banner").classList.toggle("hidden", !config.demo_mode);
  } catch (error) {
    $("#service-status").className = "service-status offline";
    $("#service-status").innerHTML = "<i></i>服务异常";
    toast(error.message, "error");
  }
  setInterval(refreshTasksQuietly, 5000);
}

function bindEvents() {
  $("#sidebar-toggle").addEventListener("click", toggleTaskSidebar);
  $("#file-panel-toggle").addEventListener("click", toggleFilePanel);
  $("#source-back").addEventListener("click", navigateSourceBack);
  $("#source-code").addEventListener("click", followSourceSymbol);
  document.addEventListener("keydown", event => {
    if (event.key === "Control") $("#source-code").classList.add("ctrl-navigation");
    if (event.altKey && event.key === "ArrowLeft" && state.sourceHistory.length) {
      event.preventDefault(); navigateSourceBack();
    }
  });
  document.addEventListener("keyup", event => { if (event.key === "Control") $("#source-code").classList.remove("ctrl-navigation"); });
  window.addEventListener("blur", () => $("#source-code").classList.remove("ctrl-navigation"));
  const panelResizer = $("#source-issue-resizer");
  panelResizer.addEventListener("pointerdown", startPanelResize);
  panelResizer.addEventListener("pointermove", movePanelResize);
  panelResizer.addEventListener("pointerup", stopPanelResize);
  panelResizer.addEventListener("pointercancel", stopPanelResize);
  panelResizer.addEventListener("dblclick", resetPanelWidths);
  panelResizer.addEventListener("keydown", resizePanelsWithKeyboard);
  window.addEventListener("resize", constrainPanelWidths);
  $("#new-task-button").addEventListener("click", openCreateDialog);
  $$(".new-task-trigger").forEach(button => button.addEventListener("click", openCreateDialog));
  $$('[data-close]').forEach(button => button.addEventListener("click", () => $("#" + button.dataset.close).close()));
  $("#task-search").addEventListener("input", renderTaskList);
  $("#tree-search").addEventListener("input", renderFileTree);
  $("#project-search-input").addEventListener("input", queueContentSearch);
  [["search-case", "case"], ["search-word", "word"], ["search-regex", "regex"]].forEach(([id]) => {
    $("#" + id).addEventListener("click", event => {
      const button = event.currentTarget;
      button.setAttribute("aria-pressed", String(button.getAttribute("aria-pressed") !== "true"));
      queueContentSearch();
    });
  });
  $("#severity-filter").addEventListener("change", () => renderIssues(false));
  $("#directory-picker").addEventListener("click", () => $("#directory-input").click());
  $("#directory-input").addEventListener("change", onDirectorySelected);
  $("#select-all-files").addEventListener("change", event => {
    state.selectedUploadPaths = event.target.checked ? new Set(state.uploadFiles.map(item => item.path)) : new Set();
    renderUploadTree();
  });
  $("#domain-input").addEventListener("change", event => { state.domainFiles = [...event.target.files]; renderMaterials(); });
  $("#intent-input").addEventListener("change", event => { state.requirementFiles = [...event.target.files]; renderMaterials(); });
  $("#create-form").addEventListener("submit", createTask);
  $("#requirement-regenerate").addEventListener("click", regenerateRequirements);
  $("#requirement-retry").addEventListener("click", regenerateRequirements);
  $("#requirement-confirm").addEventListener("click", confirmRequirements);
  $("#requirement-new-files").addEventListener("change", event => {
    state.newRequirementFiles = [...event.target.files];
    const type = isDomainReview() ? "Markdown/TXT" : "DOCX";
    $("#requirement-new-files-label").textContent = state.newRequirementFiles.length
      ? `待加入 ${state.newRequirementFiles.length} 份 ${type}：${state.newRequirementFiles.map(file => file.name).join("、")}`
      : `可选择新的${isDomainReview() ? "领域规约" : "需求文档"}，重新生成时一并处理`;
  });
  $("#requirement-category-content").addEventListener("input", onRequirementCategoryInput);
  $("#requirement-view-preview").addEventListener("click", () => setRequirementViewMode("preview"));
  $("#requirement-view-edit").addEventListener("click", () => setRequirementViewMode("edit"));
  $$(".inspector-tab").forEach(tab => tab.addEventListener("click", () => selectInspectorTab(tab.dataset.tab)));
  $("#collapse-tree").addEventListener("click", () => {
    $$(".tree-children", $("#file-tree")).forEach(node => node.classList.add("collapsed"));
    $$(".tree-toggle", $("#file-tree")).forEach(node => node.textContent = "›");
  });
  $("#end-task-button").addEventListener("click", endTask);
  $("#resume-button").addEventListener("click", resumeTask);
  $("#rerun-button").addEventListener("click", rerunTask);
  $("#adjust-intent-button").addEventListener("click", adjustDesignIntent);
  $("#delete-button").addEventListener("click", deleteTask);
  $("#report-button").addEventListener("click", openReports);
  $("#more-button").addEventListener("click", event => { event.stopPropagation(); $("#more-menu").classList.toggle("hidden"); });
  document.addEventListener("click", () => $("#more-menu").classList.add("hidden"));
}

function toggleTaskSidebar() {
  const shell = $("#app-shell");
  const collapsed = shell.classList.toggle("sidebar-collapsed");
  const button = $("#sidebar-toggle");
  button.textContent = collapsed ? "›" : "‹";
  button.title = collapsed ? "展开验证记录" : "收起验证记录";
  button.setAttribute("aria-expanded", String(!collapsed));
  requestAnimationFrame(constrainPanelWidths);
}

function toggleFilePanel() {
  const workspace = $("#workspace");
  const collapsed = workspace.classList.toggle("file-panel-collapsed");
  const button = $("#file-panel-toggle");
  button.textContent = collapsed ? "›" : "‹";
  button.title = collapsed ? "展开工程目录" : "收起工程目录";
  button.setAttribute("aria-expanded", String(!collapsed));
  requestAnimationFrame(constrainPanelWidths);
  setTimeout(constrainPanelWidths, 220);
}

function panelWidthBounds() {
  const workspace = $("#workspace");
  const source = $(".source-panel");
  const resizer = $("#source-issue-resizer");
  const available = workspace.getBoundingClientRect().right - source.getBoundingClientRect().left;
  const maximum = Math.max(320, Math.min(760, available - resizer.offsetWidth - 360));
  return { minimum: Math.min(320, maximum), maximum };
}

function setInspectorWidth(width) {
  const bounds = panelWidthBounds();
  const next = Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, width)));
  $("#workspace").style.setProperty("--inspector-width", `${next}px`);
  const resizer = $("#source-issue-resizer");
  resizer.setAttribute("aria-valuemin", String(Math.round(bounds.minimum)));
  resizer.setAttribute("aria-valuemax", String(Math.round(bounds.maximum)));
  resizer.setAttribute("aria-valuenow", String(next));
}

function startPanelResize(event) {
  if (event.button !== 0) return;
  const resizer = event.currentTarget;
  state.panelResize = {
    pointerId: event.pointerId,
    startX: event.clientX,
    startWidth: $(".inspector").getBoundingClientRect().width,
  };
  resizer.setPointerCapture(event.pointerId);
  resizer.classList.add("active");
  document.body.classList.add("resizing-panels");
  event.preventDefault();
}

function movePanelResize(event) {
  if (!state.panelResize || event.pointerId !== state.panelResize.pointerId) return;
  setInspectorWidth(state.panelResize.startWidth - (event.clientX - state.panelResize.startX));
}

function stopPanelResize(event) {
  if (!state.panelResize || event.pointerId !== state.panelResize.pointerId) return;
  const resizer = event.currentTarget;
  if (resizer.hasPointerCapture(event.pointerId)) resizer.releasePointerCapture(event.pointerId);
  resizer.classList.remove("active");
  document.body.classList.remove("resizing-panels");
  state.panelResize = null;
}

function resetPanelWidths() {
  $("#workspace").style.removeProperty("--inspector-width");
  requestAnimationFrame(constrainPanelWidths);
}

function resizePanelsWithKeyboard(event) {
  if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
  const current = $(".inspector").getBoundingClientRect().width;
  setInspectorWidth(current + (event.key === "ArrowLeft" ? 24 : -24));
  event.preventDefault();
}

function constrainPanelWidths() {
  const workspace = $("#workspace");
  const width = $(".inspector").getBoundingClientRect().width;
  if (!width) return;
  if (workspace.style.getPropertyValue("--inspector-width")) {
    setInspectorWidth(width);
    return;
  }
  const bounds = panelWidthBounds();
  const resizer = $("#source-issue-resizer");
  resizer.setAttribute("aria-valuemin", String(Math.round(bounds.minimum)));
  resizer.setAttribute("aria-valuemax", String(Math.round(bounds.maximum)));
  resizer.setAttribute("aria-valuenow", String(Math.round(width)));
}

async function loadTasks() {
  const payload = await api("/api/tasks");
  state.tasks = payload.tasks;
  renderTaskList();
  return payload;
}

async function refreshTasksQuietly() {
  try {
    await loadTasks();
    if (state.selectedTask) {
      const latest = state.tasks.find(item => item.id === state.selectedTask.id);
      if (latest) {
        const changedMode = REQUIREMENT_STATUSES.has(latest.status) !== REQUIREMENT_STATUSES.has(state.selectedTask.status);
        const changedRequirementStatus = REQUIREMENT_STATUSES.has(latest.status) && latest.status !== state.selectedTask.status;
        if (changedMode) { await selectTask(latest.id); return; }
        Object.assign(state.selectedTask, latest); renderTaskHeader(); renderTaskMode();
        if (changedRequirementStatus) await loadRequirementReview();
      }
    }
  } catch { /* SSE and the status indicator already communicate connectivity. */ }
}

function renderTaskList() {
  const list = $("#task-list");
  const needle = $("#task-search").value.trim().toLowerCase();
  const tasks = state.tasks.filter(task => `${task.name} ${task.project_name}`.toLowerCase().includes(needle));
  $("#task-count").textContent = state.tasks.length;
  list.replaceChildren();
  if (!tasks.length) {
    const empty = document.createElement("div"); empty.className = "sidebar-empty";
    empty.textContent = state.tasks.length ? "没有匹配的任务" : "尚无验证记录\n创建任务后将在这里持续保存";
    list.append(empty); return;
  }
  tasks.forEach(task => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `task-item ${state.selectedTask?.id === task.id ? "active" : ""}`;
    const indicator = document.createElement("span"); indicator.className = `task-indicator ${task.status}`;
    const copy = document.createElement("span"); copy.className = "task-copy";
    const title = document.createElement("strong"); title.textContent = task.name;
    const meta = document.createElement("span"); meta.className = "task-meta";
    const project = document.createElement("span"); project.textContent = task.project_name;
    const info = document.createElement("span"); info.className = task.issue_count ? "task-issues" : "";
    info.textContent = task.issue_count ? `${task.issue_count} 个问题` : shortDate(task.created_at);
    meta.append(project, info); copy.append(title, meta); button.append(indicator, copy);
    button.addEventListener("click", () => selectTask(task.id)); list.append(button);
  });
}

async function selectTask(taskId) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  try {
    const task = await api(`/api/tasks/${taskId}`);
    state.selectedTask = task;
    state.selectedSource = null; state.selectedIssue = null; state.sourceHistory = []; state.currentDocument = null;
    state.requirementCategories = []; state.selectedRequirementCategory = null;
    state.requirementViewMode = "preview"; state.requirementPreviewRequest += 1;
    state.materialCategoryPayload = null; state.newRequirementFiles = [];
    $("#requirement-new-files").value = "";
    $("#requirement-new-files-label").textContent = "可选择新的需求文档，重新生成时一并处理";
    clearTimeout(state.contentSearchTimer); state.contentSearchRequest += 1; state.contentSearch = null;
    $("#project-search-input").value = "";
    $("#project-search-results").classList.add("hidden"); $("#file-tree").classList.remove("hidden");
    $("#tree-search").closest(".tree-search").classList.remove("hidden");
    $("#empty-state").classList.add("hidden"); $("#task-view").classList.remove("hidden");
    if (REQUIREMENT_STATUSES.has(task.status)) {
      state.treeFiles = []; state.materialFiles = []; state.logs = []; state.requirementReview = null;
      renderTaskList(); renderTaskHeader(); renderTaskMode(); await loadRequirementReview();
    } else {
      const [tree, logs] = await Promise.all([
        api(`/api/tasks/${taskId}/tree`), api(`/api/tasks/${taskId}/logs?lines=500`),
      ]);
      state.treeFiles = tree.files; state.materialFiles = tree.materials || [];
      state.logs = logs.lines.map(line => ({ line, stream: "process" }));
      renderTaskList(); renderTaskHeader(); renderTaskMode(); renderFileTree(); renderIssues(false); renderLogs(); clearSource();
      requestAnimationFrame(constrainPanelWidths);
    }
    connectEvents(taskId, task.last_event_id || 0);
  } catch (error) { toast(error.message, "error"); }
}

function renderTaskMode() {
  const requirementMode = REQUIREMENT_STATUSES.has(state.selectedTask?.status);
  $("#task-view").classList.toggle("requirement-mode", requirementMode);
  $("#requirement-stage").classList.toggle("hidden", !requirementMode);
  $("#verification-stage").classList.toggle("hidden", requirementMode);
}

async function loadRequirementReview() {
  if (!state.selectedTask || !REQUIREMENT_STATUSES.has(state.selectedTask.status)) return;
  const taskId = state.selectedTask.id;
  try {
    const review = await api(`/api/tasks/${taskId}/${reviewRoute()}`);
    if (state.selectedTask?.id !== taskId) return;
    state.requirementReview = review;
    state.requirementCategories = (state.requirementReview.categories || []).map(category => ({ ...category }));
    state.selectedRequirementCategory = state.requirementCategories[0]?.key || null;
    state.requirementViewMode = "preview"; state.requirementPreviewRequest += 1;
    renderRequirementStage();
  } catch (error) { toast(error.message, "error"); }
}

function renderRequirementStage() {
  const task = state.selectedTask; const review = state.requirementReview || {};
  if (!task || !REQUIREMENT_STATUSES.has(task.status)) return;
  const domain = isDomainReview(); const label = domain ? "领域规约" : "设计意图";
  const processing = task.status === (domain ? "domain_preprocessing" : "preprocessing");
  const ready = task.status === (domain ? "awaiting_domain_confirmation" : "awaiting_confirmation");
  const failed = task.status === (domain ? "domain_preprocess_failed" : "preprocess_failed");
  $("#requirement-step").classList.toggle("active", !domain);
  $("#requirement-step").classList.toggle("completed", domain && Boolean(task.has_requirement_docs));
  $("#domain-step").classList.toggle("active", domain);
  $("#requirement-step small").textContent = domain && !task.has_requirement_docs ? "未上传，已跳过" : "提取并确认设计意图";
  $("#domain-step small").textContent = !domain && !task.has_domain_docs ? "未上传，自动跳过" : "分类并人工确认";
  $("#requirement-stage-label").textContent = domain ? "领域规约整理" : "需求预处理";
  $("#requirement-new-files-button").textContent = domain ? "＋ 添加或替换 Markdown/TXT" : "＋ 添加或替换 DOCX";
  $("#requirement-new-files").accept = domain ? ".md,.txt,text/markdown,text/plain" : ".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  if (!state.newRequirementFiles.length) $("#requirement-new-files-label").textContent = domain
    ? "可选择新的领域规约，重新生成时一并处理" : "可选择新的需求文档，重新生成时一并处理";
  $("#requirement-review-title").textContent = `分类确认${label}`;
  $("#requirement-review-note").textContent = domain
    ? "请重点检查条款依据、数值、单位与待确认事项；不确定的内容不要作为确定规约。"
    : "请重点检查需求编号、数值、单位、状态转换，以及模型标记为“待确认”的内容。";
  $("#requirement-confirm").textContent = domain ? "确认领域规约并开始验证" : "确认设计意图并继续";
  $("#requirement-processing-title").textContent = `正在生成适合 FM-Agent 的${label}`;
  $("#requirement-failure-title").textContent = domain ? "领域规约整理失败" : "需求预处理失败";
  $("#requirement-processing").classList.toggle("hidden", !processing);
  $("#requirement-review").classList.toggle("hidden", !ready);
  $("#requirement-failure").classList.toggle("hidden", !failed);
  $("#requirement-reupload").classList.toggle("hidden", processing);
  const icon = $("#requirement-state-icon");
  icon.className = `requirement-state-icon ${processing ? "loading" : ready ? "ready" : "failed"}`;
  $("#requirement-state-title").textContent = processing ? (domain ? "正在整理领域规约" : "正在整理需求文档") : ready ? `${label}已生成，等待人工确认` : (domain ? "领域规约整理失败" : "需求预处理失败");
  $("#requirement-state-copy").textContent = processing
    ? (domain ? "正在读取 Markdown/TXT，并由大模型分类整理成可追溯的中文领域条款。" : "正在提取 Word 正文和表格，并由大模型生成中文设计意图。")
    : ready ? `已使用 ${review.model || "当前模型"} 完成整理，确认后才会进入代码验证。`
      : "原始材料和源码均已保留，可以修正模型配置后重新生成。";
  $("#requirement-failure-message").textContent = review.error || task.error || "未知错误";
  const sources = $("#requirement-review-sources"); sources.replaceChildren();
  (review.documents || []).forEach(documentInfo => {
    const chip = document.createElement("span"); chip.className = "intent-review-source";
    const detail = documentInfo.characters ? ` · ${Number(documentInfo.characters).toLocaleString("zh-CN")} 字符 · ${documentInfo.chunks} 个分段` : "";
    const kind = document.createElement("b"); kind.textContent = domain ? "MD/TXT" : "DOCX";
    chip.append(kind, document.createTextNode(` ${documentInfo.name}${detail}`)); sources.append(chip);
  });
  if (ready) renderRequirementCategories();
  if (!processing) setRequirementActionBusy(false);
}

function countRequirementRules(content) {
  const lines = String(content || "").split("\n");
  const count = lines.filter(line => /^\s*(?:[-*+] |\d+[.)] )/.test(line) && !(line.includes("未") && line.includes("识别到明确约束"))).length;
  return count || (String(content || "").trim() ? 1 : 0);
}

function saveCurrentRequirementCategory() {
  if (state.requirementViewMode !== "edit") return;
  const category = state.requirementCategories.find(item => item.key === state.selectedRequirementCategory);
  if (!category) return;
  const content = $("#requirement-category-content").value;
  if (category.content !== content) {
    category.content = content;
    // Editing one category can shift every later rule number.
    state.requirementCategories.forEach(item => { item.rendered_html = null; });
  }
}

function setRequirementViewMode(mode) {
  if (state.requirementViewMode === mode) return;
  saveCurrentRequirementCategory();
  state.requirementViewMode = mode;
  renderRequirementCategories();
  if (mode === "edit") $("#requirement-category-content").focus();
}

function showRequirementPreview(html) {
  const preview = $("#requirement-category-preview");
  if (!html) { preview.textContent = "本类别暂无内容"; return; }
  // HTML is rendered server-side with raw Markdown HTML disabled.
  preview.innerHTML = html;
  preview.querySelectorAll("a[href]").forEach(link => {
    if (/^https?:/i.test(link.getAttribute("href"))) {
      link.target = "_blank"; link.rel = "noopener noreferrer";
    }
  });
}

async function loadRequirementCategoryPreview(category, requestId) {
  const taskId = state.selectedTask?.id;
  const categories = state.requirementCategories;
  const snapshot = categories.map(item => item.content);
  const markdown = composeRequirementMarkdown();
  $("#requirement-category-preview").textContent = "正在生成预览…";
  try {
    const result = await api(`/api/tasks/${taskId}/${reviewRoute()}/preview`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ markdown, category: category.key }),
    });
    if (!Array.isArray(result.categories)) throw new Error("当前服务版本不支持条款编号，请重启服务");
    if (requestId !== state.requirementPreviewRequest || state.selectedTask?.id !== taskId ||
        state.selectedRequirementCategory !== category.key || state.requirementViewMode !== "preview" ||
        state.requirementCategories !== categories ||
        categories.some((item, index) => item.content !== snapshot[index])) return;
    const updatedByKey = new Map(result.categories.map(item => [item.key, item]));
    categories.forEach(item => {
      const updated = updatedByKey.get(item.key);
      if (updated) { item.content = updated.content; item.rendered_html = updated.rendered_html; }
    });
    renderRequirementCategories();
  } catch (error) {
    if (requestId === state.requirementPreviewRequest && state.selectedTask?.id === taskId &&
        state.selectedRequirementCategory === category.key && state.requirementViewMode === "preview") {
      $("#requirement-category-preview").textContent = `预览失败：${error.message}。可切换到编辑查看原文。`;
    }
  }
}

function renderRequirementCategories() {
  const requestId = ++state.requirementPreviewRequest;
  const list = $("#requirement-category-list"); list.replaceChildren();
  state.requirementCategories.forEach(category => {
    const button = document.createElement("button"); button.type = "button";
    button.className = `requirement-category-item ${category.key === state.selectedRequirementCategory ? "active" : ""} ${category.key === "questions" ? "questions" : ""}`;
    const title = document.createElement("span"); title.textContent = category.title;
    const count = document.createElement("b"); count.textContent = countRequirementRules(category.content);
    button.append(title, count);
    button.addEventListener("click", () => {
      saveCurrentRequirementCategory(); state.selectedRequirementCategory = category.key; renderRequirementCategories();
    });
    list.append(button);
  });
  const current = state.requirementCategories.find(item => item.key === state.selectedRequirementCategory);
  if (!current) return;
  $("#requirement-category-title").textContent = current.title;
  $("#requirement-category-description").textContent = current.description || "";
  $("#requirement-category-count").textContent = `${countRequirementRules(current.content)} 条`;
  $("#requirement-category-content").value = current.content || "";
  const previewMode = state.requirementViewMode === "preview";
  $("#requirement-category-preview").classList.toggle("hidden", !previewMode);
  $("#requirement-category-content").classList.toggle("hidden", previewMode);
  $("#requirement-view-preview").setAttribute("aria-pressed", String(previewMode));
  $("#requirement-view-edit").setAttribute("aria-pressed", String(!previewMode));
  if (previewMode) {
    if (current.rendered_html == null) loadRequirementCategoryPreview(current, requestId);
    else showRequirementPreview(current.rendered_html);
  }
}

function onRequirementCategoryInput() {
  saveCurrentRequirementCategory();
  const current = state.requirementCategories.find(item => item.key === state.selectedRequirementCategory);
  if (!current) return;
  const count = countRequirementRules(current.content);
  $("#requirement-category-count").textContent = `${count} 条`;
  const badge = $(`.requirement-category-item.active b`, $("#requirement-category-list"));
  if (badge) badge.textContent = count;
}

function composeRequirementMarkdown() {
  saveCurrentRequirementCategory();
  const lines = isDomainReview()
    ? ["# 领域规约（经人工确认）", "", "> 本文由领域材料整理；待确认事项不作为已确定的验证约束。"]
    : ["# 设计意图（由需求文档整理）", "", "> 本文由大模型从原始需求文档中整理。开始验证前必须由人工确认；“待确认事项”不应直接视为确定约束。"];
  state.requirementCategories.forEach(category => {
    lines.push("", `## ${category.title}`, "", String(category.content || "").trim() || "- 未从上传文档中识别到明确约束。");
  });
  return `${lines.join("\n").trim()}\n`;
}

function renderTaskHeader() {
  const task = state.selectedTask; if (!task) return;
  $("#task-title").textContent = task.name;
  $("#task-project").textContent = task.project_name;
  $("#task-created").textContent = `创建于 ${formatDate(task.created_at)}`;
  $("#task-id").textContent = `ID ${task.id.slice(0, 8)}`;
  const status = $("#task-status"); status.textContent = STATUS[task.status] || task.status; status.className = `status-pill ${task.status}`;
  $("#task-phase").textContent = task.phase;
  $("#phase-icon").className = `phase-icon ${task.status}`;
  const totalFunctions = Number(task.progress_total) || 0;
  const verificationCompleted = Number(task.progress_completed) || 0;
  const specCompleted = Number(task.spec_completed) || (
    task.status === "completed" && totalFunctions && verificationCompleted >= totalFunctions
      ? totalFunctions : 0
  );
  task.display_spec_completed = specCompleted;
  $("#spec-metric").textContent = totalFunctions ? `${specCompleted}/${totalFunctions}` : specCompleted || "0";
  $("#processed-metric").textContent = task.progress_total ? `${task.progress_completed}/${task.progress_total}` : task.progress_completed || "0";
  const functionProgress = $("#task-function-progress");
  let functionProgressText = totalFunctions ? `已识别 ${totalFunctions} 个函数` : "等待提取函数";
  if (task.progress_source_file || task.progress_function) {
    const location = [task.progress_source_file, task.progress_function ? `${task.progress_function}()` : ""].filter(Boolean).join(" › ");
    functionProgressText = `最近处理：${location}`;
  } else if (Number(task.stage_number) === 6 && totalFunctions) {
    functionProgressText = "正在生成函数规约";
  }
  if (task.status === "completed" && Number(task.verification_error_count) > 0) {
    functionProgressText = `验证中有 ${task.verification_error_count} 个错误`;
  }
  functionProgress.textContent = functionProgressText;
  functionProgress.title = functionProgressText;
  $("#issue-metric").textContent = task.issue_count || 0;
  $("#duration-metric").textContent = elapsed(task);
  $("#file-count").textContent = state.materialFiles.length
    ? `${task.file_count} 个文件 · ${state.materialFiles.length} 份材料`
    : `${task.file_count} 个文件`;
  renderActivitySteps(task);
  const endButton = $("#end-task-button");
  endButton.classList.toggle("hidden", !["queued","running","cancelling"].includes(task.status));
  endButton.disabled = task.status === "cancelling";
  endButton.textContent = task.status === "cancelling" ? "正在结束…" : "结束任务";
  $("#resume-button").classList.toggle("hidden", !["failed","cancelled"].includes(task.status));
  $("#rerun-button").classList.toggle("hidden", task.status !== "completed");
  const adjustButton = $("#adjust-intent-button");
  const canAdjust = Boolean(task.can_revise_intent) && !REQUIREMENT_STATUSES.has(task.status);
  adjustButton.classList.toggle("hidden", !canAdjust);
  adjustButton.disabled = task.status === "cancelling";
  adjustButton.textContent = task.status === "cancelling" ? "正在停止…" : "调整设计意图";
  $("#task-error").classList.toggle("hidden", !task.error || task.status === "completed");
  $("#task-error").textContent = task.error || "";
  $("#issue-tab-count").textContent = task.issue_count || 0;
  $("#marked-tab-count").textContent = (task.issues || []).filter(issue => issue.is_marked).length;
  renderIssueOverview(task.issues || []);
  clearInterval(state.durationTimer);
  if (task.status === "running") state.durationTimer = setInterval(() => { $("#duration-metric").textContent = elapsed(state.selectedTask); }, 1000);
}

function renderIssueOverview(issues) {
  const counts = { high: 0, medium: 0, low: 0, pending: 0 };
  issues.forEach(issue => {
    if (issue.severity === "高") counts.high += 1;
    else if (issue.severity === "中") counts.medium += 1;
    else if (issue.severity === "低") counts.low += 1;
    else counts.pending += 1;
  });
  $("#overview-issue-total").textContent = issues.length;
  $("#overview-issue-high").textContent = counts.high;
  $("#overview-issue-medium").textContent = counts.medium;
  $("#overview-issue-low").textContent = counts.low;
  $("#overview-issue-pending").textContent = counts.pending;
}

function renderActivitySteps(task) {
  let currentStage = Number(task.stage_number) || PHASE_STAGE[task.phase] || 0;
  if (!currentStage && task.progress_total > 0) currentStage = 6;
  if (!currentStage && task.status !== "completed") currentStage = 1;
  $$(".activity-step", $("#activity-steps")).forEach((step, index) => {
    const number = index + 1;
    const detail = $("small", step);
    step.className = "activity-step";
    detail.textContent = "";
    if (task.status === "completed" || number < currentStage) {
      step.classList.add("completed");
      if (task.status === "completed" && number === 6) detail.textContent = task.verification_error_count
        ? `${task.verification_error_count} 个错误` : "全部完成";
      return;
    }
    if (number !== currentStage) return;
    if (task.status === "failed") {
      step.classList.add("failed"); detail.textContent = "在此失败";
    } else if (task.status === "cancelled") {
      step.classList.add("cancelled"); detail.textContent = "在此结束";
    } else if (task.status === "queued") {
      step.classList.add("waiting"); detail.textContent = "等待开始";
    } else {
      step.classList.add("current");
      detail.textContent = number === 6 && task.progress_total
        ? `规约 ${task.display_spec_completed || task.spec_completed || 0}/${task.progress_total} · 验证 ${task.progress_completed}/${task.progress_total}`
        : (task.status === "cancelling" ? "正在结束" : "进行中");
    }
  });
}

function connectEvents(taskId, after) {
  const source = new EventSource(`/api/tasks/${taskId}/events?after=${after}`);
  state.eventSource = source;
  const handleTask = event => {
    const payload = JSON.parse(event.data);
    if (!state.selectedTask || payload.task.id !== state.selectedTask.id) return;
    const wasRequirementMode = REQUIREMENT_STATUSES.has(state.selectedTask.status);
    const previousStatus = state.selectedTask.status;
    Object.assign(state.selectedTask, payload.task); renderTaskHeader(); renderTaskMode();
    const item = state.tasks.find(task => task.id === payload.task.id); if (item) Object.assign(item, payload.task);
    renderTaskList();
    const requirementMode = REQUIREMENT_STATUSES.has(state.selectedTask.status);
    if (wasRequirementMode && !requirementMode) {
      selectTask(state.selectedTask.id); return;
    }
    if (requirementMode && previousStatus !== state.selectedTask.status) loadRequirementReview();
  };
  source.addEventListener("task.updated", handleTask);
  source.addEventListener("issue.created", event => upsertIssue(JSON.parse(event.data).issue, true));
  source.addEventListener("issue.updated", event => upsertIssue(JSON.parse(event.data).issue, false));
  source.addEventListener("spec.updated", event => {
    const updated = JSON.parse(event.data);
    const current = state.currentDocument;
    if (updated.kind !== "code" || current?.kind !== "source" || current.path !== updated.source_file) return;
    openSource(current.path, current.startLine, current.endLine, {
      recordHistory: false, restoreScroll: $("#source-code").scrollTop, ruleId: current.ruleId,
    });
  });
  source.addEventListener("log", event => {
    const item = JSON.parse(event.data); state.logs.push(item); if (state.logs.length > 1000) state.logs.shift(); appendLog(item);
  });
  source.addEventListener("report.updated", async () => {
    if (state.selectedTask?.id === taskId) state.selectedTask.reports = await api(`/api/tasks/${taskId}/reports`);
  });
  source.onerror = () => { if (state.selectedTask?.status && ["completed","failed","cancelled"].includes(state.selectedTask.status)) source.close(); };
}

function upsertIssue(issue, notify) {
  if (!state.selectedTask || issue.task_id !== state.selectedTask.id) return;
  const index = state.selectedTask.issues.findIndex(item => item.id === issue.id);
  if (index >= 0) state.selectedTask.issues[index] = issue; else state.selectedTask.issues.push(issue);
  state.selectedTask.issue_count = state.selectedTask.issues.length;
  renderTaskHeader(); renderIssues();
  if (notify && index < 0) toast(`发现 MISMATCH：${issue.function_name}`);
}

function buildTree(files, rootName, kind = "source") {
  const root = { name: rootName, kind, dirs: new Map(), files: [] };
  files.forEach(entry => {
    const parts = entry.path.split("/"); let node = root;
    parts.slice(0, -1).forEach(part => {
      if (!node.dirs.has(part)) node.dirs.set(part, { name: part, dirs: new Map(), files: [] });
      node = node.dirs.get(part);
    });
    node.files.push({ ...entry, name: parts.at(-1) });
  });
  return root;
}

function renderFileTree() {
  const container = $("#file-tree"); container.replaceChildren();
  const needle = $("#tree-search").value.trim().toLowerCase();
  const projectName = state.selectedTask?.project_name || state.projectName || "工程源码";
  const sourceFiles = !needle || projectName.toLowerCase().includes(needle)
    ? state.treeFiles
    : state.treeFiles.filter(file => file.path.toLowerCase().includes(needle));
  if (!needle || sourceFiles.length) renderTreeNode(buildTree(sourceFiles, projectName), container, 0, true);
  [["domain", "领域规约"], ["intent", "设计意图"]].forEach(([category, folderName]) => {
    const categoryFiles = state.materialFiles.filter(file => file.category === category ||
      (category === "domain" && file.category === "domain-source"));
    if (!categoryFiles.length) return;
    const visibleFiles = !needle || folderName.includes(needle)
      ? categoryFiles
      : categoryFiles.filter(file => file.path.toLowerCase().includes(needle));
    if (visibleFiles.length) renderTreeNode(buildTree(visibleFiles, folderName, category), container, 0, true);
  });
}

function queueContentSearch() {
  clearTimeout(state.contentSearchTimer);
  const request = ++state.contentSearchRequest;
  const query = $("#project-search-input").value;
  const searching = Boolean(query.trim());
  $("#project-search-results").classList.toggle("hidden", !searching);
  $("#file-tree").classList.toggle("hidden", searching);
  $("#tree-search").closest(".tree-search").classList.toggle("hidden", searching);
  if (!searching) { state.contentSearch = null; return; }
  $("#project-search-results").textContent = "正在搜索…";
  state.contentSearchTimer = setTimeout(async () => {
    const taskId = state.selectedTask?.id;
    if (!taskId) return;
    const options = new URLSearchParams({ q: query });
    [["search-case", "case"], ["search-word", "word"], ["search-regex", "regex"]].forEach(([id, key]) => {
      if ($("#" + id).getAttribute("aria-pressed") === "true") options.set(key, "1");
    });
    try {
      const results = await api(`/api/tasks/${taskId}/search?${options}`);
      if (request !== state.contentSearchRequest || taskId !== state.selectedTask?.id) return;
      state.contentSearch = results; renderContentSearchResults();
    } catch (error) {
      if (request === state.contentSearchRequest) {
        $("#project-search-results").textContent = error.message;
      }
    }
  }, 280);
}

function renderContentSearchResults() {
  const container = $("#project-search-results"); container.replaceChildren();
  const result = state.contentSearch;
  if (!result) return;
  const summary = document.createElement("div"); summary.className = "search-summary";
  summary.textContent = `${result.total_matches} 处结果 · ${result.files.length} 个文件${result.truncated ? " · 只显示前 1000 处" : ""}`;
  container.append(summary);
  if (!result.files.length) {
    const empty = document.createElement("p"); empty.className = "search-empty";
    empty.textContent = "当前工程及验证材料中未找到匹配内容"; container.append(empty); return;
  }
  result.files.forEach(file => {
    const group = document.createElement("details"); group.className = "search-file-group"; group.open = true;
    const heading = document.createElement("summary");
    const path = document.createElement("span"); path.textContent = file.display_path; path.title = file.display_path;
    const count = document.createElement("b"); count.textContent = file.matches.length;
    heading.append(path, count); group.append(heading);
    file.matches.forEach(match => {
      const button = document.createElement("button"); button.type = "button"; button.className = "search-match";
      const line = document.createElement("span"); line.className = "search-match-line"; line.textContent = match.line;
      const preview = document.createElement("span"); preview.className = "search-match-preview";
      const start = match.preview_column; const end = start + match.preview_length;
      preview.append(document.createTextNode(match.preview.slice(0, start)));
      const hit = document.createElement("mark"); hit.textContent = match.preview.slice(start, end); preview.append(hit);
      preview.append(document.createTextNode(match.preview.slice(end)));
      button.append(line, preview);
      button.addEventListener("click", () => {
        const searchMatch = { line: match.line, column: match.column, length: match.length };
        if (file.kind === "material") openMaterial(file, { searchMatch });
        else openSource(file.path, match.line, match.line, { searchMatch });
      });
      group.append(button);
    });
    container.append(group);
  });
}

function renderTreeNode(node, parent, depth, root = false) {
  const wrap = document.createElement("div"); wrap.className = "tree-node";
  const row = document.createElement("div"); row.className = "tree-row"; row.style.paddingLeft = `${depth * 13 + 4}px`;
  const toggle = document.createElement("span"); toggle.className = "tree-toggle"; toggle.textContent = "⌄";
  const icon = document.createElement("span"); icon.className = `tree-icon ${node.kind !== "source" ? `material-folder ${node.kind}` : ""}`; icon.textContent = "▰";
  const label = document.createElement("span"); label.className = "tree-label"; label.textContent = node.name || "工程";
  row.append(toggle, icon, label); wrap.append(row);
  const children = document.createElement("div"); children.className = "tree-children";
  [...node.dirs.values()].sort((a,b) => a.name.localeCompare(b.name)).forEach(child => renderTreeNode(child, children, depth + 1));
  node.files.sort((a,b) => a.name.localeCompare(b.name)).forEach(file => {
    const fileKey = treeFileKey(file);
    const fileRow = document.createElement("div"); fileRow.className = `tree-row ${state.selectedSource === fileKey ? "active" : ""}`; fileRow.style.paddingLeft = `${(depth + 1) * 13 + 4}px`;
    const spacer = document.createElement("span"); spacer.className = "tree-toggle";
    const fileIcon = document.createElement("span"); fileIcon.className = `tree-icon file ${file.kind === "material" ? "material-file" : ""}`; fileIcon.textContent = file.kind === "material" ? "文" : file.is_source ? "<>" : "•";
    const name = document.createElement("span"); name.className = "tree-label"; name.textContent = file.display_name || file.name; name.title = file.path;
    fileRow.append(spacer, fileIcon, name);
    fileRow.addEventListener("click", () => file.kind === "material" ? openMaterial(file) : openSource(file.path));
    children.append(fileRow);
  });
  row.addEventListener("click", () => { children.classList.toggle("collapsed"); toggle.textContent = children.classList.contains("collapsed") ? "›" : "⌄"; });
  wrap.append(children); parent.append(wrap);
}

function treeFileKey(file) {
  return file.kind === "material" ? `material:${file.category}:${file.path}` : `source:${file.path}`;
}

async function openSource(path, startLine = null, endLine = null, options = {}) {
  try {
    const payload = await api(
      `/api/tasks/${state.selectedTask.id}/source?path=${encodeURIComponent(path)}`,
      options.signal ? { signal: options.signal } : {},
    );
    if (options.recordHistory !== false) rememberCurrentDocument();
    state.selectedSource = `source:${path}`; renderFileTree();
    state.materialCategoryPayload = null;
    state.currentDocument = { kind: "source", path, startLine, endLine, scrollTop: 0, searchMatch: options.searchMatch || null, ruleId: options.ruleId || null };
    renderTextFile(payload, path, startLine, endLine, false, options.restoreScroll, options.searchMatch, options.ruleId);
    updateSourceBackButton();
  } catch (error) { toast(error.name === "AbortError" ? "源码加载超时，请重试" : error.message, "error"); }
}

async function openMaterial(file, options = {}) {
  try {
    const payload = await api(`/api/tasks/${state.selectedTask.id}/material?category=${encodeURIComponent(file.category)}&name=${encodeURIComponent(file.path)}`);
    if (options.recordHistory !== false) rememberCurrentDocument();
    state.selectedSource = treeFileKey(file); renderFileTree();
    state.currentDocument = { kind: "material", category: file.category, path: file.path, startLine: null, endLine: null, scrollTop: 0, categoryKey: options.categoryKey || null, searchMatch: options.searchMatch || null, ruleId: options.ruleId || null };
    state.materialCategoryPayload = payload.categories?.length ? payload : null;
    if (state.materialCategoryPayload) {
      renderMaterialCategories(payload, options);
    } else {
      state.materialCategoryPayload = null;
      renderTextFile(payload, payload.display_path, options.searchMatch?.line, options.searchMatch?.line, true, options.restoreScroll, options.searchMatch);
    }
    updateSourceBackButton();
  } catch (error) { toast(error.message, "error"); }
}

function rememberCurrentDocument() {
  if (!state.currentDocument) return;
  const scrollArea = state.materialCategoryPayload ? $("#material-category-content") : $("#source-code");
  state.sourceHistory.push({ ...state.currentDocument, scrollTop: scrollArea.scrollTop });
  if (state.sourceHistory.length > 100) state.sourceHistory.shift();
  updateSourceBackButton();
}

async function navigateSourceBack() {
  const target = state.sourceHistory.pop();
  if (!target) return;
  updateSourceBackButton();
  if (target.kind === "material") {
    const file = state.materialFiles.find(item => item.category === target.category && item.path === target.path);
    if (file) await openMaterial(file, { recordHistory: false, restoreScroll: target.scrollTop, categoryKey: target.categoryKey, searchMatch: target.searchMatch, ruleId: target.ruleId });
    return;
  }
  await openSource(target.path, target.startLine, target.endLine, { recordHistory: false, restoreScroll: target.scrollTop, searchMatch: target.searchMatch, ruleId: target.ruleId });
}

function updateSourceBackButton() {
  $("#source-back").disabled = !state.sourceHistory.length;
}

async function followSourceSymbol(event) {
  if (!event.ctrlKey || state.currentDocument?.kind !== "source") return;
  const token = event.target.closest(".symbol-token");
  if (!token || !$("#source-code").contains(token)) return;
  event.preventDefault();
  const row = token.closest(".code-line");
  const symbol = token.dataset.symbol;
  const line = Number(row?.dataset.line || 1);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  token.classList.add("resolving");
  try {
    const result = await api(
      `/api/tasks/${state.selectedTask.id}/definition?path=${encodeURIComponent(state.currentDocument.path)}&symbol=${encodeURIComponent(symbol)}&line=${line}`,
      { signal: controller.signal },
    );
    if (!result.found) { toast(`未找到“${symbol}”的定义`); return; }
    const definition = result.definition;
    await openSource(definition.path, definition.line, definition.line, { signal: controller.signal });
  } catch (error) {
    toast(error.name === "AbortError" ? "定义查找超时，请重试" : error.message, "error");
  } finally {
    clearTimeout(timeout);
    token.classList.remove("resolving");
  }
}

function renderTextFile(payload, displayPath, startLine = null, endLine = null, material = false, restoreScroll = null, searchMatch = null, ruleId = null) {
  $("#material-category-view").classList.add("hidden");
  $("#source-empty").classList.add("hidden"); $("#source-code").classList.remove("hidden");
  $("#source-file-icon").textContent = material ? "文" : "</>";
  $("#source-path").textContent = displayPath;
  const location = startLine ? `L${startLine}${endLine && endLine !== startLine ? `–L${endLine}` : ""}` : "";
  $("#source-location").textContent = [location, payload.encoding].filter(Boolean).join(" · ");
  const code = $("#source-code"); code.replaceChildren();
  const specsByLine = new Map();
  if (!material) (payload.function_specs || []).forEach(rule => {
    const line = rule.source_line || 1;
    if (!specsByLine.has(line)) specsByLine.set(line, new Map());
    const functions = specsByLine.get(line);
    if (!functions.has(rule.function_name)) functions.set(rule.function_name, []);
    functions.get(rule.function_name).push(rule);
  });
  payload.content.split("\n").forEach((text, index) => {
    const lineNumber = index + 1; const row = document.createElement("div");
    (specsByLine.get(lineNumber) || new Map()).forEach((rules, functionName) => {
      const details = document.createElement("details"); details.className = "function-spec-block";
      const summary = document.createElement("summary"); summary.textContent = `函数规约 · ${functionName}() · ${rules.length} 条`;
      details.append(summary);
      rules.forEach(rule => {
        const item = document.createElement("div"); item.className = "function-spec-rule";
        item.dataset.ruleId = rule.rule_id;
        const id = document.createElement("b"); id.textContent = `【${rule.rule_id}】`;
        const type = document.createElement("span"); type.className = "function-spec-type"; type.textContent = rule.category;
        const content = document.createElement("span"); content.textContent = rule.content;
        item.append(id, type, content); details.append(item);
      });
      code.append(details);
    });
    row.className = `code-line ${startLine && lineNumber >= startLine && lineNumber <= (endLine || startLine) ? "hit" : ""}`; row.dataset.line = lineNumber;
    const number = document.createElement("span"); number.className = "line-number"; number.textContent = lineNumber;
    const value = document.createElement("span"); value.className = "line-text";
    if (!material && payload.highlighted_lines?.[index] != null) value.innerHTML = payload.highlighted_lines[index] || " ";
    else value.textContent = text || " ";
    if (searchMatch?.line === lineNumber) markSearchText(value, searchMatch.column, searchMatch.length);
    row.append(number, value); code.append(row);
  });
  requestAnimationFrame(() => {
    if (ruleId) {
      const target = [...code.querySelectorAll(".function-spec-rule")].find(node => node.dataset.ruleId === ruleId);
      if (target) { target.closest("details").open = true; target.classList.add("trace-focus"); target.scrollIntoView({ block: "center" }); return; }
    }
    if (restoreScroll != null) { code.scrollTop = restoreScroll; return; }
    if (!startLine) { code.scrollTop = 0; return; }
    const hit = $(`.code-line[data-line="${startLine}"]`, code); if (hit) { hit.classList.add("focus"); hit.scrollIntoView({ block: "center" }); }
  });
}

function markSearchText(element, column, length) {
  if (!length) return;
  const start = column - 1, end = start + length;
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  let offset = 0;
  nodes.forEach(node => {
    const size = node.textContent.length;
    const left = Math.max(0, start - offset), right = Math.min(size, end - offset);
    if (right > left) {
      let segment = node;
      if (left) segment = segment.splitText(left);
      if (right - left < segment.textContent.length) segment.splitText(right - left);
      const mark = document.createElement("mark"); mark.className = "source-search-hit";
      segment.parentNode.replaceChild(mark, segment); mark.append(segment);
    }
    offset += size;
  });
}

function renderMaterialCategories(payload, options = {}) {
  $("#source-empty").classList.add("hidden"); $("#source-code").classList.add("hidden");
  $("#material-category-view").classList.remove("hidden");
  $("#source-file-icon").textContent = "文"; $("#source-path").textContent = payload.display_path;
  $("#source-location").textContent = payload.encoding || "";
  const categories = payload.categories.filter(category => category.start_line != null);
  const searched = categories.find(category => options.searchMatch?.line >= category.start_line && options.searchMatch?.line <= category.end_line);
  const current = categories.find(category => category.key === options.categoryKey) || searched || categories[0];
  if (!current) return;
  state.currentDocument.categoryKey = current.key;
  state.currentDocument.searchMatch = options.searchMatch || null;
  state.currentDocument.ruleId = options.ruleId || null;
  const list = $("#material-category-list"); list.replaceChildren();
  categories.forEach(category => {
    const button = document.createElement("button"); button.type = "button";
    button.className = `requirement-category-item ${category.key === current.key ? "active" : ""} ${category.key === "questions" ? "questions" : ""}`;
    const label = document.createElement("span"); label.textContent = category.title;
    const count = document.createElement("b"); count.textContent = countRequirementRules(category.content);
    button.append(label, count);
    button.addEventListener("click", () => renderMaterialCategories(payload, { categoryKey: category.key }));
    list.append(button);
  });
  $("#material-category-title").textContent = current.title;
  $("#material-category-title").classList.toggle("search-title-hit", options.searchMatch?.line === current.start_line);
  $("#material-category-description").textContent = current.description;
  const content = $("#material-category-content"); content.replaceChildren();
  let hit = null;
  if (typeof current.rendered_html === "string") {
    // HTML is produced server-side with raw Markdown HTML disabled.
    content.innerHTML = current.rendered_html;
    content.querySelectorAll("a[href]").forEach(link => {
      if (/^https?:/i.test(link.getAttribute("href"))) {
        link.target = "_blank"; link.rel = "noopener noreferrer";
      }
    });
    if (options.searchMatch) {
      const line = options.searchMatch.line;
      let span = Infinity;
      content.querySelectorAll("[data-source-start][data-source-end]").forEach(element => {
        const start = Number(element.dataset.sourceStart), end = Number(element.dataset.sourceEnd);
        if (start <= line && line <= end && end - start <= span) {
          hit = element; span = end - start;
        }
      });
      if (hit) {
        hit.classList.add("markdown-search-hit");
        const raw = payload.content.split("\n")[line - 1] || "";
        const needle = raw.slice(options.searchMatch.column - 1, options.searchMatch.column - 1 + options.searchMatch.length);
        const offset = hit.textContent.indexOf(needle);
        if (needle && offset >= 0) markSearchText(hit, offset + 1, needle.length);
      }
    }
    if (options.ruleId) {
      const target = [...content.querySelectorAll("li, p")].find(element => element.textContent.includes(options.ruleId));
      if (target) { hit = target; hit.classList.add("trace-focus"); }
    }
  } else {
    const lines = payload.content.split("\n");
    for (let number = current.start_line + 1; number <= current.end_line; number++) {
      const row = document.createElement("div"); row.className = `material-category-line ${options.searchMatch?.line === number ? "hit" : ""}`;
      row.dataset.line = number;
      const lineNumber = document.createElement("span"); lineNumber.textContent = number;
      const text = document.createElement("span"); text.textContent = lines[number - 1] || " ";
      if (options.searchMatch?.line === number) markSearchText(text, options.searchMatch.column, options.searchMatch.length);
      row.append(lineNumber, text); content.append(row);
    }
    hit = options.searchMatch && $(`.material-category-line[data-line="${options.searchMatch.line}"]`, content);
  }
  requestAnimationFrame(() => {
    if (options.restoreScroll != null) { content.scrollTop = options.restoreScroll; return; }
    if (hit) hit.scrollIntoView({ block: "center" });
    else content.scrollTop = 0;
  });
}

function clearSource() {
  state.materialCategoryPayload = null;
  $("#source-empty").classList.remove("hidden"); $("#source-code").classList.add("hidden");
  $("#material-category-view").classList.add("hidden");
  $("#source-code").replaceChildren(); $("#source-file-icon").textContent = "</>"; $("#source-path").textContent = "选择文件查看源码"; $("#source-location").textContent = "";
  updateSourceBackButton();
}

function captureIssueListView(list) {
  const listRect = list.getBoundingClientRect();
  const cards = $$(".issue-card", list);
  const anchor = cards.find(card => card.getBoundingClientRect().bottom > listRect.top + 1);
  return {
    scrollTop: list.scrollTop,
    anchorId: anchor?.dataset.issueId || null,
    anchorOffset: anchor ? anchor.getBoundingClientRect().top - listRect.top : 0,
    openReports: new Set($$("details.raw-report[open]", list).map(details => details.closest(".issue-card")?.dataset.issueId).filter(Boolean)),
    openTraces: new Set($$("details.issue-trace[open]", list).map(details => details.closest(".issue-card")?.dataset.issueId).filter(Boolean)),
  };
}

function restoreIssueListView(list, view) {
  view.openTraces.forEach(id => {
    const details = $(`.issue-card[data-issue-id="${id}"] details.issue-trace`, list);
    if (details) details.open = true;
  });
  view.openReports.forEach(id => {
    const details = $(`.issue-card[data-issue-id="${id}"] details.raw-report`, list);
    if (details) details.open = true;
  });
  if (!view.anchorId) { list.scrollTop = view.scrollTop; return; }
  const anchor = $(`.issue-card[data-issue-id="${view.anchorId}"]`, list);
  if (!anchor) { list.scrollTop = view.scrollTop; return; }
  const listTop = list.getBoundingClientRect().top;
  list.scrollTop += anchor.getBoundingClientRect().top - listTop - view.anchorOffset;
}

function renderIssueCollection(list, issues, emptyTitle, emptyCopy, preservePosition) {
  const view = preservePosition ? captureIssueListView(list) : null;
  list.replaceChildren();
  if (!issues.length) {
    const empty = document.createElement("div"); empty.className = "no-issues";
    const icon = document.createElement("span"); icon.className = "check-circle"; icon.textContent = emptyTitle.includes("标记") ? "☆" : "✓";
    const title = document.createElement("strong"); title.textContent = emptyTitle;
    const copy = document.createElement("p"); copy.textContent = emptyCopy;
    empty.append(icon, title, copy); list.append(empty);
  } else {
    issues.forEach(issue => list.append(issueCard(issue)));
  }
  if (view) restoreIssueListView(list, view);
}

function renderIssues(preservePosition = true) {
  const filter = $("#severity-filter").value;
  const allIssues = state.selectedTask?.issues || [];
  const issues = allIssues.filter(issue => filter === "all" || (filter === "pending" ? !issue.severity : issue.severity === filter));
  const issueCopy = state.selectedTask?.status === "running" ? "验证仍在进行，新问题会实时显示在这里。" : "可切换筛选条件查看其他问题。";
  renderIssueCollection(
    $("#issue-list"), issues, filter === "all" ? "尚未发现 MISMATCH" : "该级别暂无问题", issueCopy, preservePosition,
  );
  renderIssueCollection(
    $("#marked-issue-list"), allIssues.filter(issue => issue.is_marked), "尚未标记问题", "点击问题右上角的五角星，即可在这里集中查看。", preservePosition,
  );
  $("#marked-tab-count").textContent = allIssues.filter(issue => issue.is_marked).length;
}

function issueCard(issue) {
  const card = document.createElement("article");
  card.dataset.issueId = issue.id;
  card.className = `issue-card ${state.selectedIssue === issue.id ? "selected" : ""} ${issue.is_marked ? "marked" : ""}`;
  const head = document.createElement("div"); head.className = "issue-card-head";
  const severity = document.createElement("span"); const level = issue.severity || "待";
  severity.className = `severity ${issue.severity === "高" ? "high" : issue.severity === "低" ? "low" : issue.severity ? "" : "pending"}`; severity.textContent = level;
  const title = document.createElement("div"); title.className = "issue-title";
  const strong = document.createElement("strong"); strong.textContent = issue.description_zh || `${issue.function_name} 存在静态不一致候选`;
  const path = document.createElement("code"); path.textContent = `${issue.source_file}:${issue.start_line || "?"}`;
  title.append(strong, path); const confidence = document.createElement("span"); confidence.className = "confidence"; confidence.textContent = issue.confidence == null ? "—" : `${issue.confidence}%`;
  const mark = document.createElement("button"); mark.type = "button"; mark.className = `mark-button ${issue.is_marked ? "active" : ""}`;
  mark.textContent = issue.is_marked ? "★" : "☆"; mark.title = issue.is_marked ? "取消标记" : "标记此问题";
  mark.setAttribute("aria-label", mark.title); mark.setAttribute("aria-pressed", String(Boolean(issue.is_marked)));
  mark.addEventListener("click", event => { event.stopPropagation(); toggleIssueMarked(issue, mark); });
  head.append(severity, title, confidence, mark);
  head.addEventListener("click", () => selectIssue(issue));
  const body = document.createElement("div"); body.className = "issue-card-body";
  if (issue.enrichment_status === "failed") {
    const error = document.createElement("p"); error.className = "enrich-error"; error.textContent = issue.enrichment_error || "中文说明生成失败"; body.append(error);
  } else if (issue.enrichment_status !== "ready") {
    const pending = document.createElement("p"); pending.textContent = "已发现问题，正在生成中文说明、问题反例和修改建议…"; body.append(pending);
  }
  if (issue.counterexample_zh) {
    const example = document.createElement("section"); example.className = "counterexample";
    const label = document.createElement("h4"); label.textContent = "问题反例（静态推理）";
    const content = document.createElement("p"); content.textContent = issue.counterexample_zh;
    example.append(label, content); body.append(example);
  }
  if (issue.suggestion_zh) { const label = document.createElement("h4"); label.textContent = "修改建议"; const suggestion = document.createElement("p"); suggestion.textContent = issue.suggestion_zh; body.append(label, suggestion); }
  if (state.selectedTask?.trace_enabled) {
    const trace = document.createElement("details"); trace.className = "issue-trace";
    const rules = issue.violated_specs || [];
    const heading = document.createElement("summary");
    heading.textContent = rules.length ? `违反的规约 · ${rules.length} 条`
      : issue.enrichment_status === "ready" ? "违反的规约 · 未定位" : "违反的规约 · 待追溯";
    trace.append(heading);
    if (rules.length) rules.forEach(rule => {
      const item = document.createElement("div"); item.className = "issue-trace-item";
      const button = document.createElement("button"); button.type = "button"; button.className = "issue-trace-link";
      const kind = { intent: "设计意图", domain: "领域规约", code: "函数规约" }[rule.kind] || "规约";
      button.textContent = `【${rule.rule_id}】${kind} · ${rule.category} ↗`;
      button.addEventListener("click", () => navigateToSpec(rule));
      const content = document.createElement("p"); content.textContent = rule.content;
      const reason = document.createElement("small"); reason.textContent = `对应证据：“${rule.evidence_quote}” · ${rule.reason}`;
      item.append(button, content, reason); trace.append(item);
    });
    else {
      const empty = document.createElement("p"); empty.className = "issue-trace-empty";
      empty.textContent = issue.enrichment_status === "ready"
        ? "现有证据不足以可靠定位违反的具体条款，请人工核对原始报告。"
        : issue.enrichment_status === "failed"
          ? "解读失败，自动追溯尚未完成；可重试或查看原始报告。"
          : "正在根据原始验证证据查找对应条款…";
      trace.append(empty);
    }
    body.append(trace);
  }
  const rawDetails = document.createElement("details"); rawDetails.className = "raw-report";
  const rawSummary = document.createElement("summary"); rawSummary.textContent = "查看解读前的原始验证报告";
  const rawContent = document.createElement("pre"); rawContent.textContent = JSON.stringify(issue.raw || {}, null, 2);
  rawDetails.append(rawSummary, rawContent); body.append(rawDetails);
  const actions = document.createElement("div"); actions.className = "issue-actions";
  const locate = document.createElement("button"); locate.type = "button"; locate.className = "link-button"; locate.textContent = "定位源码 →"; locate.addEventListener("click", () => openSource(issue.source_file, issue.start_line, issue.end_line));
  const status = document.createElement("span"); status.className = `enrich-state ${issue.enrichment_status === "enriching" ? "loading" : ""}`;
  status.textContent = issue.enrichment_status === "ready" ? "中文解读已完成" : issue.enrichment_status === "failed" ? "" : "生成中文说明";
  actions.append(locate, status);
  if (issue.enrichment_status === "failed" || issue.enrichment_status === "ready") { const retry = document.createElement("button"); retry.type = "button"; retry.className = "link-button"; retry.textContent = issue.enrichment_status === "ready" ? "重新解读" : "重新生成"; retry.addEventListener("click", () => retryEnrichment(issue.id)); actions.append(retry); }
  body.append(actions); card.append(head, body); return card;
}

function navigateToSpec(rule) {
  if (rule.kind === "code") {
    openSource(rule.source_file, rule.source_line, rule.source_line, { ruleId: rule.rule_id });
    return;
  }
  const file = state.materialFiles.find(item => item.category === rule.kind && item.path === rule.source_file);
  if (!file) { toast("对应规约文件尚未出现在当前工程目录中", "error"); return; }
  openMaterial(file, { ruleId: rule.rule_id, searchMatch: { line: rule.source_line || 1, column: 1, length: 0 } });
}

function selectIssue(issue) {
  state.selectedIssue = issue.id;
  $$(".issue-card", $(".inspector")).forEach(card => card.classList.toggle("selected", Number(card.dataset.issueId) === issue.id));
  openSource(issue.source_file, issue.start_line, issue.end_line);
}

async function toggleIssueMarked(issue, button) {
  button.disabled = true;
  try {
    const updated = await api(`/api/issues/${issue.id}/mark`, { method: "POST" });
    upsertIssue(updated, false);
    toast(updated.is_marked ? "已加入标记问题" : "已取消问题标记");
  } catch (error) {
    button.disabled = false;
    toast(error.message, "error");
  }
}

async function retryEnrichment(id) {
  try { const issue = await api(`/api/issues/${id}/retry`, { method: "POST" }); upsertIssue(issue, false); toast("已重新提交中文解读"); }
  catch (error) { toast(error.message, "error"); }
}

function selectInspectorTab(name) {
  $$(".inspector-tab").forEach(tab => tab.classList.toggle("active", tab.dataset.tab === name));
  $("#issues-tab").classList.toggle("hidden", name !== "issues");
  $("#marked-tab").classList.toggle("hidden", name !== "marked");
  $("#logs-tab").classList.toggle("hidden", name !== "logs");
  if (name === "logs") $("#log-output").scrollTop = $("#log-output").scrollHeight;
}

function renderLogs() { const output = $("#log-output"); output.replaceChildren(); state.logs.forEach(appendLog); output.scrollTop = output.scrollHeight; }
function appendLog(item) {
  const output = $("#log-output"); const nearBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 60;
  const line = document.createElement("div"); line.className = `log-line ${item.stream === "system" ? "system" : ""}`; line.textContent = item.line; output.append(line);
  while (output.children.length > 1000) output.firstChild.remove(); if (nearBottom) output.scrollTop = output.scrollHeight;
}

function openCreateDialog() {
  resetCreateForm(); $("#create-dialog").showModal();
}

function resetCreateForm() {
  state.uploadFiles = []; state.selectedUploadPaths.clear(); state.projectName = ""; state.domainFiles = []; state.requirementFiles = [];
  $("#create-form").reset(); $("#upload-tree-wrap").classList.add("hidden"); $("#upload-tree").replaceChildren(); $("#material-files").replaceChildren();
  $("#submit-task").disabled = true; $("#submit-task").textContent = "新建任务"; $("#upload-progress-wrap").classList.add("hidden"); $("#upload-progress-wrap").classList.remove("processing");
}

function onDirectorySelected(event) {
  const files = [...event.target.files]; if (!files.length) return;
  const first = files[0].webkitRelativePath || files[0].name; const root = first.split("/")[0];
  state.projectName = root || "未命名工程";
  state.uploadFiles = files.map(file => {
    const full = file.webkitRelativePath || file.name;
    const path = full.startsWith(root + "/") ? full.slice(root.length + 1) : full;
    return { file, path };
  }).sort((a,b) => a.path.localeCompare(b.path));
  state.selectedUploadPaths = new Set(state.uploadFiles.map(item => item.path));
  $("#task-name-input").value = state.projectName; $("#upload-root-name").textContent = state.projectName; $("#upload-tree-wrap").classList.remove("hidden");
  renderUploadTree();
}

function renderUploadTree() {
  const container = $("#upload-tree"); container.replaceChildren();
  state.uploadFiles.forEach(item => {
    const row = document.createElement("label"); row.className = "upload-file"; row.style.setProperty("--depth", Math.max(0, item.path.split("/").length - 1));
    const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selectedUploadPaths.has(item.path);
    check.addEventListener("change", () => { check.checked ? state.selectedUploadPaths.add(item.path) : state.selectedUploadPaths.delete(item.path); updateUploadSummary(); });
    const name = document.createElement("span"); name.textContent = item.path; name.title = item.path; row.append(check, name); container.append(row);
  }); updateUploadSummary();
}

function updateUploadSummary() {
  const selected = state.uploadFiles.filter(item => state.selectedUploadPaths.has(item.path)); const bytes = selected.reduce((sum,item) => sum + item.file.size, 0);
  $("#upload-stats").textContent = `已选 ${selected.length}/${state.uploadFiles.length} 个文件 · ${formatBytes(bytes)}`;
  const all = selected.length === state.uploadFiles.length && selected.length > 0; const some = selected.length > 0 && !all;
  $("#select-all-files").checked = all; $("#select-all-files").indeterminate = some;
  const limitOk = !state.config || (selected.length <= state.config.max_project_files && bytes <= state.config.max_project_bytes);
  if (!limitOk) $("#upload-stats").textContent += " · 超出限制";
  updateCreateAction(selected.length > 0 && limitOk);
}

function renderMaterials() {
  const wrap = $("#material-files"); wrap.replaceChildren();
  [["领域规约", state.domainFiles], ["设计意图", state.requirementFiles]].forEach(([type, files]) => files.forEach(file => {
    const chip = document.createElement("span"); chip.className = "material-chip";
    const kind = document.createElement("b"); kind.textContent = type; const name = document.createElement("span"); name.textContent = `${file.name} · ${formatBytes(file.size)}`;
    chip.append(kind, name); wrap.append(chip);
  }));
  updateUploadSummary();
}

function updateCreateAction(sourceReady = null) {
  $$(".material-limit-note", $("#material-files")).forEach(node => node.remove());
  const selected = state.uploadFiles.filter(item => state.selectedUploadPaths.has(item.path));
  if (sourceReady == null) {
    const bytes = selected.reduce((sum,item) => sum + item.file.size, 0);
    sourceReady = selected.length > 0 && (!state.config || (selected.length <= state.config.max_project_files && bytes <= state.config.max_project_bytes));
  }
  const requirementBytes = state.requirementFiles.reduce((sum,file) => sum + file.size, 0);
  const requirementReady = !state.config || (
    state.requirementFiles.length <= state.config.max_requirement_files
    && requirementBytes <= state.config.max_requirement_bytes
  );
  const domainBytes = state.domainFiles.reduce((sum, file) => sum + file.size, 0);
  const domainReady = !state.config || (
    state.domainFiles.length <= state.config.max_material_files
    && domainBytes <= state.config.max_material_bytes
  );
  const submit = $("#submit-task");
  submit.disabled = !sourceReady || !requirementReady || !domainReady;
  submit.textContent = "新建任务";
  if (!requirementReady) {
    const note = document.createElement("span"); note.className = "material-chip material-limit-note"; note.textContent = "需求文档数量或总大小超出限制"; $("#material-files").append(note);
  }
  if (!domainReady) {
    const note = document.createElement("span"); note.className = "material-chip material-limit-note"; note.textContent = "领域规约数量或总大小超出限制"; $("#material-files").append(note);
  }
}

async function createTask(event) {
  event.preventDefault(); const selected = state.uploadFiles.filter(item => state.selectedUploadPaths.has(item.path)); if (!selected.length) return;
  const form = new FormData(); form.append("name", $("#task-name-input").value.trim() || state.projectName); form.append("project_name", state.projectName);
  form.append("source_paths", JSON.stringify(selected.map(item => item.path)));
  selected.forEach(item => form.append("source_files", item.file, item.file.name));
  state.domainFiles.forEach(file => form.append("domain_files", file, file.name));
  state.requirementFiles.forEach(file => form.append("requirement_files", file, file.name));
  const submit = $("#submit-task"); submit.disabled = true; $("#upload-progress-wrap").classList.remove("hidden");
  try {
    const task = await uploadForm("/api/tasks", form, percent => {
      $("#upload-progress").style.width = `${percent}%`; $("#upload-progress-text").textContent = percent >= 100 ? "正在创建任务…" : `正在上传… ${percent}%`;
    });
    $("#create-dialog").close(); await loadTasks(); await selectTask(task.id);
    toast(state.requirementFiles.length ? "任务已创建，正在进行需求预处理"
      : state.domainFiles.length ? "任务已创建，正在整理领域规约" : "任务已创建，正在排队验证");
  } catch (error) {
    toast(error.message, "error"); submit.disabled = false;
  }
}

function setRequirementActionBusy(busy, message = "") {
  $("#requirement-regenerate").disabled = busy; $("#requirement-retry").disabled = busy; $("#requirement-confirm").disabled = busy;
  $("#requirement-category-content").disabled = busy;
  $("#requirement-view-preview").disabled = busy; $("#requirement-view-edit").disabled = busy;
  $("#requirement-new-files").disabled = busy;
  $$(".requirement-category-item", $("#requirement-category-list")).forEach(button => { button.disabled = busy; });
  const stateNode = $("#requirement-action-state"); stateNode.className = busy ? "loading" : ""; stateNode.textContent = message;
}

async function regenerateRequirements() {
  if (!state.selectedTask) return;
  const domain = isDomainReview(); const label = domain ? "领域规约" : "设计意图";
  if (["awaiting_confirmation", "awaiting_domain_confirmation"].includes(state.selectedTask.status) &&
      !confirm(`重新生成会覆盖当前尚未确认的${label}修改，是否继续？`)) return;
  setRequirementActionBusy(true, `正在重新提交${label}整理…`);
  try {
    const form = new FormData();
    state.newRequirementFiles.forEach(file => form.append(domain ? "domain_files" : "requirement_files", file, file.name));
    await api(`/api/tasks/${state.selectedTask.id}/${reviewRoute()}/regenerate`, { method: "POST", body: form });
    await loadTasks(); await selectTask(state.selectedTask.id); toast(`已重新开始生成${label}`);
  } catch (error) { toast(error.message, "error"); setRequirementActionBusy(false); }
}

async function confirmRequirements() {
  if (!state.selectedTask) return;
  const domain = isDomainReview(); const label = domain ? "领域规约" : "设计意图";
  const markdown = composeRequirementMarkdown().trim();
  if (!markdown) { toast(`${label}不能为空，请修改或重新生成`, "error"); return; }
  setRequirementActionBusy(true, `正在保存${label}…`);
  try {
    const result = await api(`/api/tasks/${state.selectedTask.id}/${reviewRoute()}/confirm`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ markdown }),
    });
    await loadTasks(); await selectTask(state.selectedTask.id);
    toast(result.status === "domain_preprocessing" ? "设计意图已确认，正在整理领域规约" : `${label}已确认，代码验证已开始`);
  } catch (error) { toast(error.message, "error"); setRequirementActionBusy(false); }
}

async function adjustDesignIntent() {
  if (!state.selectedTask) return;
  const active = ["queued", "running", "cancelling"].includes(state.selectedTask.status);
  const message = active
    ? "将停止当前验证，并保留已有问题、日志和报告；随后创建一条新的设计意图调整任务。是否继续？"
    : "将保留当前任务，并创建一条新的设计意图调整任务。确认后会重新执行完整验证。是否继续？";
  if (!confirm(message)) return;
  const button = $("#adjust-intent-button"); button.disabled = true; button.textContent = "正在准备…";
  try {
    const task = await api(`/api/tasks/${state.selectedTask.id}/requirements/revise`, { method: "POST" });
    await loadTasks(); await selectTask(task.id);
    toast(active ? "原验证正在停止，请调整设计意图后重新验证" : "已创建设计意图调整任务");
  } catch (error) {
    toast(error.message, "error"); button.disabled = false; button.textContent = "调整设计意图";
  }
}

function uploadForm(url, form, onProgress) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest(); request.open("POST", url); request.responseType = "json";
    request.upload.onprogress = event => { if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100)); };
    request.onload = () => request.status >= 200 && request.status < 300 ? resolve(request.response) : reject(new Error(request.response?.error || `上传失败（${request.status}）`));
    request.onerror = () => reject(new Error("上传连接失败")); request.send(form);
  });
}

async function endTask() {
  if (!state.selectedTask || !confirm("确定结束当前任务吗？已发现的问题、日志和中间结果都会保留。")) return;
  try { state.selectedTask = { ...state.selectedTask, ...await api(`/api/tasks/${state.selectedTask.id}/end`, { method: "POST" }) }; renderTaskHeader(); }
  catch (error) { toast(error.message, "error"); }
}
async function resumeTask() {
  try { state.selectedTask = { ...state.selectedTask, ...await api(`/api/tasks/${state.selectedTask.id}/resume`, { method: "POST" }) }; renderTaskHeader(); toast("任务已进入继续验证队列"); }
  catch (error) { toast(error.message, "error"); }
}
async function rerunTask() {
  try { const task = await api(`/api/tasks/${state.selectedTask.id}/rerun`, { method: "POST" }); await loadTasks(); await selectTask(task.id); toast("已基于原材料创建新的验证任务"); }
  catch (error) { toast(error.message, "error"); }
}
async function deleteTask() {
  if (!state.selectedTask || !confirm(`将永久删除“${state.selectedTask.name}”的服务器端源码副本、材料、日志和报告。此操作不可撤销，是否继续？`)) return;
  try {
    const id = state.selectedTask.id; await api(`/api/tasks/${id}`, { method: "DELETE" }); if (state.eventSource) state.eventSource.close();
    state.selectedTask = null; $("#task-view").classList.add("hidden"); $("#empty-state").classList.remove("hidden"); await loadTasks(); toast("任务数据已删除");
  } catch (error) { toast(error.message, "error"); }
}

async function openReports() {
  if (!state.selectedTask) return;
  try { state.selectedTask.reports = await api(`/api/tasks/${state.selectedTask.id}/reports`); } catch (error) { toast(error.message, "error"); return; }
  const options = [
    ["zh_html", "中文 HTML 报告", "适合直接在浏览器查看和归档", "zh-html"],
    ["zh_md", "中文 Markdown", "便于纳入工程文档或评审流程", "zh-md"],
    ["zh_json", "中文 JSON 数据", "便于后续接入软件工厂处理", "zh-json"],
    ["original_html", "原工具 HTML", "保留原工具生成的交互式报告", "original-html"],
  ];
  const wrap = $("#report-options"); wrap.replaceChildren(); options.forEach(([key,title,copy,kind]) => {
    const card = document.createElement("div"); card.className = `report-option ${state.selectedTask.reports[key] ? "" : "unavailable"}`;
    const strong = document.createElement("strong"); strong.textContent = title; const p = document.createElement("p"); p.textContent = state.selectedTask.reports[key] ? copy : "报告尚未生成";
    const link = document.createElement("a"); const browserPreview = kind.endsWith("html");
    link.textContent = browserPreview ? "浏览器查看 →" : "下载报告 →";
    link.href = `/api/tasks/${state.selectedTask.id}/download?kind=${kind}${browserPreview ? "&preview=1" : ""}`;
    if (browserPreview) link.target = "_blank"; card.append(strong,p,link); wrap.append(card);
  }); $("#report-dialog").showModal();
}

boot();
