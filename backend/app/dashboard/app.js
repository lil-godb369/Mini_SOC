"use strict";
const $ = (id) => document.getElementById(id);
const labels = {new: "Mới", triaged: "Đang điều tra", closed: "Đã xử lý"};
const sources = {rule: "Rule engine", ransomware: "Ransomware", ml_network: "ML network"};
const state = {token: null, offset: 0, limit: 20, total: 0, filters: {}, selected: null, generation: 0, loading: false};
const number = (n) => new Intl.NumberFormat("vi-VN").format(n);
const time = (value) => { const d = new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : value + "Z"); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("vi-VN"); };
function node(tag, text, className) { const n = document.createElement(tag); n.textContent = text ?? "—"; if (className) n.className = className; return n; }
function message(id, text) { $(id).textContent = text; $(id).hidden = !text; }
function logout(reason = "") {
  state.token = null; state.generation++; state.selected = null;
  if ($("detail").open) $("detail").close();
  $("password").value = ""; $("app-view").hidden = true; $("login-view").hidden = false;
  message("login-error", reason);
}
async function api(path, options = {}) {
  const response = await fetch("/api/v1" + path, {...options, headers: {"Content-Type":"application/json", ...(state.token ? {Authorization: "Bearer " + state.token} : {}), ...options.headers}, signal: options.signal ?? AbortSignal.timeout(12000)});
  if (response.status === 401 && path !== "/auth/login") { logout("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại."); throw new Error("Phiên đăng nhập đã hết hạn."); }
  if (!response.ok) { let body; try { body = await response.json(); } catch {} throw new Error(typeof body?.detail === "string" ? body.detail : "Không thể thực hiện yêu cầu (HTTP " + response.status + ")."); }
  return response.json();
}
function badge(text, kind) { return node("span", text, "badge " + (/^(critical|high|medium|low|new|triaged|closed)$/.test(kind) ? kind : "")); }
function renderRows(items) {
  $("alert-rows").replaceChildren();
  for (const a of items) {
    const tr = document.createElement("tr");
    const cell = (child) => { const td = document.createElement("td"); td.append(child); tr.append(td); return td; };
    cell(badge(a.severity.toUpperCase(), a.severity));
    const title = cell(node("strong", a.title)); title.append(node("small", "#" + a.id + " · " + (a.technique || "Chưa ánh xạ MITRE")));
    cell(node("span", a.host)); cell(node("span", sources[a.source] || a.source));
    cell(badge(labels[a.status] || a.status, a.status)); cell(node("span", time(a.ts)));
    const b = node("button", "Chi tiết →"); b.setAttribute("aria-label", "Xem cảnh báo #" + a.id); b.addEventListener("click", () => openDetail(a.id)); cell(b);
    $("alert-rows").append(tr);
  }
  $("empty").hidden = items.length !== 0;
  $("page-info").textContent = state.total ? `${number(state.offset + 1)}–${number(state.offset + items.length)} / ${number(state.total)} cảnh báo` : "0 cảnh báo";
  $("previous").disabled = state.offset === 0; $("next").disabled = state.offset + state.limit >= state.total;
}
async function loadAlerts() {
  const version = ++state.generation;
  state.loading = true; $("refresh").disabled = true; message("notice", "Đang tải cảnh báo…");
  message("page-error", "");
  try {
    const params = new URLSearchParams({...state.filters, limit: state.limit, offset: state.offset});
    const page = await api("/alerts?" + params);
    if (!state.token || version !== state.generation) return;
    if (page.total && state.offset >= page.total) { state.offset = Math.floor((page.total - 1) / state.limit) * state.limit; return await loadAlerts(); }
    state.total = page.total; renderRows(page.items);
    $("updated").textContent = "Cập nhật lúc " + new Date().toLocaleTimeString("vi-VN") + " · Số liệu tổng quan không phụ thuộc bộ lọc";
  } catch (err) { if (state.token && version === state.generation) message("page-error", "Không tải được danh sách. " + err.message); }
  finally { if (version === state.generation) {state.loading = false; $("refresh").disabled = false; message("notice", "");} }
}
async function loadOverview() {
  const token = state.token;
  try {
    const stats = await api("/stats/overview?hours=24"); if (!state.token || state.token !== token) return;
    for (const [id,key] of [["events","total_events"],["alerts","total_alerts"],["open","open_alerts"],["agents","agents_online"]]) $("metric-" + id).textContent = number(stats[key]);
  } catch { if (state.token === token) for (const id of ["events","alerts","open","agents"]) $("metric-" + id).textContent = "—"; }
}
async function loadHosts() {
  const token = state.token;
  try { const agents = await api("/agents"); if (state.token !== token) return; $("host-list").replaceChildren(...[...new Set(agents.map(a => a.hostname))].sort().map(host => {const option = document.createElement("option"); option.value = host; return option;})); } catch { /* Free-text host filtering remains available. */ }
}
async function refresh() { await Promise.all([loadAlerts(), loadOverview()]); }
async function openDetail(id) {
  state.selected = id; $("detail-title").textContent = "Đang tải cảnh báo…"; $("detail-id").textContent = "#" + id;
  $("detail-meta").replaceChildren(); $("evidence").textContent = ""; message("detail-message", ""); $("status-form").hidden = true;
  if (!$("detail").open) $("detail").showModal();
  try {
    const a = await api("/alerts/" + id); if (state.selected !== id || !$("detail").open) return;
    $("detail-title").textContent = a.title;
    for (const [label, value] of [["Mức độ",a.severity.toUpperCase()],["Máy",a.host],["Thời gian",time(a.ts)],["Nguồn",sources[a.source] || a.source],["MITRE ATT&CK",[a.technique,a.technique_name].filter(Boolean).join(" · ") || "—"],["Rule",a.rule_id || "—"]]) {const div = document.createElement("div"); div.append(node("span",label),document.createTextNode(value)); $("detail-meta").append(div);}
    $("detail-status").value = a.status; $("evidence").textContent = JSON.stringify(a.evidence, null, 2);
    $("status-form").hidden = false;
  } catch (err) { if (state.selected === id) {$("detail-title").textContent = "Không tải được cảnh báo"; message("detail-message",err.message);} }
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("login-button").disabled = true; message("login-error", "");
  try {
    const token = await api("/auth/login", {method:"POST", body:JSON.stringify({email:$("email").value.trim(),password:$("password").value})});
    state.token = token.access_token; state.offset = 0; state.filters = {}; $("filters").reset(); $("password").value = "";
    $("user-email").textContent = $("email").value.trim(); $("login-view").hidden = true; $("app-view").hidden = false;
    $("alert-rows").replaceChildren(); $("empty").hidden = true; $("page-info").textContent = "Đang tải…";
    await Promise.all([refresh(),loadHosts()]);
  } catch (err) { message("login-error", err.message); } finally { $("login-button").disabled = false; }
});
$("logout").addEventListener("click", () => logout());
$("filters").addEventListener("submit", (event) => {event.preventDefault(); state.filters = Object.fromEntries([...new FormData(event.target)].map(([k,v])=>[k,v.trim()]).filter(([,v])=>v)); state.offset=0; loadAlerts();});
$("reset-filters").addEventListener("click",()=>{$("filters").reset();state.filters={};state.offset=0;loadAlerts();});
$("refresh").addEventListener("click", refresh);
$("previous").addEventListener("click",()=>{state.offset=Math.max(0,state.offset-state.limit);loadAlerts();});
$("next").addEventListener("click",()=>{state.offset+=state.limit;loadAlerts();});
$("close-detail").addEventListener("click",()=>$("detail").close());
$("detail").addEventListener("close",()=>{state.selected=null;});
$("status-form").addEventListener("submit",async(event)=>{
  event.preventDefault();const id=state.selected; $("save-status").disabled=true;message("detail-message", "Đang lưu…");
  try {const a=await api("/alerts/"+id+"/status",{method:"PATCH",body:JSON.stringify({status:$("detail-status").value})}); if(state.selected===id){$("detail-status").value=a.status;message("detail-message","Đã lưu: "+labels[a.status]+".");} if(state.token) await refresh();}
  catch(err){if(state.selected===id) message("detail-message","Lưu thất bại. "+err.message);}
  finally{$("save-status").disabled=false;}
});
setInterval(()=>{if(state.token && $("auto-refresh").checked && !document.hidden && !state.loading && !$("detail").open) refresh();},15000);
