/* Network Traffic Security - live dashboard client */
const $ = (id) => document.getElementById(id);
const COLORS = { cyan:"#22d3ee", blue:"#3b82f6", green:"#22c55e",
                 red:"#ef4444", orange:"#f59e0b", muted:"#8b98ab" };
Chart.defaults.color = "#8b98ab";
Chart.defaults.borderColor = "#1f2b3d";

let sevFilter = "all";
const base = { responsive:true, maintainAspectRatio:true, plugins:{ legend:{ labels:{ boxWidth:12 } } } };

const chTimeline = new Chart($("chTimeline"), { type:"line", data:{ labels:[], datasets:[
  { label:"bytes/min", data:[], borderColor:COLORS.cyan, backgroundColor:"rgba(34,211,238,.12)",
    fill:true, tension:.35, pointRadius:0 } ] }, options:{ ...base, scales:{ y:{ beginAtZero:true } } } });

const chProto = new Chart($("chProto"), { type:"doughnut", data:{ labels:[], datasets:[
  { data:[], backgroundColor:[COLORS.cyan,COLORS.blue,COLORS.green,COLORS.orange,COLORS.red,COLORS.muted],
    borderWidth:1, borderColor:"#111827" } ] },
  options:{ ...base, cutout:"62%" } });

const chTalkers = new Chart($("chTalkers"), { type:"bar", data:{ labels:[], datasets:[
  { data:[], backgroundColor:COLORS.blue, borderRadius:4 } ] },
  options:{ ...base, indexAxis:"y", scales:{ x:{ beginAtZero:true } } } });

const chSeverity = new Chart($("chSeverity"), { type:"bar", data:{ labels:["Low","Medium","High","Critical"],
  datasets:[{ data:[0,0,0,0], backgroundColor:[COLORS.blue,COLORS.orange,COLORS.red,"#9f1239"],
    borderRadius:4 } ] }, options:{ ...base, scales:{ y:{ beginAtZero:true, ticks:{ precision:0 } } } } });

/* ---- helpers ---- */
function fmtBytes(b){ const u=["B","KB","MB","GB"]; let i=0;
  while(b>=1024 && i<u.length-1){ b/=1024; i++; } return b.toFixed(1)+" "+u[i]; }
function fmtTime(t){ return new Date(t*1000).toLocaleTimeString(); }

/* ---- controls ---- */
$("btnStart").onclick = async () => {
  const body = { mode: $("mode").value, interface: $("iface").value || null };
  await fetch("/api/start", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
  refresh();
};
$("btnStop").onclick = async () => { await fetch("/api/stop",{method:"POST"}); refresh(); };

$("sevFilter").addEventListener("click", (e) => {
  if (e.target.tagName !== "BUTTON") return;
  document.querySelectorAll("#sevFilter button").forEach(b => b.classList.remove("active"));
  e.target.classList.add("active");
  sevFilter = e.target.dataset.s;
  renderAlerts(lastData);
});

async function blockIP(ip){ await fetch("/api/block",{method:"POST",
  headers:{"Content-Type":"application/json"}, body:JSON.stringify({ip})}); refresh(); }
async function unblockIP(ip){ await fetch("/api/unblock/"+ip,{method:"DELETE"}); refresh(); }

/* ---- renderers ---- */
let lastData = null;

function renderAlerts(d){
  const tb = document.querySelector("#alertsTable tbody"); tb.innerHTML = "";
  if(!d) return;
  for(const a of d.alerts){
    if(sevFilter !== "all" && a.severity !== sevFilter) continue;
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${fmtTime(a.ts)}</td>
      <td><span class="badge b-${a.severity}">${a.severity}</span></td>
      <td>${a.rule}</td><td>${a.src}</td><td>${a.dst}</td>
      <td style="white-space:normal;max-width:280px">${a.detail}</td>
      <td style="white-space:normal;max-width:280px;color:var(--muted)">${a.recommendation}</td>
      <td><button class="blockbtn" onclick="blockIP('${a.src}')">Block</button></td>`;
    tb.appendChild(tr);
  }
}

function renderConns(d){
  const tb = document.querySelector("#connTable tbody"); tb.innerHTML = "";
  if(!d) return;
  for(const c of d.connections){
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${fmtTime(c.ts)}</td><td>${c.src}</td><td>${c.dst}</td>
      <td>${c.proto}</td><td>${c.dport ?? "-"}</td><td>${c.length}</td>
      <td>${c.blocked ? '<span class="badge b-blocked">BLOCKED</span>'
                      : '<span class="badge b-ok">OK</span>'}</td>`;
    tb.appendChild(tr);
  }
}

function renderBlocked(d){
  const ul = $("blockedList"); ul.innerHTML = "";
  if(!d || !d.blocked.length){ ul.innerHTML = '<li class="empty">No blocked IPs</li>'; return; }
  for(const b of d.blocked){
    const li = document.createElement("li");
    li.innerHTML = `<div><span class="ip">${b.ip}</span>
      <span class="reason">${b.reason}</span></div>
      <button class="unblockbtn" onclick="unblockIP('${b.ip}')">Unblock</button>`;
    ul.appendChild(li);
  }
}

function refresh(){
  fetch("/api/overview").then(r => r.json()).then(d => {
    lastData = d;
    const t = d.totals;
    $("cPackets").textContent = t.packets.toLocaleString();
    $("cBytes").textContent = fmtBytes(t.bytes);
    $("cAlerts").textContent = t.alerts;
    $("cBlocked").textContent = t.blocked;
    $("cStatus").textContent = d.running ? "RUNNING" : "Stopped";
    $("cStatus").className = "value " + (d.running ? "green" : "red");
    $("cMode").textContent = d.running ? ("mode: " + d.mode) : "";
    $("btnStart").disabled = d.running; $("btnStop").disabled = !d.running;

    chTimeline.data.labels = d.timeline.map(x => fmtTime(x.t));
    chTimeline.data.datasets[0].data = d.timeline.map(x => x.bytes);
    chTimeline.update("none");

    chProto.data.labels = d.protocols.map(x => x.proto);
    chProto.data.datasets[0].data = d.protocols.map(x => x.n);
    chProto.update("none");

    chTalkers.data.labels = d.top_talkers.map(x => x.ip);
    chTalkers.data.datasets[0].data = d.top_talkers.map(x => x.bytes);
    chTalkers.update("none");

    const sev = Object.fromEntries(d.alerts_by_severity.map(x => [x.severity, x.n]));
    chSeverity.data.datasets[0].data =
      ["Low","Medium","High","Critical"].map(s => sev[s] || 0);
    chSeverity.update("none");

    renderAlerts(d); renderConns(d); renderBlocked(d);
  });
}
refresh();
setInterval(refresh, 2000);
