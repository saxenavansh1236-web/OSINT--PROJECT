// graph.js — OSINT Investigation Graph

const TYPE_CFG = {
  target:    { color: "#00ff88", r: 18 },
  ip:        { color: "#4488ff", r: 12 },
  geo:       { color: "#00ccff", r: 10 },
  subdomain: { color: "#ffaa00", r: 10 },
  username:  { color: "#cc44ff", r: 10 },
  breach:    { color: "#ff3c3c", r: 10 },
  threat:    { color: "#ff6b35", r: 10 },
  dns_ns:    { color: "#00e5ff", r:  9 },
  dns_mx:    { color: "#40c4ff", r:  9 },
  tech:      { color: "#69ff47", r:  9 },
  ssl:       { color: "#ffd740", r:  9 },
  default:   { color: "#888888", r:  9 },
};

function getColor(type) { return (TYPE_CFG[type] || TYPE_CFG.default).color; }
function getRadius(type){ return (TYPE_CFG[type] || TYPE_CFG.default).r; }

// ── Parse a raw BreachResult(...) string into a plain object ──────────────
function parseBreachString(raw) {
  const s = String(raw);
  function extract(key) {
    const m = s.match(new RegExp(key + "='([^']*)'"));
    return m ? m[1] : null;
  }
  function extractInt(key) {
    const m = s.match(new RegExp(key + "=(\\d+)"));
    return m ? parseInt(m[1], 10) : 0;
  }
  return {
    name:     extract("name") || "Unknown breach",
    source:   extract("source") || "?",
    date:     extract("date") || "",
    severity: extract("severity") || "high",
    records:  extractInt("records"),
  };
}

function makeLabel(id, type) {
  if (!id) return "?";
  const dictMatch = String(id).match(/['"](name|id)['"]\s*:\s*['"]([^'"]+)['"]/);
  if (dictMatch) return dictMatch[2];

  const s = String(id)
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "");
  if (type === "username")  return "@" + (s.length > 18 ? s.slice(0,16)+"…" : s);
  if (type === "breach")    return s.length > 22 ? s.slice(0,20)+"…" : s;
  if (type === "threat")    return s.replace(/^⚠\s*/,"").slice(0,22);
  if (type === "subdomain") return s.length > 24 ? s.slice(0,22)+"…" : s;
  if (type === "dns_ns" || type === "dns_mx") return s.split(".")[0];
  return s.length > 28 ? s.slice(0,26)+"…" : s;
}

function drawGraph(data) {
  const graphCard = document.querySelector(".graph-card");
  const svgEl     = document.getElementById("graph");
  if (!svgEl) return;

  if (!data.nodes || data.nodes.length === 0) {
    if (graphCard) graphCard.style.display = "none";
    return;
  }

  if (graphCard) graphCard.style.display = "block";

  const svg    = d3.select(svgEl);
  svg.selectAll("*").remove();

  const width  = svgEl.parentElement.clientWidth || 1000;
  const height = 520;

  svg.attr("viewBox", `0 0 ${width} ${height}`)
     .attr("width",  width)
     .attr("height", height);

  const container = svg.append("g");
  svg.call(
    d3.zoom().scaleExtent([0.25, 3])
      .on("zoom", (e) => container.attr("transform", e.transform))
  );

  svg.append("defs").append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -4 8 8")
    .attr("refX", 20).attr("refY", 0)
    .attr("markerWidth", 6).attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", "#333");

  const simulation = d3.forceSimulation(data.nodes)
    .force("link", d3.forceLink(data.links).id(d => d.id).distance(130).strength(0.6))
    .force("charge", d3.forceManyBody().strength(-350))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(d => getRadius(d.type) + 26).strength(0.9))
    .force("x", d3.forceX(width  / 2).strength(0.04))
    .force("y", d3.forceY(height / 2).strength(0.04));

  const link = container.selectAll("line")
    .data(data.links).enter().append("line")
    .attr("stroke", "#1e3a1e")
    .attr("stroke-width", 1.2)
    .attr("stroke-opacity", 0.7)
    .attr("marker-end", "url(#arrow)");

  const node = container.selectAll("g.node")
    .data(data.nodes).enter().append("g")
    .attr("class", "node")
    .style("cursor", "pointer")
    .call(d3.drag()
      .on("start", (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag",  (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on("end",   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    );

  node.filter(d => d.type === "target")
    .append("circle").attr("r", 26).attr("fill","none")
    .attr("stroke","#00ff88").attr("stroke-width",1.5).attr("stroke-opacity",0.25);

  node.append("circle")
    .attr("r",      d => getRadius(d.type))
    .attr("fill",   d => getColor(d.type))
    .attr("stroke", "#0a0a0f").attr("stroke-width", 1.5);

  node.append("text")
    .text(d => makeLabel(d.id, d.type))
    .attr("text-anchor", "middle")
    .attr("dy", d => getRadius(d.type) + 13)
    .attr("fill", d => getColor(d.type))
    .attr("font-size", 9)
    .attr("font-family", "Courier New, monospace")
    .attr("pointer-events", "none");

  let tip = document.getElementById("osint-tip");
  if (!tip) {
    tip = document.createElement("div");
    tip.id = "osint-tip";
    tip.style.cssText =
      "position:fixed;background:#0f0f1a;border:1px solid #1a3a1a;color:#ccc;" +
      "font-family:'Courier New',monospace;font-size:11px;padding:8px 12px;" +
      "border-radius:6px;pointer-events:none;display:none;z-index:9999;" +
      "max-width:260px;line-height:1.6;box-shadow:0 4px 20px rgba(0,0,0,.7);";
    document.body.appendChild(tip);
  }

  node
    .on("mouseover", (e, d) => {
      tip.innerHTML =
        `<div style="color:${getColor(d.type)};font-size:10px;letter-spacing:1px;margin-bottom:3px">${(d.type||"node").toUpperCase()}</div>` +
        `<div style="word-break:break-all">${String(d.id).replace(/^https?:\/\//,"")}</div>`;
      tip.style.display = "block";
    })
    .on("mousemove", (e) => { tip.style.left=(e.clientX+14)+"px"; tip.style.top=(e.clientY-10)+"px"; })
    .on("mouseout",  ()  => { tip.style.display="none"; })
    .on("click",     (e,d) => { const u=String(d.id); if(u.startsWith("http")) window.open(u,"_blank","noopener"); });

  simulation.on("tick", () => {
    data.nodes.forEach(d => {
      const r = getRadius(d.type) + 2;
      d.x = Math.max(r, Math.min(width  - r, d.x));
      d.y = Math.max(r, Math.min(height - r, d.y));
    });
    link
      .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });
}

// ── FIX: normalise breach nodes whose id is a raw BreachResult string ──────
function normaliseGraphData(data) {
  if (!data || !data.nodes) return data;
  data.nodes = data.nodes.map(n => {
    if (n.type === "breach" && typeof n.id === "string" && n.id.startsWith("BreachResult(")) {
      const parsed = parseBreachString(n.id);
      return { ...n, id: parsed.name, _meta: parsed };
    }
    return n;
  });
  // Also fix link references that pointed to the old raw string id
  // (only needed if your backend uses the raw string as the link source/target)
  return data;
}

async function loadGraph() {
  try {
    // ── FIX: read the target shown on the page and send it to /graph ─────────
    // This ensures we always get the graph for the CURRENT scan, not a cached one.
    const targetEl = document.querySelector(".target-value");
    const target   = targetEl ? targetEl.textContent.trim() : "";
    const url      = target
      ? `/graph?target=${encodeURIComponent(target)}&_=${Date.now()}`
      : `/graph?_=${Date.now()}`;                 // cache-bust even without target

    const res = await fetch(url);

    // ── Guard against non-JSON responses (404, 500, HTML error pages) ────────
    const contentType = res.headers.get("content-type") || "";
    if (!res.ok || !contentType.includes("application/json")) {
      throw new Error(`Graph endpoint returned ${res.status} ${res.statusText}`);
    }

    const raw  = await res.json();

    // ── Extra safety: if the returned target doesn't match, bail out ──────────
    if (target && raw.target && raw.target !== target) {
      console.warn(`Graph target mismatch: expected "${target}", got "${raw.target}". Hiding graph.`);
      const card = document.querySelector(".graph-card");
      if (card) card.style.display = "none";
      return;
    }

    const data = normaliseGraphData(raw);
    drawGraph(data);
  } catch(err) {
    console.warn("Graph load failed:", err);
    const card = document.querySelector(".graph-card");
    if (card) card.style.display = "none";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("graph")) {
    loadGraph();
  }
});