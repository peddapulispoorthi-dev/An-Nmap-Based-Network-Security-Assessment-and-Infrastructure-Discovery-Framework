(() => {
  const svg = document.getElementById("topology");
  const source = document.getElementById("topology-data");
  if (!svg || !source) return;
  const graph = JSON.parse(source.textContent);
  const ns = "http://www.w3.org/2000/svg";
  const width = Math.max(svg.clientWidth, 320);
  const height = 180;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const positions = new Map();
  graph.nodes.forEach((node, index) => {
    positions.set(node.id, { x: 30 + (index + 1) * (width - 60) / (graph.nodes.length + 1), y: height / 2 });
  });
  const add = (name, attrs, text) => {
    const element = document.createElementNS(ns, name);
    Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, value));
    if (text) element.textContent = text;
    svg.appendChild(element);
  };
  graph.links.forEach(link => {
    const from = positions.get(link.source);
    const to = positions.get(link.target);
    if (from && to) add("line", { x1: from.x, y1: from.y, x2: to.x, y2: to.y, stroke: "#8193aa", "stroke-width": 2 });
  });
  graph.nodes.forEach(node => {
    const point = positions.get(node.id);
    add("circle", { cx: point.x, cy: point.y, r: 9, fill: node.kind === "host" ? "#1558a6" : "#5c9c73" });
    add("text", { x: point.x, y: point.y + 28, "text-anchor": "middle", class: "node-label" }, node.label);
  });
})();
