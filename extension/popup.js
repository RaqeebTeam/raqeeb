const API = "http://127.0.0.1:8000";
chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
  document.getElementById("url").textContent = tab.url;
  const out = document.getElementById("out");
  try {
    const r = await fetch(`${API}/api/check?url=${encodeURIComponent(tab.url)}`);
    const d = await r.json();
    out.innerHTML = `<span class="badge ${d.color}">${d.label}</span> <b>Risk ${d.score}/100</b><ul>` +
      d.reasons.map(t => `<li>${t.replace(/</g, "&lt;")}</li>`).join("") + "</ul>";
  } catch (e) {
    out.textContent = "Server not running. Start it with: uvicorn app:app";
  }
});
