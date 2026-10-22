const UNTRACKED = new Set(["signature.json", "certificate.html", "attestation.json"]);

async function sha256Hex(buffer) {
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function relName(file) {
  const name = file.webkitRelativePath || file.name;
  const parts = name.split(/[/\\]/);
  return parts[parts.length - 1] === "manifest.json" || !name.includes("/")
    ? file.name.split(/[/\\]/).pop()
    : name.replace(/^[^/]+\\/, "").replace(/^[^/]+\//, "");
}

async function hashLocal() {
  const input = document.getElementById("files");
  const out = document.getElementById("out");
  const files = [...(input.files || [])];
  if (!files.length) {
    out.textContent = "Select the files from a sealed pack (at least manifest.json).";
    return;
  }
  const byName = {};
  for (const file of files) {
    byName[relName(file)] = file;
  }
  const manifestFile = Object.values(byName).find((f) => f.name === "manifest.json" || relName(f) === "manifest.json");
  if (!manifestFile) {
    out.textContent = "manifest.json is required.";
    return;
  }
  const manifest = JSON.parse(await manifestFile.text());
  const expected = manifest.files || {};
  const missing = [];
  const changed = [];
  for (const [rel, meta] of Object.entries(expected)) {
    const file = byName[rel] || byName[rel.split("/").pop()];
    if (!file) {
      missing.push(rel);
      continue;
    }
    const digest = await sha256Hex(await file.arrayBuffer());
    if (digest !== meta.sha256) changed.push(rel);
  }
  const extra = Object.keys(byName).filter((n) => n !== "manifest.json" && !expected[n] && !UNTRACKED.has(n.split(/[/\\]/).pop()));
  const ok = !missing.length && !changed.length;
  out.textContent = JSON.stringify(
    {
      ok,
      issuer: "New Chisel Independent Evidence — not issued by a model vendor",
      sealed_at: manifest.sealed_at,
      aisec_version: manifest.aisec_version,
      missing,
      changed,
      extra,
    },
    null,
    2
  );
}

async function uploadTar() {
  const input = document.getElementById("tarball");
  const out = document.getElementById("out");
  if (!input.files || !input.files[0]) {
    out.textContent = "Choose a .tar.gz of a sealed pack.";
    return;
  }
  const body = new FormData();
  body.set("pack", input.files[0], input.files[0].name);
  const res = await fetch("/v1/public/verify", { method: "POST", body });
  const text = await res.text();
  out.textContent = text;
}

document.getElementById("hash-files").onclick = () => hashLocal().catch((e) => {
  document.getElementById("out").textContent = String(e);
});
document.getElementById("upload").onclick = () => uploadTar().catch((e) => {
  document.getElementById("out").textContent = String(e);
});
