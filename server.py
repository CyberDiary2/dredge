from flask import Flask, request, jsonify, Response, render_template_string
import json
import os
import subprocess
import sys
import threading
from bson.regex import Regex
import re
from pymongo import MongoClient
from functools import wraps

DASHBOARD_USER = "drew"
DASHBOARD_PASS = "dredge2026"

app = Flask(__name__)
mongo_uri = "mongodb://localhost:27017/"
client = MongoClient(mongo_uri)
db = client["scannerdb"]
collection = db["sslchecker"]
umbrella = db["umbrella"]
stab_col = db["stab_results"]


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != DASHBOARD_USER or auth.password != DASHBOARD_PASS:
            return Response(
                "authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="DREDGE"'}
            )
        return f(*args, **kwargs)
    return decorated


def get_umbrella_rank(domain):
    if not domain:
        return None
    d = domain.lstrip("*.").lower()
    result = umbrella.find_one({"domain": d}, {"rank": 1, "_id": 0})
    return result["rank"] if result else None


def get_takeover(domain):
    if not domain:
        return None
    d = domain.lstrip("*.").lower()
    result = stab_col.find_one({"subdomain": d}, {"type": 1, "service": 1, "_id": 0})
    return result if result else None


def enrich_with_rank(docs):
    for doc in docs:
        domain = None
        for section in ["https_responseForDomainName", "http_responseForDomainName", "https_responseForIP", "http_responseForIP"]:
            s = doc.get(section)
            if not s:
                continue
            items = s if isinstance(s, list) else [s]
            for item in items:
                if item.get("domain"):
                    domain = item["domain"]
                    break
            if domain:
                break
        doc["umbrella_rank"] = get_umbrella_rank(domain)
        doc["takeover"] = get_takeover(domain)
    return docs

try:
    print("MongoDB connection successful")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")

_import_lock = threading.Lock()
_import_status = {"running": False, "last_result": None, "error": None}
_stab_status = {"running": False, "last_result": None, "error": None}


@app.errorhandler(Exception)
def handle_database_error(e):
    return "An error occurred while connecting to the database.", 500


DASHBOARD = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DREDGE</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #1e2326; color: #d3c6aa; font-family: 'Courier New', monospace; }
    header { background: #2d3b2d; padding: 18px 32px; border-bottom: 2px solid #4a7c59; }
    header h1 { color: #83c092; font-size: 1.4rem; letter-spacing: 2px; }
    header span { color: #7fbbb3; font-size: 0.85rem; margin-left: 16px; }
    .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

    .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
    .stat-card { background: #272e33; border: 1px solid #3d5a48; border-radius: 6px; padding: 14px 20px; min-width: 140px; }
    .stat-card .label { font-size: 0.75rem; color: #7fbbb3; text-transform: uppercase; letter-spacing: 1px; }
    .stat-card .value { font-size: 1.6rem; color: #83c092; font-weight: bold; margin-top: 4px; }

    .search-bar { background: #272e33; border: 1px solid #3d5a48; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; }
    .search-bar h2 { color: #83c092; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; }
    .fields { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
    .field { display: flex; flex-direction: column; gap: 5px; }
    .field label { font-size: 0.75rem; color: #7fbbb3; text-transform: uppercase; letter-spacing: 1px; }
    .field input { background: #1e2326; border: 1px solid #4a7c59; color: #d3c6aa; padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 0.9rem; width: 200px; }
    .field input:focus { outline: none; border-color: #83c092; }
    .field input::placeholder { color: #5c6a72; }
    .btn { background: #4a7c59; color: #d3c6aa; border: none; padding: 9px 20px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 0.9rem; }
    .btn:hover { background: #83c092; color: #1e2326; }
    .btn-danger { background: #4c3743; border: 1px solid #c03060; color: #e67e80; margin-left: auto; }
    .btn-danger:hover { background: #c03060; color: #fff; }

    .results-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .results-header h2 { color: #83c092; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
    .count { color: #7fbbb3; font-size: 0.85rem; }

    table { width: 100%; border-collapse: collapse; background: #272e33; border-radius: 8px; overflow: hidden; font-size: 0.85rem; }
    th { background: #2d3b2d; color: #83c092; text-align: left; padding: 10px 14px; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid #3d5a48; }
    td { padding: 9px 14px; border-bottom: 1px solid #2d3437; color: #d3c6aa; word-break: break-all; max-width: 300px; }
    tr:hover td { background: #2d3b2d; }
    td.domain { color: #83c092; }
    td.ip { color: #7fbbb3; }
    td.port { color: #dbbc7f; }
    td.title { color: #e69875; }
    .tag { display: inline-block; background: #3d5a48; color: #83c092; padding: 1px 7px; border-radius: 3px; font-size: 0.75rem; margin: 1px; }
    .tag.http { background: #3a3d2e; color: #dbbc7f; }
    .tag.https { background: #2d3b2d; color: #83c092; }
    .empty { text-align: center; padding: 48px; color: #5c6a72; }
    .loading { text-align: center; padding: 32px; color: #7fbbb3; }
    .error { color: #e67e80; padding: 12px; background: #4c3743; border-radius: 4px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <header>
    <h1>DREDGE</h1>
    <span>Drew's Reconnaissance and Enumeration Dashboard for Ghost Endpoints</span>
  </header>
  <div class="container">

    <div class="stats" id="stats">
      <div class="stat-card"><div class="label">total records</div><div class="value" id="stat-total">-</div></div>
      <div class="stat-card"><div class="label">unique domains</div><div class="value" id="stat-domains">-</div></div>
      <div class="stat-card"><div class="label">unique IPs</div><div class="value" id="stat-ips">-</div></div>
      <div class="stat-card"><div class="label">umbrella domains</div><div class="value" id="stat-umbrella">-</div></div>
      <div class="stat-card" style="border-color: #4a7c59;"><div class="label" style="color: #83c092;">in scope</div><div class="value" id="stat-inscope" style="color: #83c092;">-</div></div>
      <div class="stat-card" style="border-color: #c03060;"><div class="label" style="color: #e67e80;">takeover candidates</div><div class="value" id="stat-takeovers" style="color: #e67e80;">-</div></div>
    </div>

    <div class="search-bar">
      <h2>search</h2>
      <div class="fields">
        <div class="field">
          <label>domain</label>
          <input type="text" id="f-domain" placeholder="t-mobile.com">
        </div>
        <div class="field">
          <label>IP address</label>
          <input type="text" id="f-ip" placeholder="172.56.248.1">
        </div>
        <div class="field">
          <label>port</label>
          <input type="text" id="f-port" placeholder="443">
        </div>
        <div class="field">
          <label>page title</label>
          <input type="text" id="f-title" placeholder="login">
        </div>
        <div class="field">
          <label>page content</label>
          <input type="text" id="f-html" placeholder="admin panel">
        </div>
        <div class="field">
          <label>response header</label>
          <input type="text" id="f-header" placeholder="X-Powered-By">
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" onclick="runSearch()">search</button>
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" onclick="loadAll()">show all</button>
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" style="background: #2d4a35; border: 1px solid #4a7c59; color: #83c092;" onclick="loadInScope()">in scope only</button>
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" id="btn-run-stab" style="background: #3a2e2e; border: 1px solid #e67e80; color: #e67e80;" onclick="runStab()">run stab</button>
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" id="btn-import-scopes" style="background: #3a3d2e; border: 1px solid #7fbbb3; color: #7fbbb3;" onclick="importScopes()">import scopes</button>
        </div>
        <div class="field" style="justify-content: flex-end; margin-left: auto;">
          <button class="btn btn-danger" onclick="confirmDelete()">clear db</button>
        </div>
      </div>
    </div>

    <div class="search-bar" style="border-color: #4a6c7c;">
      <h2 style="color: #7fbbb3;">umbrella top 1M lookup</h2>
      <div class="fields">
        <div class="field">
          <label style="color: #7fbbb3;">domain search</label>
          <input type="text" id="u-domain" placeholder="t-mobile.com" style="border-color: #4a6c7c;">
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" style="background: #3a5a6c;" onclick="umbrellaSearch()">lookup</button>
        </div>
      </div>
      <div id="umbrella-results" style="margin-top: 14px; display: none;">
        <table>
          <thead><tr><th>rank</th><th>domain</th></tr></thead>
          <tbody id="umbrella-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="search-bar" style="border-color: #c03060;">
      <h2 style="color: #e67e80;">takeover candidates</h2>
      <div class="fields">
        <div class="field">
          <label style="color: #e67e80;">filter by domain</label>
          <input type="text" id="t-filter" placeholder="t-mobile.com" style="border-color: #c03060;">
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" style="background: #4c3743; color: #e67e80; border: 1px solid #c03060;" onclick="loadTakeovers(false)">show all</button>
        </div>
        <div class="field" style="justify-content: flex-end;">
          <button class="btn" style="background: #2d4a35; color: #83c092; border: 1px solid #4a7c59;" onclick="loadTakeovers(true)">in scope only</button>
        </div>
      </div>
      <div id="takeover-results" style="margin-top: 14px; display: none;">
        <table>
          <thead><tr><th style="color:#e67e80;">subdomain</th><th style="color:#e67e80;">type</th><th style="color:#e67e80;">service</th><th style="color:#e67e80;">evidence</th><th style="color:#e67e80;">scanned</th></tr></thead>
          <tbody id="takeover-tbody"></tbody>
        </table>
      </div>
    </div>

    <div id="error-box" style="display:none" class="error"></div>

    <div class="results-header">
      <h2>results</h2>
      <span class="count" id="result-count"></span>
    </div>

    <div id="pagination" style="display:none; gap:12px; align-items:center; margin-bottom:12px;">
      <button class="btn" id="btn-prev" onclick="prevPage()">prev</button>
      <button class="btn" id="btn-next" onclick="nextPage()">next</button>
    </div>

    <div id="results-container">
      <div class="empty">run a search or click "show all"</div>
    </div>

  </div>

  <script>
    async function fetchStats() {
      try {
        const r = await fetch('/stats');
        const data = await r.json();
        document.getElementById('stat-total').textContent = data.total ?? '-';
        document.getElementById('stat-domains').textContent = data.unique_domains ?? '-';
        document.getElementById('stat-ips').textContent = data.unique_ips ?? '-';
        document.getElementById('stat-umbrella').textContent = data.umbrella_count != null ? data.umbrella_count.toLocaleString() : '-';
        const tc = data.takeover_count ?? 0;
        document.getElementById('stat-takeovers').textContent = tc > 0 ? tc : '-';
        const isc = data.in_scope_count ?? 0;
        document.getElementById('stat-inscope').textContent = isc > 0 ? isc.toLocaleString() : '-';
      } catch(e) {}
    }

    let _stabPollInterval = null;

    async function runStab() {
      const domain = document.getElementById('f-domain').value.trim();
      const btn = document.getElementById('btn-run-stab');
      btn.disabled = true;
      btn.textContent = domain ? `stab: ${domain}...` : 'stab running...';
      try {
        const r = await fetch('/run_stab', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({filter: domain})
        });
        if (r.status === 409) { btn.textContent = 'stab already running'; pollStabStatus(); return; }
        pollStabStatus();
      } catch(e) {
        btn.disabled = false;
        btn.textContent = 'run stab';
      }
    }

    function pollStabStatus() {
      if (_stabPollInterval) clearInterval(_stabPollInterval);
      _stabPollInterval = setInterval(async () => {
        try {
          const r = await fetch('/run_stab/status');
          const data = await r.json();
          const btn = document.getElementById('btn-run-stab');
          if (!data.running) {
            clearInterval(_stabPollInterval);
            btn.disabled = false;
            btn.style.color = data.error ? '#e67e80' : '#83c092';
            btn.textContent = data.error ? 'stab failed' : 'run stab';
            if (!data.error) { fetchStats(); if (currentBaseUrl) fetchPage(); }
          }
        } catch(e) { clearInterval(_stabPollInterval); }
      }, 3000);
    }

    let _importPollInterval = null;

    async function importScopes() {
      const btn = document.getElementById('btn-import-scopes');
      btn.disabled = true;
      btn.textContent = 'importing...';
      btn.style.color = '#dbbc7f';
      try {
        const r = await fetch('/import_scopes', { method: 'POST' });
        if (r.status === 409) {
          btn.textContent = 'already running';
          setTimeout(() => pollImportStatus(), 3000);
          return;
        }
        pollImportStatus();
      } catch(e) {
        btn.textContent = 'import scopes';
        btn.disabled = false;
      }
    }

    function pollImportStatus() {
      if (_importPollInterval) clearInterval(_importPollInterval);
      _importPollInterval = setInterval(async () => {
        try {
          const r = await fetch('/import_scopes/status');
          const data = await r.json();
          const btn = document.getElementById('btn-import-scopes');
          if (!data.running) {
            clearInterval(_importPollInterval);
            btn.disabled = false;
            btn.style.color = '#83c092';
            btn.textContent = data.error ? 'import failed' : 'import scopes';
            if (!data.error) fetchStats();
          }
        } catch(e) {
          clearInterval(_importPollInterval);
        }
      }, 3000);
    }

    async function loadTakeovers(inscopeOnly) {
      const filter = document.getElementById('t-filter').value.trim();
      const tbody = document.getElementById('takeover-tbody');
      const panel = document.getElementById('takeover-results');
      tbody.innerHTML = '<tr><td colspan="5" style="color:#7fbbb3">loading...</td></tr>';
      panel.style.display = 'block';
      try {
        let url = '/takeovers';
        const params = [];
        if (filter) params.push(`filter=${encodeURIComponent(filter)}`);
        if (inscopeOnly) params.push('inscope=true');
        if (params.length) url += '?' + params.join('&');
        const r = await fetch(url);
        const data = await r.json();
        if (!data.results || data.results.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="color:#5c6a72">no takeover candidates -- run: python3 run_stab.py --domain &lt;target&gt;</td></tr>';
          return;
        }
        const typeColor = t => t === 'cname_takeover' ? '#dbbc7f' : t === 's3_takeover' ? '#7fbbb3' : '#e67e80';
        tbody.innerHTML = data.results.map(r => {
          const evidence = r.evidence || r.ns_record || (Array.isArray(r.cname) ? r.cname.join(', ') : r.cname) || '-';
          const scanned = r.scanned_at ? r.scanned_at.split('T')[0] : '-';
          const type = r.type || '-';
          return `<tr>
            <td class="domain">${r.subdomain}</td>
            <td style="color:${typeColor(type)}">${type}</td>
            <td style="color:#83c092">${r.service || '-'}</td>
            <td style="color:#5c6a72;font-size:0.8rem">${evidence}</td>
            <td style="color:#5c6a72;font-size:0.8rem">${scanned}</td>
          </tr>`;
        }).join('');
      } catch(e) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:#e67e80">error: ${e.message}</td></tr>`;
      }
    }

    async function umbrellaSearch() {
      const q = document.getElementById('u-domain').value.trim();
      if (!q) return;
      const tbody = document.getElementById('umbrella-tbody');
      const panel = document.getElementById('umbrella-results');
      tbody.innerHTML = '<tr><td colspan="2" style="color:#7fbbb3">searching...</td></tr>';
      panel.style.display = 'block';
      try {
        const r = await fetch(`/umbrella/search?q=${encodeURIComponent(q)}&limit=50`);
        const data = await r.json();
        if (!data.results || data.results.length === 0) {
          tbody.innerHTML = '<tr><td colspan="2" style="color:#5c6a72">not found in top 1M</td></tr>';
          return;
        }
        tbody.innerHTML = data.results.map(row =>
          `<tr><td class="port">#${row.rank.toLocaleString()}</td><td class="domain">${row.domain}</td></tr>`
        ).join('');
      } catch(e) {
        tbody.innerHTML = `<tr><td colspan="2" style="color:#e67e80">error: ${e.message}</td></tr>`;
      }
    }

    function getFirstVal(doc, keys) {
      for (const section of ['https_responseForDomainName','http_responseForDomainName','https_responseForIP','http_responseForIP']) {
        const s = doc[section];
        if (!s) continue;
        const items = Array.isArray(s) ? s : [s];
        for (const item of items) {
          for (const k of keys) {
            if (item[k]) return item[k];
          }
        }
      }
      return '';
    }

    function getAllVals(doc, key) {
      const vals = new Set();
      for (const section of ['https_responseForDomainName','http_responseForDomainName','https_responseForIP','http_responseForIP']) {
        const s = doc[section];
        if (!s) continue;
        const items = Array.isArray(s) ? s : [s];
        for (const item of items) {
          if (item[key]) vals.add(item[key]);
        }
      }
      return [...vals];
    }

    function renderTable(docs) {
      if (!docs || docs.length === 0) {
        return '<div class="empty">no results found</div>';
      }
      let rows = docs.map(doc => {
        const domain = getFirstVal(doc, ['domain']);
        const ip = getFirstVal(doc, ['ip']);
        const title = getFirstVal(doc, ['title']);
        const ports = getAllVals(doc, 'port');
        const requests = getAllVals(doc, 'request');
        const protocols = new Set(requests.map(r => r.startsWith('https') ? 'https' : 'http'));
        const portTags = ports.map(p => `<span class="tag">${p}</span>`).join('');
        const protoTags = [...protocols].map(p => `<span class="tag ${p}">${p}</span>`).join('');
        const rank = doc.umbrella_rank ? `<span style="color:#dbbc7f">#${doc.umbrella_rank.toLocaleString()}</span>` : '<span style="color:#5c6a72">-</span>';
        const to = doc.takeover;
        const takeover = to
          ? `<span style="background:#4c2020;color:#e67e80;padding:1px 7px;border-radius:3px;font-size:0.75rem;border:1px solid #c03060;" title="${to.service || ''}">${to.type.replace('_takeover','')}</span>`
          : '<span style="color:#5c6a72">-</span>';
        let scopeUrl = '#';
        if (doc.in_scope_url) {
          scopeUrl = doc.in_scope_url.includes('hackerone.com')
            ? doc.in_scope_url + '#scope'
            : doc.in_scope_url + '#scope';
        }
        const platform = doc.in_scope_platform === 'hackerone' ? 'H1' : doc.in_scope_platform === 'bugcrowd' ? 'BC' : '';
        const program = doc.in_scope_program
          ? `<a href="${scopeUrl}" target="_blank" style="color:#83c092;text-decoration:none;background:#2d4a35;padding:1px 7px;border-radius:3px;font-size:0.75rem;">${doc.in_scope_program}</a> <span style="color:#5c6a72;font-size:0.7rem;">${platform}</span>`
          : '<span style="color:#5c6a72">-</span>';
        const isVuln = !!doc.takeover;
        const rowStyle = isVuln ? ' style="background:#2e1e1e;"' : (doc.in_scope_program ? ' style="background:#1e2e20;"' : '');
        return `<tr${rowStyle}>
          <td class="domain">${domain || '<span style="color:#5c6a72">-</span>'}</td>
          <td class="ip">${ip || '-'}</td>
          <td class="port">${portTags || '-'}</td>
          <td>${protoTags}</td>
          <td class="title">${title || '<span style="color:#5c6a72">-</span>'}</td>
          <td>${rank}</td>
          <td>${program}</td>
          <td>${takeover}</td>
        </tr>`;
      }).join('');
      return `<table>
        <thead><tr><th>domain</th><th>IP</th><th>ports</th><th>protocol</th><th>title</th><th>umbrella rank</th><th>program</th><th>takeover</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    const PAGE_SIZE = 100;
    let currentBaseUrl = '';
    let currentOffset = 0;
    let currentTotal = 0;

    function showError(msg) {
      const box = document.getElementById('error-box');
      box.textContent = msg;
      box.style.display = 'block';
    }

    function clearError() {
      document.getElementById('error-box').style.display = 'none';
    }

    async function fetchPage() {
      const from = currentOffset;
      const to = currentOffset + PAGE_SIZE;
      const sep = currentBaseUrl.includes('?') ? '&' : '?';
      const url = `${currentBaseUrl}${sep}from=${from}&to=${to}`;
      document.getElementById('results-container').innerHTML = '<div class="loading">loading...</div>';
      document.getElementById('result-count').textContent = '';
      document.getElementById('pagination').style.display = 'none';
      try {
        const r = await fetch(url);
        const data = await r.json();
        const docs = Array.isArray(data) ? data : (data.entries || []);
        currentTotal = data.total_entries ?? docs.length;
        const page = Math.floor(currentOffset / PAGE_SIZE) + 1;
        const totalPages = Math.ceil(currentTotal / PAGE_SIZE);
        document.getElementById('result-count').textContent =
          `${currentTotal} result${currentTotal !== 1 ? 's' : ''} -- page ${page} of ${totalPages}`;
        document.getElementById('results-container').innerHTML = renderTable(docs);
        const pagination = document.getElementById('pagination');
        if (currentTotal > PAGE_SIZE) {
          pagination.style.display = 'flex';
          document.getElementById('btn-prev').disabled = currentOffset === 0;
          document.getElementById('btn-next').disabled = currentOffset + PAGE_SIZE >= currentTotal;
        }
      } catch(e) {
        showError('failed to load: ' + e.message);
        document.getElementById('results-container').innerHTML = '';
      }
    }

    async function runSearch() {
      clearError();
      const domain = document.getElementById('f-domain').value.trim();
      const ip = document.getElementById('f-ip').value.trim();
      const port = document.getElementById('f-port').value.trim();
      const title = document.getElementById('f-title').value.trim();
      const html = document.getElementById('f-html').value.trim();
      const header = document.getElementById('f-header').value.trim();

      if (!domain && !ip && !port && !title && !html && !header) {
        showError('enter at least one search field');
        return;
      }

      if (domain) currentBaseUrl = `/bydomain?domain=${encodeURIComponent(domain)}`;
      else if (ip) currentBaseUrl = `/byip?ip=${encodeURIComponent(ip)}`;
      else if (port) currentBaseUrl = `/byport?port=${encodeURIComponent(port)}`;
      else if (title) currentBaseUrl = `/bytitle?title=${encodeURIComponent(title)}`;
      else if (html) currentBaseUrl = `/byhtml?html=${encodeURIComponent(html)}`;
      else if (header) currentBaseUrl = `/byhkeyresponse?hkeyresponse=${encodeURIComponent(header)}`;

      currentOffset = 0;
      await fetchPage();
    }

    async function loadAll() {
      clearError();
      currentBaseUrl = '/all';
      currentOffset = 0;
      await fetchPage();
    }

    async function loadInScope() {
      clearError();
      currentBaseUrl = '/inscope';
      currentOffset = 0;
      await fetchPage();
    }

    function prevPage() {
      if (currentOffset === 0) return;
      currentOffset = Math.max(0, currentOffset - PAGE_SIZE);
      fetchPage();
    }

    function nextPage() {
      if (currentOffset + PAGE_SIZE >= currentTotal) return;
      currentOffset += PAGE_SIZE;
      fetchPage();
    }

    async function confirmDelete() {
      if (!confirm('delete all records from the database?')) return;
      try {
        const r = await fetch('/perform_delete', { method: 'DELETE' });
        const data = await r.json();
        alert(data.message);
        fetchStats();
        document.getElementById('results-container').innerHTML = '<div class="empty">database cleared</div>';
        document.getElementById('result-count').textContent = '';
      } catch(e) {
        showError('delete failed: ' + e.message);
      }
    }

    document.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        if (document.activeElement && document.activeElement.id === 'u-domain') {
          umbrellaSearch();
        } else {
          runSearch();
        }
      }
    });

    fetchStats();
  </script>
</body>
</html>
"""


@app.route("/")
@require_auth
def dashboard():
    return render_template_string(DASHBOARD)


@app.route("/stats")
@require_auth
def stats():
    try:
        total = collection.count_documents({})
        domains = set()
        ips = set()
        for doc in collection.find({}, {"_id": 0}):
            for section in ["https_responseForDomainName", "http_responseForDomainName", "https_responseForIP", "http_responseForIP"]:
                s = doc.get(section)
                if not s:
                    continue
                items = s if isinstance(s, list) else [s]
                for item in items:
                    if item.get("domain"):
                        domains.add(item["domain"])
                    if item.get("ip"):
                        ips.add(item["ip"])
        umbrella_count = umbrella.count_documents({})
        takeover_count = stab_col.count_documents({})
        in_scope_count = collection.count_documents({"in_scope_program": {"$ne": None}})
        return jsonify({"total": total, "unique_domains": len(domains), "unique_ips": len(ips), "umbrella_count": umbrella_count, "takeover_count": takeover_count, "in_scope_count": in_scope_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/all")
@require_auth
def all_records():
    try:
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", 200))
        limit = max(1, to_index - from_index)
        total = collection.count_documents({})
        docs = list(collection.find({}, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": enrich_with_rank(docs)}, indent=2), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/inscope", methods=["GET"])
@require_auth
def inscope():
    try:
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", 100))
        program_filter = request.args.get("program", "").strip()
        query = {"in_scope_program": {"$ne": None}}
        if program_filter:
            query["in_scope_program"] = Regex(re.escape(program_filter), "i")
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        docs = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": enrich_with_rank(docs)}, indent=2), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/takeovers", methods=["GET"])
@require_auth
def takeovers():
    try:
        filter_param = request.args.get("filter", "").strip()
        inscope_only = request.args.get("inscope", "false").lower() == "true"
        query = {"filter": {"$regex": filter_param, "$options": "i"}} if filter_param else {}
        results = list(stab_col.find(query, {"_id": 0}).sort("scanned_at", -1))
        if inscope_only:
            scope_domains = set()
            for s in db["scopes"].find({}, {"asset": 1, "_id": 0}):
                scope_domains.add(s.get("asset", "").lower().lstrip("*."))
            def is_inscope(subdomain):
                d = subdomain.lower()
                parts = d.split(".")
                for i in range(len(parts) - 1):
                    if ".".join(parts[i:]) in scope_domains:
                        return True
                return False
            results = [r for r in results if is_inscope(r.get("subdomain", ""))]
        return jsonify({"count": len(results), "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rank", methods=["GET"])
@require_auth
def rank():
    try:
        domain = request.args.get("domain", "").strip().lower().lstrip("*.")
        if not domain:
            return jsonify({"error": "domain parameter required"}), 400
        result = umbrella.find_one({"domain": domain}, {"_id": 0})
        if result:
            return jsonify({"domain": domain, "rank": result["rank"]})
        return jsonify({"domain": domain, "rank": None})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/umbrella/search", methods=["GET"])
@require_auth
def umbrella_search():
    try:
        q = request.args.get("q", "").strip().lower()
        if not q:
            return jsonify({"error": "q parameter required"}), 400
        limit = int(request.args.get("limit", 50))
        regex = Regex(rf".*{re.escape(q)}.*", "i")
        results = list(umbrella.find({"domain": regex}, {"_id": 0}).sort("rank", 1).limit(limit))
        return jsonify({"count": len(results), "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/run_stab", methods=["POST"])
@require_auth
def trigger_run_stab():
    global _stab_status
    if _stab_status["running"]:
        return jsonify({"status": "already_running"}), 409

    domain_filter = (request.json or {}).get("filter", "").strip()

    def run():
        global _stab_status
        _stab_status["running"] = True
        _stab_status["error"] = None
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_stab.py")
            cmd = [sys.executable, script]
            if domain_filter:
                cmd += ["--domain", domain_filter]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            _stab_status["last_result"] = (result.stdout + result.stderr).strip()
            if result.returncode != 0:
                _stab_status["error"] = result.stderr.strip()
        except Exception as e:
            _stab_status["error"] = str(e)
            _stab_status["last_result"] = str(e)
        finally:
            _stab_status["running"] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started", "filter": domain_filter or "all"}), 202


@app.route("/run_stab/status", methods=["GET"])
@require_auth
def run_stab_status():
    return jsonify(_stab_status)


@app.route("/import_scopes", methods=["POST"])
@require_auth
def trigger_import_scopes():
    global _import_status
    if _import_status["running"]:
        return jsonify({"status": "already_running"}), 409

    def run():
        global _import_status
        _import_status["running"] = True
        _import_status["error"] = None
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "import_scopes.py")
            result = subprocess.run(
                [sys.executable, script],
                capture_output=True, text=True, timeout=300
            )
            _import_status["last_result"] = (result.stdout + result.stderr).strip()
            if result.returncode != 0:
                _import_status["error"] = result.stderr.strip()
        except Exception as e:
            _import_status["error"] = str(e)
            _import_status["last_result"] = str(e)
        finally:
            _import_status["running"] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"}), 202


@app.route("/import_scopes/status", methods=["GET"])
@require_auth
def import_scopes_status():
    return jsonify(_import_status)


@app.route("/<path:any_path>", methods=["GET"])
@require_auth
def respond_to_any_path(any_path):
    return jsonify({"message": f"Unknown endpoint: {any_path}"})


@app.route("/insert", methods=["POST"])
def insert():
    try:
        results_json = request.get_json()
        collection.insert_many(results_json)
        return jsonify({"message": "Inserted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bytitle", methods=["GET"])
@require_auth
def bytitle():
    try:
        title_param = request.args.get("title")
        if title_param is None:
            return jsonify({"error": "title query parameter is missing"}), 400
        regex = Regex(rf".*{re.escape(title_param)}.*", "i")
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", float("inf")))
        query = {"$or": [
            {"http_responseForIP.title": regex},
            {"https_responseForIP.title": regex},
            {"http_responseForDomainName.title": regex},
            {"https_responseForDomainName.title": regex},
        ]}
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        paginated = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bydomain", methods=["GET"])
@require_auth
def bydomain():
    try:
        domain_param = request.args.get("domain")
        if domain_param is None:
            return jsonify({"error": "domain query parameter is missing"}), 400
        regex = Regex(rf".*{re.escape(domain_param)}.*", "i")
        query = {"$or": [
            {"http_responseForIP.domain": regex},
            {"https_responseForIP.domain": regex},
            {"http_responseForDomainName.domain": regex},
            {"https_responseForDomainName.domain": regex},
        ]}
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", 100))
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        docs = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": enrich_with_rank(docs)}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byip", methods=["GET"])
@require_auth
def byip():
    try:
        ip_param = request.args.get("ip")
        if ip_param is None:
            return jsonify({"error": "ip query parameter is missing"}), 400
        regex = Regex(rf".*{re.escape(ip_param)}.*", "i")
        query = {"$or": [
            {"http_responseForIP.ip": regex},
            {"https_responseForIP.ip": regex},
            {"http_responseForDomainName.ip": regex},
            {"https_responseForDomainName.ip": regex},
        ]}
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", 100))
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        docs = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": enrich_with_rank(docs)}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byport", methods=["GET"])
@require_auth
def byport():
    try:
        port_param = request.args.get("port")
        if port_param is None:
            return jsonify({"error": "port query parameter is missing"}), 400
        regex = Regex(rf".*{re.escape(port_param)}.*", "i")
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", float("inf")))
        query = {"$or": [
            {"http_responseForIP.port": regex},
            {"https_responseForIP.port": regex},
            {"http_responseForDomainName.port": regex},
            {"https_responseForDomainName.port": regex},
        ]}
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        paginated = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byhtml", methods=["GET"])
@require_auth
def byhtml():
    try:
        html_param = request.args.get("html")
        if html_param is None:
            return jsonify({"error": "html query parameter is missing"}), 400
        regex = Regex(rf".*{re.escape(html_param)}.*", "i")
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", float("inf")))
        query = {"$or": [
            {"http_responseForIP.response_text": regex},
            {"https_responseForIP.response_text": regex},
            {"http_responseForDomainName.response_text": regex},
            {"https_responseForDomainName.response_text": regex},
        ]}
        total = collection.count_documents(query)
        limit = max(1, to_index - from_index)
        paginated = list(collection.find(query, {"_id": 0}).skip(from_index).limit(limit))
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byhresponse", methods=["GET"])
@require_auth
def byhresponse():
    try:
        hresponse_param = request.args.get("hresponse")
        if hresponse_param is None:
            return jsonify({"error": "hresponse query parameter is missing"}), 400
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", float("inf")))
        all_documents = list(collection.find({}))
        matching_entries = []
        for document in all_documents:
            for keyName in ["http_responseForDomainName", "https_responseForDomainName", "https_responseForIP"]:
                field = document.get(keyName)
                if field:
                    for key in field:
                        if "response_headers" in key:
                            for val in field["response_headers"].values():
                                if hresponse_param.lower() in val.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)
            arr = document.get("http_responseForIP")
            if arr:
                for item in arr:
                    for key in item:
                        if "response_headers" in key:
                            for val in item["response_headers"].values():
                                if hresponse_param.lower() in val.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)
        total = len(matching_entries)
        from_index = max(0, min(from_index, total))
        to_index = min(total, max(to_index, 0))
        paginated = matching_entries[from_index:to_index]
        for e in paginated:
            e.pop("_id", None)
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byhkeyresponse", methods=["GET"])
@require_auth
def byhkeyresponse():
    try:
        hkeyresponse_param = request.args.get("hkeyresponse")
        if hkeyresponse_param is None:
            return jsonify({"error": "hkeyresponse query parameter is missing"}), 400
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", float("inf")))
        all_documents = list(collection.find({}))
        matching_entries = []
        for document in all_documents:
            for keyName in ["http_responseForDomainName", "https_responseForDomainName", "https_responseForIP"]:
                field = document.get(keyName)
                if field:
                    for key in field:
                        if "response_headers" in key:
                            for hkey in field["response_headers"].keys():
                                if hkeyresponse_param.lower() in hkey.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)
            arr = document.get("http_responseForIP")
            if arr:
                for item in arr:
                    for key in item:
                        if "response_headers" in key:
                            for hkey in item["response_headers"].keys():
                                if hkeyresponse_param.lower() in hkey.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)
        total = len(matching_entries)
        from_index = max(0, min(from_index, total))
        to_index = min(total, max(to_index, 0))
        paginated = matching_entries[from_index:to_index]
        for e in paginated:
            e.pop("_id", None)
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/perform_delete", methods=["DELETE"])
@require_auth
def perform_delete():
    try:
        result = collection.delete_many({})
        return jsonify({"message": f"Deleted {result.deleted_count} documents"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
