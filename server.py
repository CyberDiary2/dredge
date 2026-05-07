from flask import Flask, request, jsonify, Response, render_template_string
import json
from bson.regex import Regex
import re
from pymongo import MongoClient

app = Flask(__name__)
mongo_uri = "mongodb://localhost:27017/"
client = MongoClient(mongo_uri)

try:
    db = client["scannerdb"]
    collection = db["sslchecker"]
    print("MongoDB connection successful")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")


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
        <div class="field" style="justify-content: flex-end; margin-left: auto;">
          <button class="btn btn-danger" onclick="confirmDelete()">clear db</button>
        </div>
      </div>
    </div>

    <div id="error-box" style="display:none" class="error"></div>

    <div class="results-header">
      <h2>results</h2>
      <span class="count" id="result-count"></span>
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
      } catch(e) {}
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
        return `<tr>
          <td class="domain">${domain || '<span style="color:#5c6a72">-</span>'}</td>
          <td class="ip">${ip || '-'}</td>
          <td class="port">${portTags || '-'}</td>
          <td>${protoTags}</td>
          <td class="title">${title || '<span style="color:#5c6a72">-</span>'}</td>
        </tr>`;
      }).join('');
      return `<table>
        <thead><tr><th>domain</th><th>IP</th><th>ports</th><th>protocol</th><th>title</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function showError(msg) {
      const box = document.getElementById('error-box');
      box.textContent = msg;
      box.style.display = 'block';
    }

    function clearError() {
      document.getElementById('error-box').style.display = 'none';
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

      document.getElementById('results-container').innerHTML = '<div class="loading">searching...</div>';
      document.getElementById('result-count').textContent = '';

      let url = '';
      if (domain) url = `/bydomain?domain=${encodeURIComponent(domain)}`;
      else if (ip) url = `/byip?ip=${encodeURIComponent(ip)}`;
      else if (port) url = `/byport?port=${encodeURIComponent(port)}&from=0&to=500`;
      else if (title) url = `/bytitle?title=${encodeURIComponent(title)}&from=0&to=500`;
      else if (html) url = `/byhtml?html=${encodeURIComponent(html)}&from=0&to=500`;
      else if (header) url = `/byhkeyresponse?hkeyresponse=${encodeURIComponent(header)}&from=0&to=500`;

      try {
        const r = await fetch(url);
        const data = await r.json();
        const docs = Array.isArray(data) ? data : (data.entries || []);
        const total = data.total_entries ?? docs.length;
        document.getElementById('result-count').textContent = `${total} result${total !== 1 ? 's' : ''}`;
        document.getElementById('results-container').innerHTML = renderTable(docs);
      } catch(e) {
        showError('search failed: ' + e.message);
        document.getElementById('results-container').innerHTML = '';
      }
    }

    async function loadAll() {
      clearError();
      document.getElementById('results-container').innerHTML = '<div class="loading">loading...</div>';
      document.getElementById('result-count').textContent = '';
      try {
        const r = await fetch('/all?from=0&to=200');
        const data = await r.json();
        const docs = data.entries || [];
        const total = data.total_entries ?? docs.length;
        document.getElementById('result-count').textContent = `showing ${docs.length} of ${total}`;
        document.getElementById('results-container').innerHTML = renderTable(docs);
      } catch(e) {
        showError('failed to load: ' + e.message);
      }
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
      if (e.key === 'Enter') runSearch();
    });

    fetchStats();
  </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD)


@app.route("/stats")
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
        return jsonify({"total": total, "unique_domains": len(domains), "unique_ips": len(ips)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/all")
def all_records():
    try:
        from_index = int(request.args.get("from", 0))
        to_index = int(request.args.get("to", 200))
        all_docs = list(collection.find({}, {"_id": 0}))
        total = len(all_docs)
        paginated = all_docs[from_index:to_index]
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=2), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/<path:any_path>", methods=["GET"])
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
        matching = list(collection.find(query, {"_id": 0}))
        total = len(matching)
        from_index = max(0, min(from_index, total))
        to_index = min(total, max(to_index, 0))
        paginated = matching[from_index:to_index]
        return Response(json.dumps({"total_entries": total, "entries": paginated}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bydomain", methods=["GET"])
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
        return jsonify(list(collection.find(query, {"_id": 0})))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byip", methods=["GET"])
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
        return jsonify(list(collection.find(query, {"_id": 0})))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byport", methods=["GET"])
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
        matching = list(collection.find(query, {"_id": 0}))
        total = len(matching)
        from_index = max(0, min(from_index, total))
        to_index = min(total, max(to_index, 0))
        return Response(json.dumps({"total_entries": total, "entries": matching[from_index:to_index]}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byhtml", methods=["GET"])
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
        matching = list(collection.find(query, {"_id": 0}))
        total = len(matching)
        from_index = max(0, min(from_index, total))
        to_index = min(total, max(to_index, 0))
        return Response(json.dumps({"total_entries": total, "entries": matching[from_index:to_index]}, indent=4), content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/byhresponse", methods=["GET"])
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
def perform_delete():
    try:
        result = collection.delete_many({})
        return jsonify({"message": f"Deleted {result.deleted_count} documents"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
