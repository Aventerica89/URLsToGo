export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1);
    
    // Admin page
    if (path === 'admin') {
      return new Response(adminHTML, { headers: { 'Content-Type': 'text/html' } });
    }
    
    // List all links
    if (path === 'api/links' && request.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM links ORDER BY created_at DESC').all();
      return Response.json(results);
    }
    
    // Create new link
    if (path === 'api/links' && request.method === 'POST') {
      const { code, destination } = await request.json();
      if (!code || !destination) {
        return Response.json({ error: 'Missing code or destination' }, { status: 400 });
      }
      try {
        await env.DB.prepare('INSERT INTO links (code, destination) VALUES (?, ?)').bind(code, destination).run();
        return Response.json({ success: true, code, destination });
      } catch (e) {
        return Response.json({ error: 'Code already exists' }, { status: 409 });
      }
    }
    
    // Delete link
    if (path.startsWith('api/links/') && request.method === 'DELETE') {
      const code = path.replace('api/links/', '');
      await env.DB.prepare('DELETE FROM links WHERE code = ?').bind(code).run();
      return Response.json({ success: true });
    }
    
    // Redirect
    if (path) {
      const link = await env.DB.prepare('SELECT destination FROM links WHERE code = ?').bind(path).first();
      if (link) {
        await env.DB.prepare('UPDATE links SET clicks = clicks + 1 WHERE code = ?').bind(path).run();
        return Response.redirect(link.destination, 302);
      }
    }
    
    return new Response('Not found', { status: 404 });
  }
};

const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Admin</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { margin-bottom: 2rem; color: #fff; }
    .form-row { display: flex; gap: 1rem; margin-bottom: 2rem; }
    input { flex: 1; padding: 0.75rem 1rem; border: 1px solid #334155; border-radius: 8px; background: #1e293b; color: #fff; font-size: 1rem; }
    input:focus { outline: none; border-color: #3b82f6; }
    input::placeholder { color: #64748b; }
    button { padding: 0.75rem 1.5rem; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
    .btn-primary { background: #3b82f6; color: #fff; }
    .btn-primary:hover { background: #2563eb; }
    .btn-danger { background: #ef4444; color: #fff; padding: 0.5rem 1rem; font-size: 0.875rem; }
    .btn-danger:hover { background: #dc2626; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 1rem; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 500; font-size: 0.875rem; text-transform: uppercase; }
    td { color: #e2e8f0; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .clicks { color: #94a3b8; }
    .empty { text-align: center; padding: 3rem; color: #64748b; }
    .toast { position: fixed; bottom: 2rem; right: 2rem; padding: 1rem 1.5rem; border-radius: 8px; color: #fff; opacity: 0; transition: opacity 0.3s; }
    .toast.success { background: #22c55e; }
    .toast.error { background: #ef4444; }
    .toast.show { opacity: 1; }
    .short-link { font-family: monospace; background: #334155; padding: 0.25rem 0.5rem; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔗 Link Admin</h1>
    
    <div class="form-row">
      <input type="text" id="code" placeholder="Short code (e.g. portfolio)">
      <input type="url" id="destination" placeholder="Destination URL (e.g. https://example.com)">
      <button class="btn-primary" onclick="addLink()">Add Link</button>
    </div>
    
    <table>
      <thead>
        <tr>
          <th>Short Link</th>
          <th>Destination</th>
          <th>Clicks</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="links"></tbody>
    </table>
  </div>
  
  <div class="toast" id="toast"></div>

  <script>
    const baseUrl = window.location.origin;
    
    async function loadLinks() {
      const res = await fetch('/api/links');
      const links = await res.json();
      const tbody = document.getElementById('links');
      
      if (links.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No links yet. Add your first one above!</td></tr>';
        return;
      }
      
      tbody.innerHTML = links.map(link => \`
        <tr>
          <td><a href="\${baseUrl}/\${link.code}" target="_blank" class="short-link">/\${link.code}</a></td>
          <td><a href="\${link.destination}" target="_blank">\${link.destination.length > 50 ? link.destination.substring(0, 50) + '...' : link.destination}</a></td>
          <td class="clicks">\${link.clicks}</td>
          <td><button class="btn-danger" onclick="deleteLink('\${link.code}')">Delete</button></td>
        </tr>
      \`).join('');
    }
    
    async function addLink() {
      const code = document.getElementById('code').value.trim();
      const destination = document.getElementById('destination').value.trim();
      
      if (!code || !destination) {
        showToast('Please fill in both fields', 'error');
        return;
      }
      
      const res = await fetch('/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, destination })
      });
      
      if (res.ok) {
        document.getElementById('code').value = '';
        document.getElementById('destination').value = '';
        showToast('Link created!', 'success');
        loadLinks();
      } else {
        const data = await res.json();
        showToast(data.error || 'Failed to create link', 'error');
      }
    }
    
    async function deleteLink(code) {
      if (!confirm('Delete this link?')) return;
      
      await fetch(\`/api/links/\${code}\`, { method: 'DELETE' });
      showToast('Link deleted', 'success');
      loadLinks();
    }
    
    function showToast(message, type) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = \`toast \${type} show\`;
      setTimeout(() => toast.classList.remove('show'), 3000);
    }
    
    document.getElementById('destination').addEventListener('keypress', e => {
      if (e.key === 'Enter') addLink();
    });
    
    loadLinks();
  </script>
</body>
</html>`;
