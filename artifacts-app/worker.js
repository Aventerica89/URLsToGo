// Artifact Management App for Claude.ai Artifacts
// Cloudflare Worker with D1 Database
// Tracks published artifacts (claude.site URLs) and downloaded artifacts

// Favicon SVG with accessibility title and optimized grouped paths
const ARTIFACT_MANAGER_FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctitle%3EArtifact Manager Icon%3C/title%3E%3Crect width='32' height='32' rx='6' fill='%2309090b'/%3E%3Cg fill='none' stroke='%23a855f7' stroke-width='2'%3E%3Cpath d='M16 6l8 5v10l-8 5-8-5V11l8-5z'/%3E%3Cpath d='M16 6v10m0 10V16m8-5l-8 5m-8 0l8-5'/%3E%3C/g%3E%3C/svg%3E";

// CORS headers for Chrome extension support
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://claude.ai',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Cf-Access-Jwt-Assertion',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': '86400'
};

// Helper to add CORS headers to a response
function corsResponse(response) {
  const cloned = response.clone();
  const newHeaders = new Headers(cloned.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    newHeaders.set(key, value);
  }
  return new Response(cloned.body, {
    status: cloned.status,
    statusText: cloned.statusText,
    headers: newHeaders
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1);

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    // Wrap all API responses with CORS headers
    const handleRequest = async () => {

    // ============ PUBLIC SHARE PAGE (NO AUTH REQUIRED) ============
    if (path.match(/^share\/[a-f0-9-]{36}$/)) {
      const token = path.split('/')[1];
      return await renderSharePage(env, token, request.url);
    }

    // ============ PUBLIC ARTIFACT RENDER (NO AUTH REQUIRED) ============
    // Renders HTML artifacts in a sandboxed iframe for sharing
    if (path.match(/^render\/[A-Za-z0-9]{12}$/)) {
      const token = path.split('/')[1];
      return await renderArtifactPage(env, token, request.url);
    }

    // Get authenticated user
    const userEmail = await getUserEmail(request);

    // API routes require authentication
    if (path.startsWith('api/')) {
      if (!userEmail) {
        return corsResponse(Response.json({ error: 'Unauthorized' }, { status: 401 }));
      }

      // Process API request and wrap response with CORS headers
      const apiResponse = await handleApiRequest(path, request, env, userEmail, url);
      if (apiResponse) {
        return corsResponse(apiResponse);
      }

      return corsResponse(Response.json({ error: 'Not found' }, { status: 404 }));
    }

    // ============ PWA MANIFEST ============
    if (path === 'manifest.json') {
      return new Response(JSON.stringify({
        name: 'Artifact Manager',
        short_name: 'Artifacts',
        description: 'Track and organize Claude.ai artifacts',
        start_url: '/',
        display: 'standalone',
        background_color: '#09090b',
        theme_color: '#6366f1',
        orientation: 'portrait-primary',
        icons: [
          { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
          { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
        ]
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Serve PWA icons dynamically as SVG with purple gradient background and 3D cube logo.
    // Generated on-the-fly to avoid needing separate image files - SVG scales perfectly for any size.
    if (path === 'icon-192.png' || path === 'icon-512.png') {
      const size = path === 'icon-192.png' ? 192 : 512;
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">
        <defs>
          <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#6366f1"/>
            <stop offset="100%" style="stop-color:#8b5cf6"/>
          </linearGradient>
        </defs>
        <rect width="${size}" height="${size}" rx="${size * 0.15}" fill="url(#bg)"/>
        <g transform="translate(${size * 0.25}, ${size * 0.2}) scale(${size / 48})" fill="none" stroke="white" stroke-width="1.5">
          <path d="M12 2l10 6v12l-10 6-10-6V8l10-6z"/>
          <path d="M12 2v10m0 10V12m10-4l-10 4m-10 0l10-4"/>
        </g>
      </svg>`;

      return new Response(svg, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

    // ============ MAIN APP UI ============

    // Serve main app for root path, empty path, or /admin
    if (path === '' || path === 'admin') {
      if (!userEmail) {
        // Show landing page for non-authenticated users
        return new Response(getLandingPageHtml(), {
          headers: { 'Content-Type': 'text/html' }
        });
      }
      return new Response(getAppHtml(userEmail), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    return new Response('Not found', { status: 404 });
    };

    // Execute and wrap with CORS headers for API routes
    const response = await handleRequest();
    if (path.startsWith('api/')) {
      return corsResponse(response);
    }
    return response;
  }
};

// Handle API requests (separated for CORS wrapping)
async function handleApiRequest(path, request, env, userEmail, url) {

      // ============ ARTIFACTS API ============

      // GET /api/artifacts - List all artifacts with filters
      if (path === 'api/artifacts' && request.method === 'GET') {
        const collection = url.searchParams.get('collection');
        const tag = url.searchParams.get('tag');
        const type = url.searchParams.get('type');
        const source = url.searchParams.get('source');
        const favorite = url.searchParams.get('favorite');
        const sort = url.searchParams.get('sort') || 'newest';
        const search = url.searchParams.get('search');

        let query = `
          SELECT
            a.*,
            c.name as collection_name,
            c.slug as collection_slug,
            c.color as collection_color,
            GROUP_CONCAT(t.name) as tag_names
          FROM artifacts a
          LEFT JOIN collections c ON a.collection_id = c.id
          LEFT JOIN artifact_tags at ON a.id = at.artifact_id
          LEFT JOIN tags t ON at.tag_id = t.id
          WHERE a.user_email = ?
        `;
        const params = [userEmail];

        if (collection) {
          query += ' AND c.slug = ?';
          params.push(collection);
        }
        if (type) {
          query += ' AND a.artifact_type = ?';
          params.push(type);
        }
        if (source) {
          query += ' AND a.source_type = ?';
          params.push(source);
        }
        if (favorite === 'true') {
          query += ' AND a.is_favorite = 1';
        }
        if (search) {
          query += ' AND (a.name LIKE ? OR a.description LIKE ? OR a.notes LIKE ? OR a.language LIKE ? OR a.file_name LIKE ?)';
          const searchTerm = `%${search}%`;
          params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
        }
        if (tag) {
          query += ' AND a.id IN (SELECT artifact_id FROM artifact_tags at2 JOIN tags t2 ON at2.tag_id = t2.id WHERE t2.name = ? AND t2.user_email = ?)';
          params.push(tag, userEmail);
        }

        query += ' GROUP BY a.id';

        // Sorting
        const sortMap = {
          newest: 'a.created_at DESC',
          oldest: 'a.created_at ASC',
          name: 'a.name ASC',
          updated: 'a.updated_at DESC',
          type: 'a.artifact_type ASC, a.name ASC'
        };
        query += ` ORDER BY a.is_favorite DESC, ${sortMap[sort] || sortMap.newest}`;

        const { results } = await env.DB.prepare(query).bind(...params).all();

        // Parse tags from comma-separated string
        const artifacts = results.map(a => ({
          ...a,
          tags: a.tag_names ? a.tag_names.split(',') : []
        }));

        return Response.json(artifacts);
      }

      // GET /api/artifacts/:id - Get single artifact
      if (path.match(/^api\/artifacts\/\d+$/) && request.method === 'GET') {
        const id = path.split('/')[2];
        const artifact = await env.DB.prepare(`
          SELECT a.*, c.name as collection_name, c.slug as collection_slug, c.color as collection_color
          FROM artifacts a
          LEFT JOIN collections c ON a.collection_id = c.id
          WHERE a.id = ? AND a.user_email = ?
        `).bind(id, userEmail).first();

        if (!artifact) {
          return Response.json({ error: 'Artifact not found' }, { status: 404 });
        }

        // Get tags
        const { results: tags } = await env.DB.prepare(`
          SELECT t.name FROM tags t
          JOIN artifact_tags at ON t.id = at.tag_id
          WHERE at.artifact_id = ?
        `).bind(id).all();

        artifact.tags = tags.map(t => t.name);
        return Response.json(artifact);
      }

      // POST /api/artifacts - Create new artifact
      if (path === 'api/artifacts' && request.method === 'POST') {
        const body = await request.json();
        let {
          name, description, artifact_type, source_type,
          published_url, artifact_id, file_name, file_size, file_content,
          language, framework, claude_model, conversation_url, notes,
          collection_id, tags, is_favorite, artifact_created_at
        } = body;

        if (!name || !name.trim()) {
          return Response.json({ error: 'Name is required' }, { status: 400 });
        }

        // Sanitize name to prevent placeholders (server-side validation as backup)
        name = sanitizeName(name.trim());

        const result = await env.DB.prepare(`
          INSERT INTO artifacts (
            name, description, artifact_type, source_type,
            published_url, artifact_id, file_name, file_size, file_content,
            language, framework, claude_model, conversation_url, notes,
            collection_id, user_email, is_favorite, artifact_created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          name, description || null, artifact_type || 'code', source_type || 'published',
          published_url || null, artifact_id || null, file_name || null, file_size || null, file_content || null,
          language || null, framework || null, claude_model || null, conversation_url || null, notes || null,
          collection_id || null, userEmail, is_favorite ? 1 : 0, artifact_created_at || null
        ).run();

        const newId = result.meta.last_row_id;

        // Handle tags
        if (tags && tags.length > 0) {
          for (const tagName of tags) {
            // Get or create tag
            let tag = await env.DB.prepare(
              'SELECT id FROM tags WHERE name = ? AND user_email = ?'
            ).bind(tagName.trim(), userEmail).first();

            if (!tag) {
              const tagResult = await env.DB.prepare(
                'INSERT INTO tags (name, user_email) VALUES (?, ?)'
              ).bind(tagName.trim(), userEmail).run();
              tag = { id: tagResult.meta.last_row_id };
            }

            // Link tag to artifact
            await env.DB.prepare(
              'INSERT OR IGNORE INTO artifact_tags (artifact_id, tag_id) VALUES (?, ?)'
            ).bind(newId, tag.id).run();
          }
        }

        return Response.json({ success: true, id: newId });
      }

      // PUT /api/artifacts/:id - Update artifact
      if (path.match(/^api\/artifacts\/\d+$/) && request.method === 'PUT') {
        const id = path.split('/')[2];
        const body = await request.json();
        let {
          name, description, artifact_type, source_type,
          published_url, artifact_id, file_name, file_size, file_content,
          language, framework, claude_model, conversation_url, notes,
          collection_id, tags, is_favorite
        } = body;

        // Sanitize name to prevent placeholders
        name = sanitizeName((name || '').trim());

        await env.DB.prepare(`
          UPDATE artifacts SET
            name = ?, description = ?, artifact_type = ?, source_type = ?,
            published_url = ?, artifact_id = ?, file_name = ?, file_size = ?, file_content = ?,
            language = ?, framework = ?, claude_model = ?, conversation_url = ?, notes = ?,
            collection_id = ?, is_favorite = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_email = ?
        `).bind(
          name, description || null, artifact_type || 'code', source_type || 'published',
          published_url || null, artifact_id || null, file_name || null, file_size || null, file_content || null,
          language || null, framework || null, claude_model || null, conversation_url || null, notes || null,
          collection_id || null, is_favorite ? 1 : 0, id, userEmail
        ).run();

        // Update tags - delete all and re-add
        await env.DB.prepare('DELETE FROM artifact_tags WHERE artifact_id = ?').bind(id).run();

        if (tags && tags.length > 0) {
          for (const tagName of tags) {
            let tag = await env.DB.prepare(
              'SELECT id FROM tags WHERE name = ? AND user_email = ?'
            ).bind(tagName.trim(), userEmail).first();

            if (!tag) {
              const tagResult = await env.DB.prepare(
                'INSERT INTO tags (name, user_email) VALUES (?, ?)'
              ).bind(tagName.trim(), userEmail).run();
              tag = { id: tagResult.meta.last_row_id };
            }

            await env.DB.prepare(
              'INSERT OR IGNORE INTO artifact_tags (artifact_id, tag_id) VALUES (?, ?)'
            ).bind(id, tag.id).run();
          }
        }

        return Response.json({ success: true });
      }

      // DELETE /api/artifacts/:id
      if (path.match(/^api\/artifacts\/\d+$/) && request.method === 'DELETE') {
        const id = path.split('/')[2];
        await env.DB.prepare('DELETE FROM artifacts WHERE id = ? AND user_email = ?').bind(id, userEmail).run();
        return Response.json({ success: true });
      }

      // POST /api/artifacts/:id/favorite - Toggle favorite
      if (path.match(/^api\/artifacts\/\d+\/favorite$/) && request.method === 'POST') {
        const id = path.split('/')[2];
        await env.DB.prepare(`
          UPDATE artifacts SET is_favorite = CASE WHEN is_favorite = 1 THEN 0 ELSE 1 END, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_email = ?
        `).bind(id, userEmail).run();
        return Response.json({ success: true });
      }

      // POST /api/artifacts/:id/share - Generate share token for HTML rendering
      if (path.match(/^api\/artifacts\/\d+\/share$/) && request.method === 'POST') {
        const id = path.split('/')[2];

        // Generate 12-char alphanumeric token (like YouTube video IDs)
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let shareToken = '';
        for (let i = 0; i < 12; i++) {
          shareToken += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        await env.DB.prepare(`
          UPDATE artifacts SET share_token = ?, shared_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_email = ?
        `).bind(shareToken, id, userEmail).run();

        const baseUrl = new URL(request.url).origin;
        return Response.json({
          success: true,
          shareToken,
          renderUrl: `${baseUrl}/render/${shareToken}`
        });
      }

      // DELETE /api/artifacts/:id/share - Revoke share token
      if (path.match(/^api\/artifacts\/\d+\/share$/) && request.method === 'DELETE') {
        const id = path.split('/')[2];

        await env.DB.prepare(`
          UPDATE artifacts SET share_token = NULL, shared_at = NULL, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_email = ?
        `).bind(id, userEmail).run();

        return Response.json({ success: true });
      }

      // GET /api/artifacts/:id/share - Get share status
      if (path.match(/^api\/artifacts\/\d+\/share$/) && request.method === 'GET') {
        const id = path.split('/')[2];

        const artifact = await env.DB.prepare(`
          SELECT share_token, shared_at FROM artifacts WHERE id = ? AND user_email = ?
        `).bind(id, userEmail).first();

        if (!artifact) {
          return Response.json({ error: 'Artifact not found' }, { status: 404 });
        }

        const baseUrl = new URL(request.url).origin;
        return Response.json({
          isShared: !!artifact.share_token,
          shareToken: artifact.share_token,
          sharedAt: artifact.shared_at,
          renderUrl: artifact.share_token ? `${baseUrl}/render/${artifact.share_token}` : null
        });
      }

      // ============ COLLECTIONS API ============

      // GET /api/collections
      if (path === 'api/collections' && request.method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT c.*, COUNT(a.id) as artifact_count
          FROM collections c
          LEFT JOIN artifacts a ON c.id = a.collection_id
          WHERE c.user_email = ?
          GROUP BY c.id
          ORDER BY c.name ASC
        `).bind(userEmail).all();
        return Response.json(results);
      }

      // POST /api/collections
      if (path === 'api/collections' && request.method === 'POST') {
        const { name, description, color, icon } = await request.json();
        const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

        try {
          const result = await env.DB.prepare(
            'INSERT INTO collections (name, slug, description, color, icon, user_email) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(name, slug, description || null, color || '#6366f1', icon || 'folder', userEmail).run();
          return Response.json({ success: true, id: result.meta.last_row_id, slug });
        } catch (e) {
          return Response.json({ error: 'Collection with this name already exists' }, { status: 400 });
        }
      }

      // PUT /api/collections/:slug
      if (path.match(/^api\/collections\/[a-z0-9-]+$/) && request.method === 'PUT') {
        const slug = path.split('/')[2];
        const { name, description, color, icon } = await request.json();
        const newSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

        await env.DB.prepare(`
          UPDATE collections SET name = ?, slug = ?, description = ?, color = ?, icon = ?
          WHERE slug = ? AND user_email = ?
        `).bind(name, newSlug, description || null, color || '#6366f1', icon || 'folder', slug, userEmail).run();

        return Response.json({ success: true, slug: newSlug });
      }

      // DELETE /api/collections/:slug
      if (path.match(/^api\/collections\/[a-z0-9-]+$/) && request.method === 'DELETE') {
        const slug = path.split('/')[2];
        await env.DB.prepare('DELETE FROM collections WHERE slug = ? AND user_email = ?').bind(slug, userEmail).run();
        return Response.json({ success: true });
      }

      // POST /api/collections/:slug/share - Enable sharing for collection
      if (path.match(/^api\/collections\/[a-z0-9-]+\/share$/) && request.method === 'POST') {
        const slug = path.split('/')[2];
        const { settings } = await request.json();

        // Generate secure share token
        const shareToken = crypto.randomUUID();

        await env.DB.prepare(`
          UPDATE collections
          SET is_public = 1, share_token = ?, share_settings = ?, shared_at = CURRENT_TIMESTAMP
          WHERE slug = ? AND user_email = ?
        `).bind(shareToken, JSON.stringify(settings || {}), slug, userEmail).run();

        const baseUrl = new URL(request.url).origin;
        return Response.json({
          success: true,
          shareUrl: `${baseUrl}/share/${shareToken}`
        });
      }

      // DELETE /api/collections/:slug/share - Disable sharing
      if (path.match(/^api\/collections\/[a-z0-9-]+\/share$/) && request.method === 'DELETE') {
        const slug = path.split('/')[2];

        await env.DB.prepare(`
          UPDATE collections
          SET is_public = 0, share_token = NULL, share_settings = NULL, shared_at = NULL
          WHERE slug = ? AND user_email = ?
        `).bind(slug, userEmail).run();

        return Response.json({ success: true });
      }

      // ============ TAGS API ============

      // GET /api/tags
      if (path === 'api/tags' && request.method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT t.*, COUNT(at.artifact_id) as usage_count
          FROM tags t
          LEFT JOIN artifact_tags at ON t.id = at.tag_id
          WHERE t.user_email = ?
          GROUP BY t.id
          ORDER BY usage_count DESC, t.name ASC
        `).bind(userEmail).all();
        return Response.json(results);
      }

      // DELETE /api/tags/:name
      if (path.match(/^api\/tags\/.+$/) && request.method === 'DELETE') {
        const name = decodeURIComponent(path.split('/')[2]);
        // Get the tag ID first
        const tag = await env.DB.prepare('SELECT id FROM tags WHERE name = ? AND user_email = ?').bind(name, userEmail).first();
        if (tag) {
          // Delete artifact_tags relationships first
          await env.DB.prepare('DELETE FROM artifact_tags WHERE tag_id = ?').bind(tag.id).run();
          // Then delete the tag
          await env.DB.prepare('DELETE FROM tags WHERE id = ?').bind(tag.id).run();
        }
        return Response.json({ success: true });
      }

      // ============ STATS API ============

      if (path === 'api/stats' && request.method === 'GET') {
        const stats = await env.DB.prepare(`
          SELECT
            (SELECT COUNT(*) FROM artifacts WHERE user_email = ?) as total_artifacts,
            (SELECT COUNT(*) FROM artifacts WHERE user_email = ? AND source_type = 'published') as published_count,
            (SELECT COUNT(*) FROM artifacts WHERE user_email = ? AND source_type = 'downloaded') as downloaded_count,
            (SELECT COUNT(*) FROM artifacts WHERE user_email = ? AND is_favorite = 1) as favorites_count,
            (SELECT COUNT(*) FROM collections WHERE user_email = ?) as total_collections,
            (SELECT COUNT(DISTINCT t.id) FROM tags t JOIN artifact_tags at ON t.id = at.tag_id JOIN artifacts a ON at.artifact_id = a.id WHERE a.user_email = ?) as total_tags
        `).bind(userEmail, userEmail, userEmail, userEmail, userEmail, userEmail).first();
        return Response.json(stats);
      }

      // ============ CLEANUP API ============

      // GET /api/cleanup/scan - Find artifacts with placeholder names
      if (path === 'api/cleanup/scan' && request.method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT id, name, artifact_type
          FROM artifacts
          WHERE user_email = ?
        `).bind(userEmail).all();

        const placeholders = results.filter(artifact => {
          const trimmed = (artifact.name || '').trim();
          return !trimmed ||
                 trimmed === "Saving..." ||
                 trimmed === "Loading..." ||
                 trimmed === "Downloading..." ||
                 trimmed === "Untitled" ||
                 trimmed === "New Artifact" ||
                 trimmed.startsWith("Untitled ");
        });

        return Response.json(placeholders);
      }

      // POST /api/cleanup/fix - Fix all placeholder names
      if (path === 'api/cleanup/fix' && request.method === 'POST') {
        const { results: allArtifacts } = await env.DB.prepare(`
          SELECT id, name, artifact_type
          FROM artifacts
          WHERE user_email = ?
        `).bind(userEmail).all();

        const placeholders = allArtifacts.filter(artifact => {
          const trimmed = (artifact.name || '').trim();
          return !trimmed ||
                 trimmed === "Saving..." ||
                 trimmed === "Loading..." ||
                 trimmed === "Downloading..." ||
                 trimmed === "Untitled" ||
                 trimmed === "New Artifact" ||
                 trimmed.startsWith("Untitled ");
        });

        const existingNames = allArtifacts.map(a => a.name);
        let fixedCount = 0;

        for (const artifact of placeholders) {
          // Generate unique name based on artifact type
          const baseName = artifact.artifact_type || 'Artifact';
          let newName = baseName;
          let counter = 1;

          while (existingNames.includes(newName)) {
            counter++;
            newName = `${baseName} ${counter}`;
          }

          // Update the artifact
          await env.DB.prepare(`
            UPDATE artifacts
            SET name = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_email = ?
          `).bind(newName, artifact.id, userEmail).run();

          existingNames.push(newName);
          fixedCount++;
        }

        return Response.json({ success: true, fixed: fixedCount });
      }

      // ============ EXPORT/IMPORT API ============

      // GET /api/export
      if (path === 'api/export' && request.method === 'GET') {
        const { results: collections } = await env.DB.prepare(
          'SELECT name, slug, description, color, icon FROM collections WHERE user_email = ?'
        ).bind(userEmail).all();

        const { results: artifacts } = await env.DB.prepare(`
          SELECT
            a.name, a.description, a.artifact_type, a.source_type,
            a.published_url, a.artifact_id, a.file_name, a.file_size, a.file_content,
            a.language, a.framework, a.claude_model, a.conversation_url, a.notes,
            a.is_favorite, a.artifact_created_at, a.created_at,
            c.slug as collection_slug,
            GROUP_CONCAT(t.name) as tag_names
          FROM artifacts a
          LEFT JOIN collections c ON a.collection_id = c.id
          LEFT JOIN artifact_tags at ON a.id = at.artifact_id
          LEFT JOIN tags t ON at.tag_id = t.id
          WHERE a.user_email = ?
          GROUP BY a.id
        `).bind(userEmail).all();

        const exportData = {
          version: 1,
          exported_at: new Date().toISOString(),
          collections,
          artifacts: artifacts.map(a => ({
            ...a,
            tags: a.tag_names ? a.tag_names.split(',') : []
          }))
        };

        return new Response(JSON.stringify(exportData, null, 2), {
          headers: {
            'Content-Type': 'application/json',
            'Content-Disposition': `attachment; filename="artifacts-export-${new Date().toISOString().split('T')[0]}.json"`
          }
        });
      }

      // POST /api/import
      if (path === 'api/import' && request.method === 'POST') {
        const data = await request.json();
        let imported = 0, skipped = 0;

        // Import collections first
        if (data.collections) {
          for (const col of data.collections) {
            try {
              await env.DB.prepare(
                'INSERT INTO collections (name, slug, description, color, icon, user_email) VALUES (?, ?, ?, ?, ?, ?)'
              ).bind(col.name, col.slug, col.description, col.color || '#6366f1', col.icon || 'folder', userEmail).run();
            } catch (e) {
              // Collection exists, skip
            }
          }
        }

        // Get collection mapping
        const { results: cols } = await env.DB.prepare(
          'SELECT id, slug FROM collections WHERE user_email = ?'
        ).bind(userEmail).all();
        const colMap = Object.fromEntries(cols.map(c => [c.slug, c.id]));

        // Import artifacts
        if (data.artifacts) {
          for (const artifact of data.artifacts) {
            try {
              const collectionId = artifact.collection_slug ? colMap[artifact.collection_slug] : null;

              const result = await env.DB.prepare(`
                INSERT INTO artifacts (
                  name, description, artifact_type, source_type,
                  published_url, artifact_id, file_name, file_size, file_content,
                  language, framework, claude_model, conversation_url, notes,
                  collection_id, user_email, is_favorite, artifact_created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).bind(
                artifact.name, artifact.description, artifact.artifact_type || 'code', artifact.source_type || 'published',
                artifact.published_url, artifact.artifact_id, artifact.file_name, artifact.file_size, artifact.file_content,
                artifact.language, artifact.framework, artifact.claude_model, artifact.conversation_url, artifact.notes,
                collectionId, userEmail, artifact.is_favorite ? 1 : 0, artifact.artifact_created_at
              ).run();

              // Handle tags
              if (artifact.tags && artifact.tags.length > 0) {
                for (const tagName of artifact.tags) {
                  let tag = await env.DB.prepare(
                    'SELECT id FROM tags WHERE name = ? AND user_email = ?'
                  ).bind(tagName.trim(), userEmail).first();

                  if (!tag) {
                    const tagResult = await env.DB.prepare(
                      'INSERT INTO tags (name, user_email) VALUES (?, ?)'
                    ).bind(tagName.trim(), userEmail).run();
                    tag = { id: tagResult.meta.last_row_id };
                  }

                  await env.DB.prepare(
                    'INSERT OR IGNORE INTO artifact_tags (artifact_id, tag_id) VALUES (?, ?)'
                  ).bind(result.meta.last_row_id, tag.id).run();
                }
              }

              imported++;
            } catch (e) {
              skipped++;
            }
          }
        }

        return Response.json({ success: true, imported, skipped });
      }

      // ============ INIT DEFAULT COLLECTIONS ============

      if (path === 'api/init' && request.method === 'POST') {
        const { results: existing } = await env.DB.prepare(
          'SELECT COUNT(*) as count FROM collections WHERE user_email = ?'
        ).bind(userEmail).all();

        if (existing[0].count === 0) {
          const defaults = [
            { name: 'Code Snippets', slug: 'code-snippets', color: '#10b981', icon: 'code' },
            { name: 'Web Apps', slug: 'web-apps', color: '#6366f1', icon: 'globe' },
            { name: 'Documents', slug: 'documents', color: '#f59e0b', icon: 'file-text' },
            { name: 'Data & Analysis', slug: 'data-analysis', color: '#ec4899', icon: 'bar-chart' },
            { name: 'Experiments', slug: 'experiments', color: '#8b5cf6', icon: 'flask' }
          ];

          for (const col of defaults) {
            await env.DB.prepare(
              'INSERT INTO collections (name, slug, color, icon, user_email) VALUES (?, ?, ?, ?, ?)'
            ).bind(col.name, col.slug, col.color, col.icon, userEmail).run();
          }
        }

        return Response.json({ success: true });
      }

      // No matching API route
      return null;
}

// ============ AUTHENTICATION ============

async function getUserEmail(request) {
  const jwt = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!jwt) return null;
  try {
    const parts = jwt.split('.');
    const payload = JSON.parse(atob(parts[1]));
    return payload.email;
  } catch (e) {
    return null;
  }
}

// ============ PUBLIC SHARE PAGE RENDERING ============

async function renderSharePage(env, token, requestUrl) {
  // Get collection by share token
  const collection = await env.DB.prepare(`
    SELECT * FROM collections
    WHERE share_token = ? AND is_public = 1
  `).bind(token).first();

  if (!collection) {
    return new Response(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Collection Not Found</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f9fafb; }
          .error { text-align: center; padding: 2rem; }
          h1 { color: #374151; }
        </style>
      </head>
      <body>
        <div class="error">
          <h1>404 - Collection Not Found</h1>
          <p>This collection doesn't exist or is no longer shared.</p>
        </div>
      </body>
      </html>
    `, { status: 404, headers: { 'Content-Type': 'text/html' } });
  }

  // Get artifacts in collection (grouped by tags)
  const { results: artifacts } = await env.DB.prepare(`
    SELECT a.*, GROUP_CONCAT(t.name) as tags
    FROM artifacts a
    LEFT JOIN artifact_tags at ON a.id = at.artifact_id
    LEFT JOIN tags t ON at.tag_id = t.id
    WHERE a.collection_id = ? AND a.user_email = ?
    GROUP BY a.id
    ORDER BY a.created_at DESC
  `).bind(collection.id, collection.user_email).all();

  const settings = JSON.parse(collection.share_settings || '{}');

  // Group artifacts by tags
  const grouped = {};
  artifacts.forEach(artifact => {
    const tagList = artifact.tags ? artifact.tags.split(',') : ['Uncategorized'];
    tagList.forEach(tag => {
      if (!grouped[tag]) grouped[tag] = [];
      grouped[tag].push(artifact);
    });
  });

  // Render public share page
  return new Response(renderSharePageHTML(collection, grouped, settings), {
    headers: { 'Content-Type': 'text/html' }
  });
}

function renderSharePageHTML(collection, groupedArtifacts, settings) {
  const name = escapeHtmlServer(collection.name);
  const desc = collection.description ? escapeHtmlServer(collection.description) : '';
  const count = Object.values(groupedArtifacts).reduce((sum, arr) => sum + arr.length, 0);

  let artifactsHTML = '';
  for (const [tag, artifacts] of Object.entries(groupedArtifacts)) {
    artifactsHTML += `
      <details class="tag-group" open>
        <summary class="tag-header">
          <h2>${escapeHtmlServer(tag)}</h2>
          <span class="count">${artifacts.length} item${artifacts.length !== 1 ? 's' : ''}</span>
        </summary>
        <div class="artifacts-grid">
          ${artifacts.map(a => renderPublicCard(a, settings)).join('')}
        </div>
      </details>
    `;
  }

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${name} - Shared Collection</title>
      <style>
        /* Reset and base styles */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.5; color: #1f2937; background: #f9fafb; }

        /* Header */
        .share-header { background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 3rem 2rem; text-align: center; }
        .share-header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; font-weight: 700; }
        .share-header p { font-size: 1.125rem; opacity: 0.95; margin-top: 0.5rem; }
        .artifact-count { display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem; background: rgba(255,255,255,0.2); border-radius: 2rem; font-size: 0.875rem; }

        /* Content area */
        .share-content { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }

        /* Tag groups */
        .tag-group { background: white; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1.5rem; overflow: hidden; }
        .tag-group summary { cursor: pointer; padding: 1rem 1.5rem; background: #f9fafb; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; user-select: none; list-style: none; }
        .tag-group summary::-webkit-details-marker { display: none; }
        .tag-group summary:hover { background: #f3f4f6; }
        .tag-group summary h2 { font-size: 1.25rem; font-weight: 600; color: #111827; }
        .tag-group summary .count { color: #6b7280; font-size: 0.875rem; }
        .tag-group[open] summary { border-bottom: 2px solid #6366f1; }

        /* Artifacts grid */
        .artifacts-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; padding: 1.5rem; }

        /* Artifact cards */
        .artifact-card { background: white; border: 1px solid #e5e7eb; border-radius: 0.5rem; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; }
        .artifact-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .artifact-card .card-body { padding: 1rem; }
        .artifact-card h3 { font-size: 1.125rem; font-weight: 600; margin-bottom: 0.5rem; color: #111827; }
        .artifact-card p { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.75rem; }

        /* Card meta */
        .card-meta { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .card-meta span { padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 0.25rem; background: #f3f4f6; color: #374151; font-weight: 500; }

        /* Card actions */
        .card-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .btn-primary, .btn-secondary { flex: 1; min-width: 120px; padding: 0.5rem 1rem; border-radius: 0.375rem; font-size: 0.875rem; font-weight: 500; text-align: center; text-decoration: none; transition: all 0.2s; border: none; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 0.25rem; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: white; border: 1px solid #6366f1; color: #6366f1; }
        .btn-secondary:hover { background: #f9fafb; }

        /* Footer */
        .share-footer { text-align: center; padding: 2rem; color: #6b7280; font-size: 0.875rem; }
        .share-footer a { color: #6366f1; text-decoration: none; }
        .share-footer a:hover { text-decoration: underline; }

        /* Responsive */
        @media (max-width: 768px) {
          .artifacts-grid { grid-template-columns: 1fr; }
          .share-header h1 { font-size: 1.75rem; }
          .share-header p { font-size: 1rem; }
        }
      </style>
    </head>
    <body>
      <header class="share-header">
        <h1>${name}</h1>
        ${desc ? `<p>${desc}</p>` : ''}
        <span class="artifact-count">${count} artifact${count !== 1 ? 's' : ''}</span>
      </header>

      <main class="share-content">
        ${artifactsHTML || '<p style="text-align: center; color: #6b7280;">No artifacts in this collection yet.</p>'}
      </main>

      <footer class="share-footer">
        <p>Powered by <a href="https://artifact-manager.jbmd-creations.workers.dev">Artifact Manager</a></p>
      </footer>
    </body>
    </html>
  `;
}

function renderPublicCard(artifact, settings) {
  const name = escapeHtmlServer(artifact.name);
  const desc = artifact.description ? escapeHtmlServer(artifact.description) : '';
  const type = escapeHtmlServer(artifact.artifact_type);
  const lang = artifact.language ? escapeHtmlServer(artifact.language) : '';

  return `
    <div class="artifact-card">
      <div class="card-body">
        <h3>${name}</h3>
        ${desc ? `<p>${desc}</p>` : ''}

        <div class="card-meta">
          <span>${type}</span>
          ${lang ? `<span>${lang}</span>` : ''}
        </div>

        <div class="card-actions">
          ${artifact.published_url ? `
            <a href="${escapeHtmlServer(artifact.published_url)}" target="_blank" rel="noopener noreferrer" class="btn-primary">
              View Artifact
            </a>
          ` : ''}
          ${artifact.conversation_url ? `
            <a href="${escapeHtmlServer(artifact.conversation_url)}" target="_blank" rel="noopener noreferrer" class="btn-secondary">
              See Conversation
            </a>
          ` : ''}
        </div>
      </div>
    </div>
  `;
}

// ============ PUBLIC ARTIFACT RENDER PAGE ============

async function renderArtifactPage(env, token, requestUrl) {
  // Get artifact by share token
  const artifact = await env.DB.prepare(`
    SELECT id, name, description, artifact_type, file_content, language, published_url
    FROM artifacts
    WHERE share_token = ?
  `).bind(token).first();

  if (!artifact) {
    return new Response(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Artifact Not Found</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #09090b; color: #fafafa; }
          .error { text-align: center; padding: 2rem; }
          h1 { color: #fafafa; margin-bottom: 1rem; }
          p { color: #a1a1aa; }
        </style>
      </head>
      <body>
        <div class="error">
          <h1>404 - Artifact Not Found</h1>
          <p>This artifact doesn't exist or is no longer shared.</p>
        </div>
      </body>
      </html>
    `, { status: 404, headers: { 'Content-Type': 'text/html' } });
  }

  const name = escapeHtmlServer(artifact.name);
  const content = artifact.file_content || '';
  const isHtml = artifact.artifact_type === 'html' || (artifact.language && artifact.language.toLowerCase() === 'html');

  // If it's HTML content, render it in a sandboxed iframe
  if (isHtml && content) {
    return new Response(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${name} - Artifact Manager</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: system-ui, -apple-system, sans-serif; background: #09090b; height: 100vh; display: flex; flex-direction: column; }
          .toolbar { background: #18181b; border-bottom: 1px solid #27272a; padding: 0.75rem 1rem; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
          .toolbar-left { display: flex; align-items: center; gap: 1rem; }
          .toolbar h1 { font-size: 1rem; font-weight: 600; color: #fafafa; }
          .badge { font-size: 0.75rem; padding: 0.25rem 0.5rem; background: #27272a; color: #a1a1aa; border-radius: 0.25rem; }
          .toolbar-right { display: flex; gap: 0.5rem; }
          .btn { display: inline-flex; align-items: center; gap: 0.375rem; padding: 0.5rem 0.75rem; border-radius: 0.375rem; font-size: 0.875rem; font-weight: 500; cursor: pointer; border: none; transition: all 0.15s; }
          .btn-secondary { background: #27272a; color: #fafafa; }
          .btn-secondary:hover { background: #3f3f46; }
          .btn-primary { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; }
          .btn-primary:hover { opacity: 0.9; }
          .render-frame { flex: 1; border: none; width: 100%; background: white; }
          .powered-by { font-size: 0.75rem; color: #71717a; }
          .powered-by a { color: #6366f1; text-decoration: none; }
          .powered-by a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="toolbar">
          <div class="toolbar-left">
            <h1>${name}</h1>
            <span class="badge">HTML</span>
          </div>
          <div class="toolbar-right">
            <span class="powered-by">Powered by <a href="https://artifacts.jbcloud.app" target="_blank">Artifact Manager</a></span>
          </div>
        </div>
        <iframe class="render-frame" sandbox="allow-scripts allow-same-origin" srcdoc="${escapeHtmlServer(content).replace(/"/g, '&quot;')}"></iframe>
      </body>
      </html>
    `, { headers: { 'Content-Type': 'text/html' } });
  }

  // For non-HTML content, show it as formatted code
  return new Response(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${name} - Artifact Manager</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; background: #09090b; min-height: 100vh; }
        .toolbar { background: #18181b; border-bottom: 1px solid #27272a; padding: 0.75rem 1rem; display: flex; align-items: center; justify-content: space-between; }
        .toolbar-left { display: flex; align-items: center; gap: 1rem; }
        .toolbar h1 { font-size: 1rem; font-weight: 600; color: #fafafa; }
        .badge { font-size: 0.75rem; padding: 0.25rem 0.5rem; background: #27272a; color: #a1a1aa; border-radius: 0.25rem; }
        .powered-by { font-size: 0.75rem; color: #71717a; }
        .powered-by a { color: #6366f1; text-decoration: none; }
        .content { padding: 1.5rem; }
        pre { background: #18181b; border: 1px solid #27272a; border-radius: 0.5rem; padding: 1rem; overflow-x: auto; }
        code { font-family: 'SF Mono', Consolas, monospace; font-size: 0.875rem; color: #fafafa; white-space: pre-wrap; word-break: break-all; }
      </style>
    </head>
    <body>
      <div class="toolbar">
        <div class="toolbar-left">
          <h1>${name}</h1>
          <span class="badge">${escapeHtmlServer(artifact.language || artifact.artifact_type || 'Code')}</span>
        </div>
        <span class="powered-by">Powered by <a href="https://artifacts.jbcloud.app" target="_blank">Artifact Manager</a></span>
      </div>
      <div class="content">
        <pre><code>${escapeHtmlServer(content)}</code></pre>
      </div>
    </body>
    </html>
  `, { headers: { 'Content-Type': 'text/html' } });
}

// Server-side HTML escaping
function escapeHtmlServer(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Name validation - prevents placeholder names
function sanitizeName(name) {
  const placeholderPatterns = [
    "Saving...",
    "Loading...",
    "Untitled",
    "New Artifact",
    "Downloading...",
    ""
  ];

  const trimmed = (name || '').trim();

  // Check exact matches
  if (placeholderPatterns.includes(trimmed)) {
    return "Artifact";
  }

  // Check for pattern matches (e.g., "Untitled 1", "Untitled 2")
  if (trimmed.startsWith("Untitled")) {
    return "Artifact";
  }

  // Check if name is empty
  if (!trimmed) {
    return "Artifact";
  }

  return trimmed;
}

// ============ LANDING PAGE HTML ============

function getLandingPageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Artifact Manager - Save & Organize Claude.ai Artifacts</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #09090b;
      --bg-secondary: #18181b;
      --border: #27272a;
      --text: #fafafa;
      --text-muted: #a1a1aa;
      --indigo: #6366f1;
      --violet: #8b5cf6;
      --emerald: #10b981;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }

    /* Hero */
    .hero { min-height: 80vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 4rem 2rem; background: linear-gradient(180deg, var(--bg) 0%, #0f0f14 100%); position: relative; overflow: hidden; }
    .hero::before { content: ''; position: absolute; top: 50%; left: 50%; width: 600px; height: 600px; background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%); transform: translate(-50%, -50%); }
    .hero-content { position: relative; z-index: 1; max-width: 800px; }
    .badge { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 2rem; font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1.5rem; }
    .badge-dot { width: 8px; height: 8px; background: var(--emerald); border-radius: 50%; }
    h1 { font-size: clamp(2.5rem, 6vw, 4rem); font-weight: 700; margin-bottom: 1.5rem; background: linear-gradient(135deg, var(--text) 0%, var(--text-muted) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { font-size: 1.25rem; color: var(--text-muted); margin-bottom: 2rem; max-width: 600px; margin-left: auto; margin-right: auto; }
    .cta-buttons { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.875rem 1.5rem; border-radius: 0.5rem; font-size: 1rem; font-weight: 600; text-decoration: none; transition: all 0.2s; border: none; cursor: pointer; }
    .btn-primary { background: linear-gradient(135deg, var(--indigo), var(--violet)); color: white; }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(99, 102, 241, 0.3); }
    .btn-secondary { background: var(--bg-secondary); color: var(--text); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }

    /* Features */
    .features { padding: 6rem 2rem; max-width: 1200px; margin: 0 auto; }
    .features h2 { text-align: center; font-size: 2rem; margin-bottom: 3rem; }
    .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
    .feature-card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 1rem; padding: 2rem; }
    .feature-icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--indigo), var(--violet)); border-radius: 0.75rem; display: flex; align-items: center; justify-content: center; margin-bottom: 1rem; }
    .feature-card h3 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .feature-card p { color: var(--text-muted); }

    /* How it works */
    .how-it-works { padding: 6rem 2rem; background: var(--bg-secondary); }
    .how-it-works h2 { text-align: center; font-size: 2rem; margin-bottom: 3rem; }
    .steps { max-width: 800px; margin: 0 auto; display: flex; flex-direction: column; gap: 2rem; }
    .step { display: flex; gap: 1.5rem; align-items: flex-start; }
    .step-number { width: 40px; height: 40px; background: linear-gradient(135deg, var(--indigo), var(--violet)); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; flex-shrink: 0; }
    .step-content h3 { font-size: 1.125rem; margin-bottom: 0.25rem; }
    .step-content p { color: var(--text-muted); }

    /* Footer */
    .footer { padding: 3rem 2rem; text-align: center; border-top: 1px solid var(--border); }
    .footer p { color: var(--text-muted); font-size: 0.875rem; }
    .footer a { color: var(--indigo); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .version { margin-top: 1rem; font-size: 0.75rem; color: var(--text-muted); }
  </style>
</head>
<body>
  <section class="hero">
    <div class="hero-content">
      <div class="badge">
        <span class="badge-dot"></span>
        <span>v1.1.0 - Now with shareable HTML rendering</span>
      </div>
      <h1>Save & Organize Your Claude Artifacts</h1>
      <p>One-click saving from Claude.ai. Organize with collections and tags. Share rendered HTML with anyone.</p>
      <div class="cta-buttons">
        <a href="https://github.com/Aventerica89/cf-url-shortener/tree/main/chrome-extension" class="btn btn-primary" target="_blank">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.4 0 0 5.4 0 12c0 5.3 3.4 9.8 8.2 11.4.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.5-1.4-1.3-1.8-1.3-1.8-1-.7.1-.7.1-.7 1.1.1 1.7 1.2 1.7 1.2 1 1.7 2.6 1.2 3.3.9.1-.7.4-1.2.7-1.5-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2 1-.3 2-.4 3-.4s2 .1 3 .4c2.3-1.5 3.3-1.2 3.3-1.2.6 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6C20.6 21.8 24 17.3 24 12c0-6.6-5.4-12-12-12z"/></svg>
          Get Chrome Extension
        </a>
        <a href="#" class="btn btn-secondary" onclick="alert('Safari extension coming soon!')">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m16.24 7.76-2.12 6.36-6.36 2.12 2.12-6.36 6.36-2.12z"/></svg>
          Safari Extension
        </a>
      </div>
    </div>
  </section>

  <section class="features">
    <h2>Everything you need to manage artifacts</h2>
    <div class="features-grid">
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        </div>
        <h3>One-Click Save</h3>
        <p>Save any Claude artifact directly from claude.ai with a single click. The browser extension handles everything.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        </div>
        <h3>Collections & Tags</h3>
        <p>Organize artifacts into collections. Add tags for flexible categorization. Find anything instantly.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </div>
        <h3>Share Rendered HTML</h3>
        <p>Generate shareable links for HTML artifacts. Anyone can view the rendered result - no login required.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <h3>Live Preview</h3>
        <p>Preview HTML artifacts directly in the app. Toggle between code view and rendered preview instantly.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        </div>
        <h3>Full Content Storage</h3>
        <p>Store complete artifact content, not just URLs. View, copy, and export your code anytime.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </div>
        <h3>Export & Backup</h3>
        <p>Export your entire library as JSON. Import into other instances. Your data, your control.</p>
      </div>
    </div>
  </section>

  <section class="how-it-works">
    <h2>Get started in 3 steps</h2>
    <div class="steps">
      <div class="step">
        <div class="step-number">1</div>
        <div class="step-content">
          <h3>Install the Extension</h3>
          <p>Download and install the Chrome or Safari extension from GitHub.</p>
        </div>
      </div>
      <div class="step">
        <div class="step-number">2</div>
        <div class="step-content">
          <h3>Configure the URL</h3>
          <p>Set your Artifact Manager URL in the extension popup (it's this site!).</p>
        </div>
      </div>
      <div class="step">
        <div class="step-number">3</div>
        <div class="step-content">
          <h3>Start Saving</h3>
          <p>Visit claude.ai and click "Save" on any artifact. It appears here automatically.</p>
        </div>
      </div>
    </div>
  </section>

  <footer class="footer">
    <p>Built with Cloudflare Workers. <a href="https://github.com/Aventerica89/cf-url-shortener" target="_blank">View on GitHub</a></p>
    <p class="version">Extension v1.1.0 &middot; <a href="https://github.com/Aventerica89/cf-url-shortener/blob/main/chrome-extension/CHANGELOG.md" target="_blank">Changelog</a></p>
  </footer>
</body>
</html>`;
}

// ============ APP HTML ============

function getAppHtml(userEmail) {
  const safeEmail = escapeHtmlServer(userEmail);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <title>Artifact Manager - Claude Artifacts</title>
  <link rel="icon" type="image/svg+xml" href="${ARTIFACT_MANAGER_FAVICON}">

  <!-- PWA Meta Tags -->
  <link rel="manifest" href="/manifest.json">
  <meta name="theme-color" content="#6366f1">
  <meta name="mobile-web-app-capable" content="yes">

  <!-- iOS PWA Meta Tags -->
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Artifacts">
  <link rel="apple-touch-icon" href="/icon-192.png">

  <!-- Prevent phone number detection -->
  <meta name="format-detection" content="telephone=no">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --background: #09090b;
      --foreground: #fafafa;
      --card: #18181b;
      --card-foreground: #fafafa;
      --popover: #18181b;
      --popover-foreground: #fafafa;
      --primary: #fafafa;
      --primary-foreground: #18181b;
      --secondary: #27272a;
      --secondary-foreground: #fafafa;
      --muted: #27272a;
      --muted-foreground: #a1a1aa;
      --accent: #27272a;
      --accent-foreground: #fafafa;
      --destructive: #7f1d1d;
      --destructive-foreground: #fafafa;
      --border: #27272a;
      --input: #27272a;
      --ring: #d4d4d8;
      --radius: 0.5rem;

      --indigo: #6366f1;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --violet: #8b5cf6;
      --pink: #ec4899;
      --cyan: #06b6d4;

      --success: #10b981;
      --warning: #f59e0b;
      --warning-bg: rgba(245, 158, 11, 0.1);
      --warning-border: rgba(245, 158, 11, 0.2);
      --bg-secondary: #27272a;
      --text-secondary: #a1a1aa;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--background);
      color: var(--foreground);
      min-height: 100vh;
      display: flex;
    }

    /* Sidebar */
    .sidebar {
      width: 280px;
      background: var(--card);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      height: 100vh;
      position: fixed;
      left: 0;
      top: 0;
    }

    .sidebar-header {
      padding: 1.5rem;
      border-bottom: 1px solid var(--border);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 1.25rem;
      font-weight: 600;
    }

    .logo-icon {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--indigo), var(--violet));
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .sidebar-nav {
      flex: 1;
      overflow-y: auto;
      padding: 1rem 0;
    }

    .nav-section {
      margin-bottom: 1.5rem;
    }

    .nav-section-title {
      padding: 0.5rem 1.5rem;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted-foreground);
      letter-spacing: 0.05em;
    }

    .nav-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.625rem 1.5rem;
      color: var(--muted-foreground);
      cursor: pointer;
      transition: all 0.15s;
      font-size: 0.875rem;
    }

    .nav-item:hover {
      background: var(--accent);
      color: var(--foreground);
    }

    .nav-item.active {
      background: var(--accent);
      color: var(--foreground);
    }

    .nav-item-count {
      margin-left: auto;
      font-size: 0.75rem;
      background: var(--muted);
      padding: 0.125rem 0.5rem;
      border-radius: 9999px;
    }

    /* Collection share button */
    .collection-nav-item {
      padding: 0.625rem 0.5rem 0.625rem 1.5rem;
      justify-content: space-between;
    }

    .collection-share-btn {
      opacity: 0;
      background: none;
      border: none;
      color: var(--muted-foreground);
      cursor: pointer;
      padding: 0.25rem;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 0.25rem;
      transition: all 0.15s;
    }

    .collection-nav-item:hover .collection-share-btn {
      opacity: 1;
    }

    .collection-share-btn:hover {
      background: var(--accent);
      color: var(--indigo);
    }

    .nav-item.has-actions {
      padding: 0;
    }

    .nav-item-content {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 1rem;
      flex: 1;
      cursor: pointer;
    }

    .nav-item-delete {
      display: none;
      padding: 0.5rem;
      background: none;
      border: none;
      color: var(--muted-foreground);
      cursor: pointer;
      border-radius: var(--radius);
    }

    .nav-item.has-actions:hover .nav-item-delete {
      display: flex;
    }

    .nav-item-delete:hover {
      color: var(--destructive);
      background: var(--destructive-foreground);
    }

    .collection-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .sidebar-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid var(--border);
      font-size: 0.75rem;
      color: var(--muted-foreground);
    }

    .logout-button {
      width: 100%;
      justify-content: flex-start;
      gap: 0.75rem;
    }

    .logout-avatar {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--indigo), var(--violet));
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 600;
    }

    .logout-user-info {
      flex: 1;
      text-align: left;
      min-width: 0;
    }

    .logout-username {
      font-size: 14px;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .logout-email {
      font-size: 11px;
      color: var(--muted-foreground);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .logout-icon {
      opacity: 0.5;
    }

    .hidden-input {
      display: none;
    }

    /* Main Content */
    .main {
      margin-left: 280px;
      flex: 1;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .header {
      padding: 1rem 2rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 1rem;
      background: var(--card);
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .search-box {
      flex: 1;
      max-width: 400px;
      position: relative;
    }

    .search-box input {
      width: 100%;
      padding: 0.5rem 1rem 0.5rem 2.5rem;
      background: var(--secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--foreground);
      font-size: 0.875rem;
    }

    .search-box input:focus {
      outline: none;
      border-color: var(--indigo);
    }

    .search-box svg {
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--muted-foreground);
    }

    .search-box .clear-search {
      position: absolute;
      right: 0.5rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      padding: 0.25rem;
      cursor: pointer;
      color: var(--muted-foreground);
      display: none;
      border-radius: 50%;
    }

    .search-box .clear-search:hover {
      color: var(--foreground);
      background: var(--border);
    }

    .search-box .clear-search.visible {
      display: flex;
    }

    .search-box input {
      padding-right: 2rem;
    }

    .header-actions {
      display: flex;
      gap: 0.5rem;
      margin-left: auto;
    }

    .btn {
      padding: 0.5rem 1rem;
      border-radius: var(--radius);
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
      border: none;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }

    .btn-primary {
      background: var(--indigo);
      color: white;
    }

    .btn-primary:hover {
      background: #4f46e5;
    }

    .btn-secondary {
      background: var(--secondary);
      color: var(--foreground);
      border: 1px solid var(--border);
    }

    .btn-secondary:hover {
      background: var(--accent);
    }

    .btn-ghost {
      background: transparent;
      color: var(--muted-foreground);
    }

    .btn-ghost:hover {
      background: var(--accent);
      color: var(--foreground);
    }

    .btn-sm {
      padding: 0.375rem 0.75rem;
      font-size: 0.75rem;
    }

    .btn-icon {
      padding: 0.5rem;
      width: 36px;
      height: 36px;
      justify-content: center;
    }

    /* Content Area */
    .content {
      flex: 1;
      padding: 2rem;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem;
    }

    .stat-label {
      font-size: 0.75rem;
      color: var(--muted-foreground);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      margin-top: 0.25rem;
    }

    /* Create Form */
    .create-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      margin-bottom: 2rem;
    }

    .create-card h3 {
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 1rem;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
    }

    .form-group.full-width {
      grid-column: 1 / -1;
    }

    .form-group label {
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--muted-foreground);
    }

    .form-group input,
    .form-group select,
    .form-group textarea {
      padding: 0.5rem 0.75rem;
      background: var(--secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--foreground);
      font-size: 0.875rem;
    }

    .form-group input:focus,
    .form-group select:focus,
    .form-group textarea:focus {
      outline: none;
      border-color: var(--indigo);
    }

    .form-group textarea {
      resize: vertical;
      min-height: 80px;
    }

    /* Tags Input */
    .tags-input-container {
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
      padding: 0.375rem;
      background: var(--secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      min-height: 38px;
    }

    .tags-input-container:focus-within {
      border-color: var(--indigo);
    }

    .tags-input-container input {
      flex: 1;
      min-width: 100px;
      padding: 0.25rem;
      background: transparent;
      border: none;
      color: var(--foreground);
      font-size: 0.875rem;
    }

    .tags-input-container input:focus {
      outline: none;
    }

    .tag-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      padding: 0.125rem 0.5rem;
      background: var(--indigo);
      color: white;
      border-radius: 9999px;
      font-size: 0.75rem;
    }

    .tag-badge button {
      background: none;
      border: none;
      color: white;
      cursor: pointer;
      padding: 0;
      display: flex;
      opacity: 0.7;
    }

    .tag-badge button:hover {
      opacity: 1;
    }

    .tag-suggestions {
      position: absolute;
      top: 100%;
      left: 0;
      right: 0;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-top: 0.25rem;
      max-height: 200px;
      overflow-y: auto;
      z-index: 100;
      display: none;
    }

    .tag-suggestions.visible {
      display: block;
    }

    .tag-suggestion {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.5rem 0.75rem;
      cursor: pointer;
      font-size: 0.875rem;
    }

    .tag-suggestion:hover,
    .tag-suggestion.focused {
      background: var(--secondary);
    }

    .tag-suggestion .tag-name {
      color: var(--foreground);
    }

    .tag-suggestion .tag-count {
      color: var(--muted-foreground);
      font-size: 0.75rem;
    }

    /* Artifacts Grid */
    .artifacts-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }

    .artifacts-header h2 {
      font-size: 1.25rem;
      font-weight: 600;
    }

    .view-toggle {
      display: flex;
      background: var(--secondary);
      border-radius: var(--radius);
      padding: 0.25rem;
    }

    .view-toggle button {
      padding: 0.375rem 0.75rem;
      background: transparent;
      border: none;
      color: var(--muted-foreground);
      cursor: pointer;
      border-radius: calc(var(--radius) - 2px);
    }

    .view-toggle button.active {
      background: var(--card);
      color: var(--foreground);
    }

    .artifacts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 1rem;
    }

    .artifact-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      transition: all 0.15s;
    }

    .artifact-card:hover {
      border-color: var(--indigo);
    }

    .artifact-card-header {
      padding: 1rem;
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
    }

    .artifact-icon {
      width: 40px;
      height: 40px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .artifact-icon.code { background: rgba(16, 185, 129, 0.15); color: var(--emerald); }
    .artifact-icon.html { background: rgba(99, 102, 241, 0.15); color: var(--indigo); }
    .artifact-icon.document { background: rgba(245, 158, 11, 0.15); color: var(--amber); }
    .artifact-icon.image { background: rgba(236, 72, 153, 0.15); color: var(--pink); }
    .artifact-icon.data { background: rgba(6, 182, 212, 0.15); color: var(--cyan); }
    .artifact-icon.other { background: rgba(139, 92, 246, 0.15); color: var(--violet); }

    .artifact-info {
      flex: 1;
      min-width: 0;
    }

    .artifact-name {
      font-weight: 600;
      font-size: 0.9375rem;
      margin-bottom: 0.25rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .artifact-meta {
      font-size: 0.75rem;
      color: var(--muted-foreground);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .artifact-actions {
      display: flex;
      gap: 0.25rem;
    }

    .artifact-card-body {
      padding: 0 1rem 1rem;
    }

    .artifact-description {
      font-size: 0.8125rem;
      color: var(--muted-foreground);
      margin-bottom: 0.75rem;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }

    .artifact-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
    }

    .artifact-tag {
      padding: 0.125rem 0.5rem;
      background: var(--secondary);
      border-radius: 9999px;
      font-size: 0.6875rem;
      color: var(--muted-foreground);
    }

    .artifact-card-actions {
      padding: 0.75rem 1rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      border-top: 1px solid var(--border);
    }

    .artifact-card-actions .btn {
      flex: 1;
      min-width: fit-content;
      justify-content: center;
    }

    .artifact-card-footer {
      padding: 0.75rem 1rem;
      border-top: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.75rem;
      color: var(--muted-foreground);
    }

    .collection-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.5rem;
      background: var(--secondary);
      border-radius: var(--radius);
    }

    .favorite-btn {
      background: none;
      border: none;
      cursor: pointer;
      color: var(--muted-foreground);
      padding: 0.25rem;
      display: flex;
    }

    .favorite-btn.active {
      color: var(--amber);
    }

    /* Source Badge */
    .source-badge {
      padding: 0.125rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.6875rem;
      font-weight: 500;
    }

    .source-badge.published {
      background: rgba(99, 102, 241, 0.15);
      color: var(--indigo);
    }

    .source-badge.downloaded {
      background: rgba(16, 185, 129, 0.15);
      color: var(--emerald);
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      visibility: hidden;
      transition: all 0.2s;
    }

    .modal-overlay.active {
      opacity: 1;
      visibility: visible;
    }

    .modal {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      transform: scale(0.95);
      transition: transform 0.2s;
    }

    .modal-overlay.active .modal {
      transform: scale(1);
    }

    .modal-header {
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .modal-header h3 {
      font-size: 1.125rem;
      font-weight: 600;
    }

    .modal-body {
      padding: 1.5rem;
    }

    .modal-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
    }

    /* Toast */
    .toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 200;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .toast {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
      animation: slideIn 0.2s ease;
    }

    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }

    .toast.success { border-left: 3px solid var(--emerald); }
    .toast.error { border-left: 3px solid var(--rose); }

    /* Spinner */
    .spinner {
      width: 24px;
      height: 24px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: var(--indigo);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: inline-block;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: var(--muted-foreground);
    }

    .empty-state svg {
      width: 64px;
      height: 64px;
      margin-bottom: 1rem;
      opacity: 0.5;
    }

    .empty-state h3 {
      font-size: 1.125rem;
      font-weight: 600;
      color: var(--foreground);
      margin-bottom: 0.5rem;
    }

    /* Pagination */
    .pagination {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 2rem;
    }

    .pagination button {
      padding: 0.5rem 0.75rem;
      background: var(--secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--foreground);
      cursor: pointer;
      font-size: 0.875rem;
    }

    .pagination button:hover:not(:disabled) {
      background: var(--accent);
    }

    .pagination button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .pagination button.active {
      background: var(--indigo);
      border-color: var(--indigo);
    }

    /* Filter Pills */
    .filter-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .filter-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.375rem 0.75rem;
      background: var(--secondary);
      border: 1px solid var(--border);
      border-radius: 9999px;
      font-size: 0.75rem;
      color: var(--muted-foreground);
    }

    .filter-pill button {
      background: none;
      border: none;
      color: var(--muted-foreground);
      cursor: pointer;
      padding: 0;
      display: flex;
    }

    .filter-pill button:hover {
      color: var(--foreground);
    }

    /* Mobile Menu Button */
    .mobile-menu-btn {
      display: none;
      padding: 0.5rem;
      background: none;
      border: none;
      color: var(--foreground);
      cursor: pointer;
      border-radius: var(--radius);
      min-width: 44px;
      min-height: 44px;
      align-items: center;
      justify-content: center;
    }

    .mobile-menu-btn:hover {
      background: var(--accent);
    }

    /* Mobile Overlay */
    .mobile-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.5);
      z-index: 40;
      opacity: 0;
      transition: opacity 0.2s ease;
    }

    .mobile-overlay.active {
      opacity: 1;
    }

    /* Safe area insets for iOS */
    @supports (padding: env(safe-area-inset-top)) {
      .header {
        padding-top: calc(1rem + env(safe-area-inset-top));
      }
      .sidebar {
        padding-top: env(safe-area-inset-top);
        padding-bottom: env(safe-area-inset-bottom);
      }
      .content {
        padding-bottom: calc(2rem + env(safe-area-inset-bottom));
      }
    }

    /* Responsive - Tablet */
    @media (max-width: 1024px) {
      .stats-grid {
        grid-template-columns: repeat(3, 1fr);
      }

      .artifacts-grid {
        grid-template-columns: repeat(2, 1fr);
      }

      .header-actions .btn span {
        display: none;
      }

      .header-actions .btn {
        padding: 0.5rem;
      }
    }

    /* Responsive - Mobile */
    @media (max-width: 768px) {
      .mobile-menu-btn {
        display: flex;
      }

      .mobile-overlay {
        display: block;
      }

      .sidebar {
        transform: translateX(-100%);
        z-index: 50;
        transition: transform 0.3s ease;
        width: 85%;
        max-width: 320px;
      }

      .sidebar.open {
        transform: translateX(0);
      }

      .main {
        margin-left: 0;
      }

      .header {
        padding: 0.75rem 1rem;
        gap: 0.5rem;
      }

      .search-box {
        max-width: none;
        flex: 1;
      }

      .search-box input {
        font-size: 16px; /* Prevents iOS zoom on focus */
      }

      .header-actions {
        gap: 0.25rem;
      }

      .header-actions .btn-secondary {
        display: none;
      }

      .content {
        padding: 1rem;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 0.75rem;
      }

      .stat-card {
        padding: 1rem;
      }

      .stat-value {
        font-size: 1.5rem;
      }

      .artifacts-grid {
        grid-template-columns: 1fr;
        gap: 0.75rem;
      }

      .artifacts-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.75rem;
      }

      .artifacts-header > div {
        width: 100%;
      }

      .artifacts-header select {
        flex: 1;
      }

      /* Touch-friendly nav items */
      .nav-item {
        padding: 0.875rem 1.5rem;
        min-height: 48px;
      }

      .nav-item-content {
        padding: 0.75rem 1rem;
      }

      /* Modal improvements */
      .modal {
        width: 95%;
        max-width: none;
        margin: 1rem;
        max-height: calc(100vh - 2rem);
      }

      .modal-body {
        max-height: calc(100vh - 12rem);
      }

      .form-grid {
        gap: 0.75rem;
      }

      .form-group input,
      .form-group select,
      .form-group textarea {
        font-size: 16px; /* Prevents iOS zoom */
        padding: 0.75rem;
      }

      /* Artifact card touch improvements */
      .artifact-card {
        -webkit-tap-highlight-color: transparent;
      }

      .artifact-actions {
        opacity: 1; /* Always visible on mobile */
      }

      .artifact-actions button {
        min-width: 44px;
        min-height: 44px;
        padding: 0.5rem;
      }

      /* Filter pills scroll horizontally */
      .filter-pills {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        padding-bottom: 0.5rem;
        flex-wrap: nowrap;
      }

      .filter-pill {
        flex-shrink: 0;
      }
    }

    /* Small mobile */
    @media (max-width: 375px) {
      .stats-grid {
        grid-template-columns: 1fr 1fr;
      }

      .stat-card {
        padding: 0.75rem;
      }

      .stat-label {
        font-size: 0.65rem;
      }

      .stat-value {
        font-size: 1.25rem;
      }
    }

    /* Touch device improvements */
    @media (hover: none) and (pointer: coarse) {
      .artifact-actions {
        opacity: 1;
      }

      .nav-item-delete {
        display: flex;
        opacity: 0.5;
      }

      .btn, button {
        min-height: 44px;
      }

      .artifact-card:active {
        transform: scale(0.98);
      }
    }

    /* Standalone PWA mode */
    @media (display-mode: standalone) {
      body {
        padding-top: env(safe-area-inset-top);
      }
    }
  </style>
</head>
<body>
  <!-- Mobile Overlay -->
  <div class="mobile-overlay" id="mobile-overlay" onclick="closeMobileMenu()"></div>

  <!-- Sidebar -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-header">
      <div class="logo">
        <div class="logo-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
            <polyline points="7.5 4.21 12 6.81 16.5 4.21"/>
            <polyline points="7.5 19.79 7.5 14.6 3 12"/>
            <polyline points="21 12 16.5 14.6 16.5 19.79"/>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
            <line x1="12" y1="22.08" x2="12" y2="12"/>
          </svg>
        </div>
        Artifact Manager
      </div>
    </div>

    <nav class="sidebar-nav">
      <div class="nav-section">
        <div class="nav-section-title">Library</div>
        <div class="nav-item active" data-filter="all" onclick="setFilter('all')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7"/>
            <rect x="14" y="3" width="7" height="7"/>
            <rect x="14" y="14" width="7" height="7"/>
            <rect x="3" y="14" width="7" height="7"/>
          </svg>
          All Artifacts
          <span class="nav-item-count" id="count-all">0</span>
        </div>
        <div class="nav-item" data-filter="favorites" onclick="setFilter('favorites')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
          </svg>
          Favorites
          <span class="nav-item-count" id="count-favorites">0</span>
        </div>
        <div class="nav-item" data-filter="published" onclick="setFilter('published')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          Published
          <span class="nav-item-count" id="count-published">0</span>
        </div>
        <div class="nav-item" data-filter="downloaded" onclick="setFilter('downloaded')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Downloaded
          <span class="nav-item-count" id="count-downloaded">0</span>
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-section-title">Collections</div>
        <div id="collections-nav"></div>
      </div>

      <div class="nav-section">
        <div class="nav-section-title">Popular Tags</div>
        <div id="tags-nav"></div>
      </div>
    </nav>

    <div class="sidebar-footer">
      <button class="btn btn-ghost logout-button" id="logoutBtn">
        <div class="logout-avatar">${safeEmail.charAt(0).toUpperCase()}</div>
        <div class="logout-user-info">
          <div class="logout-username">${safeEmail.split('@')[0]}</div>
          <div class="logout-email">${safeEmail}</div>
        </div>
        <svg class="logout-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" x2="9" y1="12" y2="12"/>
        </svg>
      </button>
    </div>
  </aside>

  <!-- Main Content -->
  <main class="main">
    <header class="header">
      <!-- Mobile Menu Button -->
      <button class="mobile-menu-btn" id="mobile-menu-btn" onclick="toggleMobileMenu()" aria-label="Open menu">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="3" y1="6" x2="21" y2="6"/>
          <line x1="3" y1="12" x2="21" y2="12"/>
          <line x1="3" y1="18" x2="21" y2="18"/>
        </svg>
      </button>

      <div class="search-box">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input type="text" placeholder="Search..." id="search-input" aria-label="Search artifacts">
        <button class="clear-search" id="clear-search" onclick="clearSearch()" title="Clear search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary" id="cleanupBtn" title="Cleanup placeholder names">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
          </svg>
          <span>Cleanup</span>
        </button>
        <button class="btn btn-secondary" id="exportBtn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          <span>Export</span>
        </button>
        <button class="btn btn-secondary" id="importBtn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          <span>Import</span>
        </button>
        <input type="file" id="import-input" accept=".json" class="hidden-input">
        <button class="btn btn-primary" id="addArtifactBtn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          <span>Add</span>
        </button>
      </div>
    </header>

    <div class="content">
      <!-- Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Artifacts</div>
          <div class="stat-value" id="stat-total">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Published</div>
          <div class="stat-value" id="stat-published">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Downloaded</div>
          <div class="stat-value" id="stat-downloaded">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Collections</div>
          <div class="stat-value" id="stat-collections">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Tags</div>
          <div class="stat-value" id="stat-tags">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Favorites</div>
          <div class="stat-value" id="stat-favorites">0</div>
        </div>
      </div>

      <!-- Active Filters -->
      <div class="filter-pills" id="active-filters"></div>

      <!-- Artifacts -->
      <div class="artifacts-header">
        <h2 id="artifacts-title">All Artifacts</h2>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <select id="type-filter" onchange="loadArtifacts()">
            <option value="">All Types</option>
            <option value="code">Code</option>
            <option value="html">HTML/Web App</option>
            <option value="document">Document</option>
            <option value="image">Image</option>
            <option value="data">Data/Analysis</option>
            <option value="other">Other</option>
          </select>
          <select id="sort-select" onchange="loadArtifacts()">
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="name">Name (A-Z)</option>
            <option value="updated">Recently Updated</option>
            <option value="type">By Type</option>
          </select>
        </div>
      </div>

      <div class="artifacts-grid" id="artifacts-grid"></div>

      <div class="pagination" id="pagination"></div>
    </div>
  </main>

  <!-- Create/Edit Modal -->
  <div class="modal-overlay" id="artifact-modal">
    <div class="modal">
      <div class="modal-header">
        <h3 id="modal-title">Add New Artifact</h3>
        <button class="btn btn-ghost btn-icon" onclick="closeModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <form id="artifact-form">
          <input type="hidden" id="edit-id">
          <div class="form-grid">
            <div class="form-group full-width">
              <label>Name *</label>
              <input type="text" id="artifact-name" required placeholder="My Awesome Artifact">
            </div>

            <div class="form-group">
              <label>Source Type</label>
              <select id="artifact-source">
                <option value="published">Published (URL)</option>
                <option value="downloaded">Downloaded (Local)</option>
              </select>
            </div>

            <div class="form-group">
              <label>Artifact Type</label>
              <select id="artifact-type">
                <option value="code">Code</option>
                <option value="html">HTML/Web App</option>
                <option value="document">Document</option>
                <option value="image">Image</option>
                <option value="data">Data/Analysis</option>
                <option value="other">Other</option>
              </select>
            </div>

            <div class="form-group full-width" id="url-group">
              <label>Published URL</label>
              <input type="url" id="artifact-url" placeholder="https://claude.site/artifacts/...">
            </div>

            <div class="form-group" id="filename-group" style="display: none;">
              <label>File Name</label>
              <input type="text" id="artifact-filename" placeholder="component.tsx">
            </div>

            <div class="form-group full-width" id="content-group" style="display: none;">
              <label>HTML/Code Content</label>
              <textarea id="artifact-content" rows="10" placeholder="Paste your HTML or code here..." style="font-family: monospace; font-size: 0.8125rem;"></textarea>
            </div>

            <div class="form-group full-width">
              <label>Description</label>
              <textarea id="artifact-description" placeholder="What does this artifact do?"></textarea>
            </div>

            <div class="form-group">
              <label>Collection</label>
              <select id="artifact-collection">
                <option value="">No Collection</option>
              </select>
            </div>

            <div class="form-group">
              <label>Language/Framework</label>
              <input type="text" id="artifact-language" placeholder="React, Python, etc.">
            </div>

            <div class="form-group full-width" style="position: relative;">
              <label>Tags (press Enter to add)</label>
              <div class="tags-input-container" id="tags-container">
                <input type="text" id="tags-input" placeholder="Add tags..." autocomplete="off">
              </div>
              <div class="tag-suggestions" id="tag-suggestions"></div>
            </div>

            <div class="form-group full-width">
              <label>Conversation URL</label>
              <input type="url" id="artifact-conversation" placeholder="https://claude.ai/chat/...">
            </div>

            <div class="form-group full-width">
              <label>Notes</label>
              <textarea id="artifact-notes" placeholder="Personal notes about this artifact..."></textarea>
            </div>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button class="btn btn-primary" onclick="saveArtifact()">Save Artifact</button>
      </div>
    </div>
  </div>

  <!-- Collection Modal -->
  <div class="modal-overlay" id="collection-modal">
    <div class="modal" style="max-width: 400px;">
      <div class="modal-header">
        <h3>Create Collection</h3>
        <button class="btn btn-ghost btn-icon" onclick="closeCollectionModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>Collection Name</label>
          <input type="text" id="collection-name" placeholder="My Collection">
        </div>
        <div class="form-group" style="margin-top: 1rem;">
          <label>Color</label>
          <input type="color" id="collection-color" value="#6366f1" style="width: 100%; height: 40px; cursor: pointer;">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeCollectionModal()">Cancel</button>
        <button class="btn btn-primary" onclick="createCollection()">Create</button>
      </div>
    </div>
  </div>

  <!-- Cleanup Utility Modal -->
  <div class="modal-overlay" id="cleanup-modal">
    <div class="modal" style="max-width: 600px;">
      <div class="modal-header">
        <h3>Cleanup Placeholder Names</h3>
        <button class="btn btn-ghost btn-icon" onclick="closeCleanupModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body" id="cleanup-body">
        <div style="text-align: center; padding: 2rem;">
          <div class="spinner"></div>
          <p style="margin-top: 1rem; color: var(--text-secondary);">Scanning for placeholder names...</p>
        </div>
      </div>
      <div class="modal-footer" id="cleanup-footer" style="display: none;">
        <button class="btn btn-secondary" onclick="closeCleanupModal()">Close</button>
        <button class="btn btn-primary" onclick="fixPlaceholders()" id="fix-btn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.5rem;">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
          </svg>
          Fix All Names
        </button>
      </div>
    </div>
  </div>

  <!-- Share Collection Modal -->
  <div class="modal-overlay" id="share-modal">
    <div class="modal" style="max-width: 500px;">
      <div class="modal-header">
        <h3>Share Collection</h3>
        <button class="btn btn-ghost btn-icon" onclick="closeShareModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <p style="margin-bottom: 1.5rem;">Share "<strong id="share-collection-name"></strong>" publicly. Anyone with the link will be able to view this collection.</p>

        <div id="share-url-container" style="display: none; margin-bottom: 1.5rem;">
          <label style="display: block; font-weight: 500; margin-bottom: 0.5rem; color: var(--text-primary);">Public URL</label>
          <div style="display: flex; gap: 0.5rem;">
            <input type="text" id="share-url" readonly style="flex: 1; background: var(--secondary); font-family: monospace; font-size: 0.875rem;" />
            <button class="btn btn-secondary" onclick="copyShareUrl()">Copy</button>
          </div>
          <p style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-secondary);">This link allows anyone to view your collection without signing in.</p>
        </div>

        <div id="share-settings" style="display: none;">
          <div class="form-group">
            <label>
              <input type="checkbox" id="share-show-thumbnails" checked />
              <span style="margin-left: 0.5rem;">Show artifact previews</span>
            </label>
          </div>

          <div class="form-group">
            <label style="display: block; font-weight: 500; margin-bottom: 0.5rem;">Layout Style</label>
            <select id="share-layout" style="width: 100%;">
              <option value="grouped">Grouped by Tags (Recommended)</option>
              <option value="grid">Grid View</option>
              <option value="list">List View</option>
            </select>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeShareModal()">Close</button>
        <button class="btn btn-primary" id="enable-sharing-btn" onclick="enableSharing()">Enable Sharing</button>
        <button class="btn btn-danger" id="disable-sharing-btn" onclick="disableSharing()" style="display: none;">Stop Sharing</button>
      </div>
    </div>
  </div>

  <!-- Content Viewer Modal -->
  <div class="modal-overlay" id="content-modal">
    <div class="modal" style="max-width: 900px; max-height: 90vh;">
      <div class="modal-header">
        <h3 id="content-modal-title">View Artifact</h3>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <button class="btn btn-secondary btn-sm" onclick="copyContent()" title="Copy to clipboard">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            Copy
          </button>
          <button class="btn btn-ghost btn-icon" onclick="closeContentModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
      </div>
      <div class="modal-body" style="padding: 0; overflow: hidden;">
        <div id="content-viewer-info" style="padding: 1rem; background: var(--secondary); border-bottom: 1px solid var(--border);">
          <div style="display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem;">
            <span id="content-viewer-type"></span>
            <span id="content-viewer-language"></span>
            <a id="content-viewer-claude" href="#" target="_blank" style="color: var(--indigo); text-decoration: none;">Open in Claude</a>
            <a id="content-viewer-published" href="#" target="_blank" style="color: var(--emerald); text-decoration: none;">View Published</a>
          </div>
        </div>
        <div id="content-viewer-preview" style="display: none; height: 400px; border-bottom: 1px solid var(--border);">
          <iframe id="content-preview-iframe" sandbox="allow-scripts" style="width: 100%; height: 100%; border: none; background: white;"></iframe>
        </div>
        <pre id="content-viewer-code" style="margin: 0; padding: 1rem; overflow: auto; max-height: 500px; background: var(--background); font-size: 0.8125rem; line-height: 1.5;"><code id="content-viewer-text"></code></pre>
      </div>
      <div class="modal-footer">
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary" id="toggle-preview-btn" onclick="togglePreview()" style="display: none;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
            Toggle Preview
          </button>
          <button class="btn btn-secondary" id="open-new-tab-btn" onclick="openInNewTab()" style="display: none;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              <polyline points="15 3 21 3 21 9"/>
              <line x1="10" y1="14" x2="21" y2="3"/>
            </svg>
            Open in New Tab
          </button>
          <button class="btn btn-secondary" id="share-artifact-btn" onclick="toggleShareArtifact()" style="display: none;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="18" cy="5" r="3"/>
              <circle cx="6" cy="12" r="3"/>
              <circle cx="18" cy="19" r="3"/>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
            </svg>
            <span id="share-btn-text">Share</span>
          </button>
        </div>
        <button class="btn btn-primary" onclick="closeContentModal()">Close</button>
      </div>
    </div>
  </div>

  <!-- Toast Container -->
  <div class="toast-container" id="toast-container"></div>

  <script>
    // Name Validator - prevents placeholder names like "Saving...", "Loading...", etc.
    const NameValidator = {
      placeholderPatterns: [
        "Saving...",
        "Loading...",
        "Untitled",
        "New Artifact",
        "Downloading...",
        ""
      ],

      isPlaceholder(name) {
        const trimmed = (name || '').trim();

        // Check exact matches
        if (this.placeholderPatterns.includes(trimmed)) {
          return true;
        }

        // Check for pattern matches (e.g., "Untitled 1", "Untitled 2")
        if (trimmed.startsWith("Untitled")) {
          return true;
        }

        // Check if name is only whitespace or empty
        if (!trimmed) {
          return true;
        }

        return false;
      },

      sanitize(name, fallback = "Artifact") {
        const trimmed = (name || '').trim();

        if (this.isPlaceholder(trimmed)) {
          return fallback;
        }

        return trimmed;
      },

      generateUniqueName(baseName = "Artifact", existingNames = []) {
        let name = baseName;
        let counter = 1;

        while (existingNames.includes(name)) {
          counter++;
          name = baseName + " " + counter;
        }

        return name;
      }
    };

    // State
    let allArtifacts = [];
    let allCollections = [];
    let allTags = [];
    let currentTags = [];
    let currentPage = 1;
    const perPage = 12;

    let currentFilter = { type: 'all', value: null };

    // Mobile menu functions
    function toggleMobileMenu() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('mobile-overlay');
      const isOpen = sidebar.classList.contains('open');

      if (isOpen) {
        closeMobileMenu();
      } else {
        sidebar.classList.add('open');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
      }
    }

    function closeMobileMenu() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('mobile-overlay');
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
      document.body.style.overflow = '';
    }

    // Close menu when clicking a nav item on mobile
    function handleNavClick(callback) {
      if (typeof window !== 'undefined' && window.innerWidth <= 768) {
        closeMobileMenu();
      }
      if (callback) callback();
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', init);

    async function init() {
      await fetch('/api/init', { method: 'POST' });
      await Promise.all([
        loadStats(),
        loadCollections(),
        loadTags(),
        loadArtifacts()
      ]);

      // Keyboard shortcuts
      document.addEventListener('keydown', (e) => {
        // Search shortcut
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
          e.preventDefault();
          document.getElementById('search-input').focus();
        }
        // Escape to close mobile menu
        if (e.key === 'Escape') {
          closeMobileMenu();
        }
      });

      // Swipe to close mobile menu
      let touchStartX = 0;
      let touchEndX = 0;
      const sidebar = document.getElementById('sidebar');

      sidebar.addEventListener('touchstart', (e) => {
        touchStartX = e.changedTouches[0].screenX;
      }, { passive: true });

      sidebar.addEventListener('touchend', (e) => {
        touchEndX = e.changedTouches[0].screenX;
        const swipeDistance = touchStartX - touchEndX;
        // Swipe left to close
        if (swipeDistance > 50 && sidebar.classList.contains('open')) {
          closeMobileMenu();
        }
      }, { passive: true });

      // Search debounce
      let searchTimeout;
      const searchInput = document.getElementById('search-input');
      const clearBtn = document.getElementById('clear-search');

      searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        // Toggle clear button visibility
        clearBtn.classList.toggle('visible', e.target.value.length > 0);
        searchTimeout = setTimeout(() => {
          loadArtifacts();
        }, 300);
      });

      // Clear search function
      window.clearSearch = function() {
        searchInput.value = '';
        clearBtn.classList.remove('visible');
        loadArtifacts();
        searchInput.focus();
      };

      // Source type toggle
      document.getElementById('artifact-source').addEventListener('change', (e) => {
        const isPublished = e.target.value === 'published';
        document.getElementById('url-group').style.display = isPublished ? 'block' : 'none';
        document.getElementById('filename-group').style.display = isPublished ? 'none' : 'block';
        document.getElementById('content-group').style.display = isPublished ? 'none' : 'block';
      });

      // Tags input
      setupTagsInput();

      // Logout button
      document.getElementById('logoutBtn').addEventListener('click', function() {
        window.location.href = '/cdn-cgi/access/logout';
      });

      // Header action buttons
      document.getElementById('cleanupBtn').addEventListener('click', openCleanupModal);
      document.getElementById('exportBtn').addEventListener('click', exportData);
      document.getElementById('importBtn').addEventListener('click', function() {
        document.getElementById('import-input').click();
      });
      document.getElementById('import-input').addEventListener('change', importData);
      document.getElementById('addArtifactBtn').addEventListener('click', openCreateModal);
    }

    async function loadStats() {
      const stats = await fetch('/api/stats').then(r => r.json());
      document.getElementById('stat-total').textContent = stats.total_artifacts || 0;
      document.getElementById('stat-published').textContent = stats.published_count || 0;
      document.getElementById('stat-downloaded').textContent = stats.downloaded_count || 0;
      document.getElementById('stat-collections').textContent = stats.total_collections || 0;
      document.getElementById('stat-tags').textContent = stats.total_tags || 0;
      document.getElementById('stat-favorites').textContent = stats.favorites_count || 0;

      document.getElementById('count-all').textContent = stats.total_artifacts || 0;
      document.getElementById('count-favorites').textContent = stats.favorites_count || 0;
      document.getElementById('count-published').textContent = stats.published_count || 0;
      document.getElementById('count-downloaded').textContent = stats.downloaded_count || 0;
    }

    async function loadCollections() {
      allCollections = await fetch('/api/collections').then(r => r.json());
      renderCollectionsNav();
      renderCollectionsSelect();
    }

    function renderCollectionsNav() {
      const nav = document.getElementById('collections-nav');
      nav.innerHTML = allCollections.map(c => \`
        <div class="nav-item collection-nav-item" data-filter="collection" data-value="\${escapeAttr(c.slug)}">
          <div style="display: flex; align-items: center; flex: 1; cursor: pointer;" onclick="setFilter('collection', '\${escapeAttr(c.slug)}')">
            <div class="collection-dot" style="background: \${safeColor(c.color)}"></div>
            \${escapeHtml(c.name)}
            <span class="nav-item-count">\${c.artifact_count || 0}</span>
          </div>
          <button class="collection-share-btn" onclick="event.stopPropagation(); openShareModal('\${escapeAttr(c.slug)}')" title="Share collection">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="18" cy="5" r="3"/>
              <circle cx="6" cy="12" r="3"/>
              <circle cx="18" cy="19" r="3"/>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
            </svg>
          </button>
        </div>
      \`).join('') + \`
        <div class="nav-item" onclick="openCollectionModal()" style="color: var(--indigo);">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          New Collection
        </div>
      \`;
    }

    function renderCollectionsSelect() {
      const select = document.getElementById('artifact-collection');
      select.innerHTML = '<option value="">No Collection</option>' +
        allCollections.map(c => \`<option value="\${escapeAttr(c.id)}">\${escapeHtml(c.name)}</option>\`).join('');
    }

    async function loadTags() {
      allTags = await fetch('/api/tags').then(r => r.json());
      renderTagsNav();
    }

    function renderTagsNav() {
      const nav = document.getElementById('tags-nav');
      const topTags = allTags.slice(0, 8);
      nav.innerHTML = topTags.map(t => \`
        <div class="nav-item has-actions" data-filter="tag" data-value="\${escapeAttr(t.name)}">
          <div class="nav-item-content" onclick="setFilter('tag', '\${escapeAttr(t.name)}')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/>
              <line x1="7" y1="7" x2="7.01" y2="7"/>
            </svg>
            \${escapeHtml(t.name)}
            <span class="nav-item-count">\${t.usage_count || 0}</span>
          </div>
          <button class="nav-item-delete" onclick="event.stopPropagation(); deleteTag('\${escapeAttr(t.name)}')" title="Delete tag">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
          </button>
        </div>
      \`).join('');
    }

    async function loadArtifacts() {
      const sort = document.getElementById('sort-select').value;
      const search = document.getElementById('search-input').value;
      const typeFilter = document.getElementById('type-filter').value;

      let url = \`/api/artifacts?sort=\${sort}\`;

      if (search) url += \`&search=\${encodeURIComponent(search)}\`;
      if (typeFilter) url += \`&type=\${encodeURIComponent(typeFilter)}\`;

      if (currentFilter.type === 'collection') {
        url += \`&collection=\${currentFilter.value}\`;
      } else if (currentFilter.type === 'tag') {
        url += \`&tag=\${encodeURIComponent(currentFilter.value)}\`;
      } else if (currentFilter.type === 'published') {
        url += '&source=published';
      } else if (currentFilter.type === 'downloaded') {
        url += '&source=downloaded';
      } else if (currentFilter.type === 'favorites') {
        url += '&favorite=true';
      }

      allArtifacts = await fetch(url).then(r => r.json());
      currentPage = 1;
      renderArtifacts();
      updateActiveFilters();
    }

    function renderArtifacts() {
      const grid = document.getElementById('artifacts-grid');
      const start = (currentPage - 1) * perPage;
      const pageArtifacts = allArtifacts.slice(start, start + perPage);

      if (allArtifacts.length === 0) {
        const searchValue = document.getElementById('search-input').value;
        const typeFilter = document.getElementById('type-filter').value;
        const hasFilters = searchValue || typeFilter || currentFilter.type !== 'all';

        if (hasFilters) {
          // Show "no results" message when filtering/searching
          let message = 'No artifacts found';
          if (searchValue) {
            message = \`No artifacts found for "\${escapeHtml(searchValue)}"\`;
          } else if (typeFilter) {
            message = \`No \${typeFilter} artifacts found\`;
          } else if (currentFilter.type !== 'all') {
            message = \`No artifacts in this \${currentFilter.type}\`;
          }

          grid.innerHTML = \`
            <div class="empty-state" style="grid-column: 1 / -1;">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <h3>\${message}</h3>
              <p>Try adjusting your search or filters</p>
              <button class="btn btn-secondary" onclick="resetFilters()" style="margin-top: 1rem;">Clear Filters</button>
            </div>
          \`;
        } else {
          // Show "no artifacts yet" message when empty
          grid.innerHTML = \`
            <div class="empty-state" style="grid-column: 1 / -1;">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              </svg>
              <h3>No artifacts yet</h3>
              <p>Add your first artifact to get started</p>
            </div>
          \`;
        }
        document.getElementById('pagination').innerHTML = '';
        return;
      }

      grid.innerHTML = pageArtifacts.map(a => \`
        <div class="artifact-card">
          <div class="artifact-card-header">
            <div class="artifact-icon \${a.artifact_type}">
              \${getTypeIcon(a.artifact_type)}
            </div>
            <div class="artifact-info">
              <div class="artifact-name">\${escapeHtml(a.name)}</div>
              <div class="artifact-meta">
                <span class="source-badge \${a.source_type}">\${a.source_type}</span>
                \${a.language ? \`<span>\${escapeHtml(a.language)}</span>\` : ''}
              </div>
            </div>
            <div class="artifact-actions">
              <button class="favorite-btn \${a.is_favorite ? 'active' : ''}" onclick="toggleFavorite(\${a.id})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="\${a.is_favorite ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
                  <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                </svg>
              </button>
            </div>
          </div>
          <div class="artifact-card-body">
            \${a.description ? \`<div class="artifact-description">\${escapeHtml(a.description)}</div>\` : ''}
            \${a.tags && a.tags.length > 0 ? \`
              <div class="artifact-tags">
                \${a.tags.map(t => \`<span class="artifact-tag">\${escapeHtml(t)}</span>\`).join('')}
              </div>
            \` : ''}
          </div>
          <div class="artifact-card-actions">
            \${a.conversation_url ? \`
              <a href="\${escapeAttr(a.conversation_url)}" target="_blank" class="btn btn-secondary btn-sm" title="Open conversation in Claude">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
                Claude
              </a>
            \` : ''}
            \${a.published_url ? \`
              <a href="\${escapeAttr(a.published_url)}" target="_blank" class="btn btn-secondary btn-sm" title="View published artifact">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="2" y1="12" x2="22" y2="12"/>
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                Published
              </a>
            \` : ''}
            \${a.file_content ? \`
              <button class="btn btn-primary btn-sm" onclick="viewContent(\${a.id})" title="View artifact content">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
                View
              </button>
            \` : ''}
          </div>
          <div class="artifact-card-footer">
            <div>
              \${a.collection_name ? \`
                <span class="collection-badge">
                  <span class="collection-dot" style="background: \${safeColor(a.collection_color)}; width: 6px; height: 6px;"></span>
                  \${escapeHtml(a.collection_name)}
                </span>
              \` : '<span style="color: var(--muted-foreground)">No collection</span>'}
            </div>
            <div style="display: flex; gap: 0.5rem;">
              <button class="btn btn-ghost btn-sm" onclick="openEditModal(\${a.id})">Edit</button>
              <button class="btn btn-ghost btn-sm" onclick="deleteArtifact(\${a.id})" style="color: var(--rose);">Delete</button>
            </div>
          </div>
        </div>
      \`).join('');

      renderPagination();
    }

    function renderPagination() {
      const totalPages = Math.ceil(allArtifacts.length / perPage);
      if (totalPages <= 1) {
        document.getElementById('pagination').innerHTML = '';
        return;
      }

      let html = \`<button \${currentPage === 1 ? 'disabled' : ''} onclick="goToPage(\${currentPage - 1})">Prev</button>\`;

      for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= currentPage - 1 && i <= currentPage + 1)) {
          html += \`<button class="\${i === currentPage ? 'active' : ''}" onclick="goToPage(\${i})">\${i}</button>\`;
        } else if (i === currentPage - 2 || i === currentPage + 2) {
          html += '<span style="padding: 0 0.5rem;">...</span>';
        }
      }

      html += \`<button \${currentPage === totalPages ? 'disabled' : ''} onclick="goToPage(\${currentPage + 1})">Next</button>\`;

      document.getElementById('pagination').innerHTML = html;
    }

    function goToPage(page) {
      currentPage = page;
      renderArtifacts();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function setFilter(type, value = null) {
      currentFilter = { type, value };

      // Close mobile menu if open
      if (typeof window !== 'undefined' && window.innerWidth <= 768) {
        closeMobileMenu();
      }

      // Update nav active state
      document.querySelectorAll('.nav-item').forEach(item => {
        const itemFilter = item.dataset.filter;
        const itemValue = item.dataset.value;
        if (itemFilter === type && (!value || itemValue === value)) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });

      // Update title
      const titles = {
        all: 'All Artifacts',
        favorites: 'Favorites',
        published: 'Published Artifacts',
        downloaded: 'Downloaded Artifacts',
        collection: \`Collection: \${value}\`,
        tag: \`Tag: \${value}\`
      };
      document.getElementById('artifacts-title').textContent = titles[type] || 'Artifacts';

      loadArtifacts();
    }

    function updateActiveFilters() {
      const container = document.getElementById('active-filters');

      if (currentFilter.type === 'all') {
        container.innerHTML = '';
        return;
      }

      container.innerHTML = \`
        <div class="filter-pill">
          \${escapeHtml(currentFilter.type)}: \${escapeHtml(currentFilter.value || currentFilter.type)}
          <button onclick="setFilter('all')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
      \`;
    }

    function resetFilters() {
      // Clear search
      document.getElementById('search-input').value = '';
      document.getElementById('clear-search').classList.remove('visible');

      // Reset type filter
      document.getElementById('type-filter').value = '';

      // Reset sidebar filter to "all"
      setFilter('all');
    }

    function getTypeIcon(type) {
      const icons = {
        code: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        html: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        document: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
        image: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
        data: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
        other: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>'
      };
      return icons[type] || icons.other;
    }

    function escapeHtml(text) {
      if (!text) return '';
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    // Escape for use in JavaScript string literals (onclick handlers, etc.)
    function escapeAttr(text) {
      if (!text) return '';
      return String(text)
        .replace(/\\\\/g, '\\\\\\\\')
        .replace(/'/g, "\\\\'")
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    }

    // Validate and sanitize color values (prevents CSS injection)
    function safeColor(color) {
      if (!color) return '#6366f1';
      // Only allow valid hex colors
      const hexPattern = /^#([0-9a-fA-F]{3}){1,2}$/;
      return hexPattern.test(color) ? color : '#6366f1';
    }

    // Tags Input
    function setupTagsInput() {
      const input = document.getElementById('tags-input');

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
          e.preventDefault();
          // If a suggestion is focused, select it
          if (focusedSuggestionIndex >= 0 && input.dataset.focusedTag) {
            selectTagSuggestion(input.dataset.focusedTag);
            delete input.dataset.focusedTag;
            return;
          }
          const tag = input.value.trim().replace(',', '');
          if (tag && !currentTags.includes(tag)) {
            currentTags.push(tag);
            renderCurrentTags();
          }
          input.value = '';
          hideTagSuggestions();
        } else if (e.key === 'Backspace' && !input.value && currentTags.length > 0) {
          currentTags.pop();
          renderCurrentTags();
        } else if (e.key === 'Escape') {
          hideTagSuggestions();
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          focusNextSuggestion();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          focusPrevSuggestion();
        }
      });

      // Handle paste - split comma-separated tags
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pastedText = (e.clipboardData || window.clipboardData).getData('text');
        const tags = pastedText.split(/[,;\\n]+/).map(t => t.trim()).filter(t => t);

        tags.forEach(tag => {
          if (tag && !currentTags.includes(tag)) {
            currentTags.push(tag);
          }
        });

        renderCurrentTags();
        hideTagSuggestions();
      });

      // Handle input for autocomplete
      input.addEventListener('input', (e) => {
        const value = e.target.value.trim();
        if (value.length > 0) {
          showTagSuggestions(value);
        } else {
          hideTagSuggestions();
        }
      });

      // Hide suggestions when clicking outside
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.tags-input-container')) {
          hideTagSuggestions();
        }
      });
    }

    function renderCurrentTags() {
      const container = document.getElementById('tags-container');
      const input = document.getElementById('tags-input');
      container.innerHTML = currentTags.map(tag => \`
        <span class="tag-badge">
          \${escapeHtml(tag)}
          <button type="button" onclick="removeTag('\${escapeAttr(tag)}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </span>
      \`).join('');
      container.appendChild(input);
      input.focus();
    }

    function removeTag(tag) {
      currentTags = currentTags.filter(t => t !== tag);
      renderCurrentTags();
    }

    async function deleteTag(tagName) {
      const usage = allTags.find(t => t.name === tagName)?.usage_count || 0;
      const message = usage > 0
        ? \`Delete tag "\${tagName}"? It will be removed from \${usage} artifact\${usage !== 1 ? 's' : ''}.\`
        : \`Delete tag "\${tagName}"?\`;

      if (!confirm(message)) return;

      const res = await fetch(\`/api/tags/\${encodeURIComponent(tagName)}\`, { method: 'DELETE' });
      if (res.ok) {
        showToast(\`Tag "\${tagName}" deleted\`, 'success');
        await Promise.all([loadTags(), loadArtifacts()]);
      } else {
        showToast('Failed to delete tag', 'error');
      }
    }

    // Tag autocomplete functions
    let focusedSuggestionIndex = -1;

    function showTagSuggestions(query) {
      const suggestions = document.getElementById('tag-suggestions');
      const lowerQuery = query.toLowerCase();

      // Filter tags that match and aren't already selected (uses global allTags from loadTags)
      const matches = (allTags || [])
        .filter(t => t.name.toLowerCase().includes(lowerQuery) && !currentTags.includes(t.name))
        .slice(0, 8);

      if (matches.length === 0) {
        hideTagSuggestions();
        return;
      }

      focusedSuggestionIndex = -1;
      const count = t => t.usage_count || t.count || 0;
      suggestions.innerHTML = matches.map((t, i) => \`
        <div class="tag-suggestion" data-tag="\${escapeAttr(t.name)}" onclick="selectTagSuggestion('\${escapeAttr(t.name)}')">
          <span class="tag-name">\${escapeHtml(t.name)}</span>
          <span class="tag-count">\${count(t)} artifact\${count(t) !== 1 ? 's' : ''}</span>
        </div>
      \`).join('');

      suggestions.classList.add('visible');
    }

    function hideTagSuggestions() {
      const suggestions = document.getElementById('tag-suggestions');
      suggestions.classList.remove('visible');
      focusedSuggestionIndex = -1;
    }

    function selectTagSuggestion(tag) {
      if (tag && !currentTags.includes(tag)) {
        currentTags.push(tag);
        renderCurrentTags();
      }
      document.getElementById('tags-input').value = '';
      hideTagSuggestions();
    }

    function focusNextSuggestion() {
      const suggestions = document.querySelectorAll('.tag-suggestion');
      if (suggestions.length === 0) return;

      if (focusedSuggestionIndex >= 0) {
        suggestions[focusedSuggestionIndex].classList.remove('focused');
      }

      focusedSuggestionIndex = (focusedSuggestionIndex + 1) % suggestions.length;
      suggestions[focusedSuggestionIndex].classList.add('focused');

      // If Enter is pressed while focused, select the suggestion
      const input = document.getElementById('tags-input');
      input.dataset.focusedTag = suggestions[focusedSuggestionIndex].dataset.tag;
    }

    function focusPrevSuggestion() {
      const suggestions = document.querySelectorAll('.tag-suggestion');
      if (suggestions.length === 0) return;

      if (focusedSuggestionIndex >= 0) {
        suggestions[focusedSuggestionIndex].classList.remove('focused');
      }

      focusedSuggestionIndex = focusedSuggestionIndex <= 0 ? suggestions.length - 1 : focusedSuggestionIndex - 1;
      suggestions[focusedSuggestionIndex].classList.add('focused');

      const input = document.getElementById('tags-input');
      input.dataset.focusedTag = suggestions[focusedSuggestionIndex].dataset.tag;
    }

    // Modal Functions
    function openCreateModal() {
      document.getElementById('modal-title').textContent = 'Add New Artifact';
      document.getElementById('artifact-form').reset();
      document.getElementById('edit-id').value = '';
      document.getElementById('url-group').style.display = 'block';
      document.getElementById('filename-group').style.display = 'none';
      document.getElementById('content-group').style.display = 'none';
      currentTags = [];
      renderCurrentTags();
      document.getElementById('artifact-modal').classList.add('active');
    }

    async function openEditModal(id) {
      const artifact = await fetch(\`/api/artifacts/\${id}\`).then(r => r.json());

      document.getElementById('modal-title').textContent = 'Edit Artifact';
      document.getElementById('edit-id').value = id;
      document.getElementById('artifact-name').value = artifact.name || '';
      document.getElementById('artifact-source').value = artifact.source_type || 'published';
      document.getElementById('artifact-type').value = artifact.artifact_type || 'code';
      document.getElementById('artifact-url').value = artifact.published_url || '';
      document.getElementById('artifact-filename').value = artifact.file_name || '';
      document.getElementById('artifact-content').value = artifact.file_content || '';
      document.getElementById('artifact-description').value = artifact.description || '';
      document.getElementById('artifact-collection').value = artifact.collection_id || '';
      document.getElementById('artifact-language').value = artifact.language || '';
      document.getElementById('artifact-conversation').value = artifact.conversation_url || '';
      document.getElementById('artifact-notes').value = artifact.notes || '';

      const isPublished = artifact.source_type === 'published';
      document.getElementById('url-group').style.display = isPublished ? 'block' : 'none';
      document.getElementById('filename-group').style.display = isPublished ? 'none' : 'block';
      document.getElementById('content-group').style.display = isPublished ? 'none' : 'block';

      currentTags = artifact.tags || [];
      renderCurrentTags();

      document.getElementById('artifact-modal').classList.add('active');
    }

    function closeModal() {
      document.getElementById('artifact-modal').classList.remove('active');
    }

    async function saveArtifact() {
      const id = document.getElementById('edit-id').value;
      const rawName = document.getElementById('artifact-name').value;

      // Validate and sanitize the name
      const sanitizedName = NameValidator.sanitize(rawName);
      const existingNames = allArtifacts
        .filter(a => a.id !== parseInt(id))  // Exclude current artifact if editing
        .map(a => a.name);
      const uniqueName = NameValidator.generateUniqueName(sanitizedName, existingNames);

      const data = {
        name: uniqueName,
        source_type: document.getElementById('artifact-source').value,
        artifact_type: document.getElementById('artifact-type').value,
        published_url: document.getElementById('artifact-url').value || null,
        file_name: document.getElementById('artifact-filename').value || null,
        file_content: document.getElementById('artifact-content').value || null,
        description: document.getElementById('artifact-description').value || null,
        collection_id: document.getElementById('artifact-collection').value || null,
        language: document.getElementById('artifact-language').value || null,
        conversation_url: document.getElementById('artifact-conversation').value || null,
        notes: document.getElementById('artifact-notes').value || null,
        tags: currentTags
      };

      const url = id ? \`/api/artifacts/\${id}\` : '/api/artifacts';
      const method = id ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      if (res.ok) {
        closeModal();
        showToast(\`Artifact \${id ? 'updated' : 'created'} successfully\`, 'success');
        await Promise.all([loadStats(), loadCollections(), loadTags(), loadArtifacts()]);
      } else {
        const err = await res.json();
        showToast(err.error || 'Failed to save artifact', 'error');
      }
    }

    async function deleteArtifact(id) {
      if (!confirm('Are you sure you want to delete this artifact?')) return;

      const res = await fetch(\`/api/artifacts/\${id}\`, { method: 'DELETE' });
      if (res.ok) {
        showToast('Artifact deleted', 'success');
        await Promise.all([loadStats(), loadArtifacts()]);
      }
    }

    async function toggleFavorite(id) {
      await fetch(\`/api/artifacts/\${id}/favorite\`, { method: 'POST' });
      await Promise.all([loadStats(), loadArtifacts()]);
    }

    // Collection Modal
    function openCollectionModal() {
      document.getElementById('collection-modal').classList.add('active');
    }

    function closeCollectionModal() {
      document.getElementById('collection-modal').classList.remove('active');
      document.getElementById('collection-name').value = '';
    }

    // Content Viewer Modal
    let currentViewingArtifact = null;
    let showingPreview = false;

    async function viewContent(id) {
      try {
        const response = await fetch(\`/api/artifacts/\${id}\`);
        if (!response.ok) {
          throw new Error(\`Failed to load artifact (HTTP \${response.status})\`);
        }
        const artifact = await response.json();
        if (artifact.error) {
          throw new Error(artifact.error);
        }
        currentViewingArtifact = artifact;
        showingPreview = false;

        // Set title
        document.getElementById('content-modal-title').textContent = artifact.name || 'View Artifact';

      // Set info
      document.getElementById('content-viewer-type').textContent = \`Type: \${artifact.artifact_type || 'unknown'}\`;
      document.getElementById('content-viewer-language').textContent = artifact.language ? \`Language: \${artifact.language}\` : '';

      // Set links
      const claudeLink = document.getElementById('content-viewer-claude');
      const publishedLink = document.getElementById('content-viewer-published');

      if (artifact.conversation_url) {
        claudeLink.href = artifact.conversation_url;
        claudeLink.style.display = 'inline';
      } else {
        claudeLink.style.display = 'none';
      }

      if (artifact.published_url) {
        publishedLink.href = artifact.published_url;
        publishedLink.style.display = 'inline';
      } else {
        publishedLink.style.display = 'none';
      }

      // Set content
      const content = artifact.file_content || 'No content available';
      document.getElementById('content-viewer-text').textContent = content;

      // Show/hide preview toggle for HTML
      const previewBtn = document.getElementById('toggle-preview-btn');
      const openNewTabBtn = document.getElementById('open-new-tab-btn');
      const shareBtn = document.getElementById('share-artifact-btn');
      const previewContainer = document.getElementById('content-viewer-preview');
      const codeContainer = document.getElementById('content-viewer-code');

      const isHtml = artifact.artifact_type === 'html' || (content.includes('<html') || content.includes('<!DOCTYPE'));
      const hasContent = content && content !== 'No content available';

      if (isHtml) {
        previewBtn.style.display = 'inline-flex';
      } else {
        previewBtn.style.display = 'none';
      }

      // Show Open in New Tab and Share buttons for HTML artifacts with content
      if (isHtml && hasContent) {
        openNewTabBtn.style.display = 'inline-flex';
        shareBtn.style.display = 'inline-flex';

        // Load share status
        try {
          const shareRes = await fetch('/api/artifacts/' + id + '/share');
          if (shareRes.ok) {
            const shareData = await shareRes.json();
            currentViewingArtifact.share_token = shareData.shareToken;
            currentViewingArtifact.renderUrl = shareData.renderUrl;
          }
        } catch (e) {
          // Ignore share status errors
        }
        updateShareButton();
      } else {
        openNewTabBtn.style.display = 'none';
        shareBtn.style.display = 'none';
      }

      previewContainer.style.display = 'none';
      codeContainer.style.display = 'block';

      document.getElementById('content-modal').classList.add('active');
      } catch (error) {
        console.error('Error loading artifact:', error);
        showToast(error.message || 'Failed to load artifact content', 'error');
      }
    }

    function closeContentModal() {
      document.getElementById('content-modal').classList.remove('active');
      currentViewingArtifact = null;
      // Clear iframe
      document.getElementById('content-preview-iframe').srcdoc = '';
    }

    function copyContent() {
      const content = currentViewingArtifact?.file_content || '';
      navigator.clipboard.writeText(content).then(() => {
        showToast('Content copied to clipboard', 'success');
      }).catch(() => {
        showToast('Failed to copy content', 'error');
      });
    }

    function togglePreview() {
      if (!currentViewingArtifact) return;

      const previewContainer = document.getElementById('content-viewer-preview');
      const codeContainer = document.getElementById('content-viewer-code');
      const iframe = document.getElementById('content-preview-iframe');

      showingPreview = !showingPreview;

      if (showingPreview) {
        // Show preview
        iframe.srcdoc = currentViewingArtifact.file_content || '';
        previewContainer.style.display = 'block';
        codeContainer.style.display = 'none';
      } else {
        // Show code
        previewContainer.style.display = 'none';
        codeContainer.style.display = 'block';
      }
    }

    // Open artifact in new tab (requires share token)
    async function openInNewTab() {
      if (!currentViewingArtifact) return;

      // Check if already shared
      let renderUrl = currentViewingArtifact.renderUrl;

      if (!renderUrl) {
        // Generate share token first
        try {
          const res = await fetch('/api/artifacts/' + currentViewingArtifact.id + '/share', {
            method: 'POST'
          });

          if (res.ok) {
            const data = await res.json();
            renderUrl = data.renderUrl;
            currentViewingArtifact.share_token = data.shareToken;
            currentViewingArtifact.renderUrl = renderUrl;
            updateShareButton();
          } else {
            showToast('Failed to generate share link', 'error');
            return;
          }
        } catch (error) {
          showToast('Failed to generate share link', 'error');
          return;
        }
      }

      window.open(renderUrl, '_blank');
    }

    // Toggle share status for artifact
    async function toggleShareArtifact() {
      if (!currentViewingArtifact) return;

      const isShared = !!currentViewingArtifact.share_token;

      try {
        if (isShared) {
          // Revoke share
          const res = await fetch('/api/artifacts/' + currentViewingArtifact.id + '/share', {
            method: 'DELETE'
          });

          if (res.ok) {
            currentViewingArtifact.share_token = null;
            currentViewingArtifact.renderUrl = null;
            showToast('Share link revoked', 'success');
            updateShareButton();
          } else {
            showToast('Failed to revoke share link', 'error');
          }
        } else {
          // Create share
          const res = await fetch('/api/artifacts/' + currentViewingArtifact.id + '/share', {
            method: 'POST'
          });

          if (res.ok) {
            const data = await res.json();
            currentViewingArtifact.share_token = data.shareToken;
            currentViewingArtifact.renderUrl = data.renderUrl;

            // Copy to clipboard
            await navigator.clipboard.writeText(data.renderUrl);
            showToast('Share link copied to clipboard!', 'success');
            updateShareButton();
          } else {
            showToast('Failed to generate share link', 'error');
          }
        }
      } catch (error) {
        showToast('Error: ' + error.message, 'error');
      }
    }

    function updateShareButton() {
      const btn = document.getElementById('share-artifact-btn');
      const text = document.getElementById('share-btn-text');
      if (!btn || !text) return;

      const isShared = !!currentViewingArtifact?.share_token;
      text.textContent = isShared ? 'Unshare' : 'Share';
      btn.title = isShared ? 'Revoke public share link' : 'Generate public share link';
    }

    async function createCollection() {
      const name = document.getElementById('collection-name').value;
      const color = document.getElementById('collection-color').value;

      if (!name) return;

      const res = await fetch('/api/collections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, color })
      });

      if (res.ok) {
        closeCollectionModal();
        showToast('Collection created', 'success');
        await loadCollections();
        await loadStats();
      } else {
        const err = await res.json();
        showToast(err.error || 'Failed to create collection', 'error');
      }
    }

    // Cleanup Utility - Template Constants
    const CLEANUP_LOADING = '<div style="text-align: center; padding: 2rem;">' +
      '<div class="spinner"></div>' +
      '<p style="margin-top: 1rem; color: var(--text-secondary);">Scanning for placeholder names...</p>' +
      '</div>';

    const CLEANUP_SUCCESS_SVG = '<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" style="margin: 0 auto;">' +
      '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>' +
      '<polyline points="22 4 12 14.01 9 11.01"/>' +
      '</svg>';

    const CLEANUP_SUCCESS = '<div style="text-align: center; padding: 2rem;">' +
      CLEANUP_SUCCESS_SVG +
      '<h4 style="margin-top: 1rem;">No Issues Found</h4>' +
      '<p style="color: var(--text-secondary); margin-top: 0.5rem;">All artifacts have valid names.</p>' +
      '</div>';

    const GRID_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
      '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>' +
      '<rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>' +
      '</svg>';

    const ARROW_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
      '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>' +
      '</svg>';

    const WARNING_ICON = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2">' +
      '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>' +
      '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>' +
      '</svg>';

    function renderCleanupItem(artifact) {
      return '<div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 6px; margin-bottom: 0.5rem;">' +
        GRID_ICON +
        '<div style="flex: 1;">' +
          '<div style="font-weight: 500;">' + escapeHtml(artifact.name || '(empty)') + '</div>' +
          '<div style="font-size: 0.75rem; color: var(--text-secondary);">' + escapeHtml(artifact.artifact_type || 'code') + '</div>' +
        '</div>' +
        '<div style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary);">' +
          ARROW_ICON +
          '<span style="font-size: 0.75rem; color: var(--success);">' + escapeHtml(artifact.artifact_type || 'Artifact') + '</span>' +
        '</div>' +
      '</div>';
    }

    function renderCleanupWarning(count, listHtml) {
      const plural = count === 1 ? '' : 's';
      return '<div style="background: var(--warning-bg); border: 1px solid var(--warning-border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">' +
        '<div style="display: flex; align-items: center; gap: 0.75rem;">' +
          WARNING_ICON +
          '<div>' +
            '<strong>Found ' + count + ' placeholder name' + plural + '</strong>' +
            '<p style="font-size: 0.875rem; color: var(--text-secondary); margin-top: 0.25rem;">These artifacts have temporary or invalid names</p>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div style="max-height: 300px; overflow-y: auto;">' + listHtml + '</div>';
    }

    let placeholderArtifacts = [];

    async function openCleanupModal() {
      document.getElementById('cleanup-modal').classList.add('active');
      document.getElementById('cleanup-body').innerHTML = CLEANUP_LOADING;
      document.getElementById('cleanup-footer').style.display = 'none';

      // Scan for placeholders
      const res = await fetch('/api/cleanup/scan');
      placeholderArtifacts = await res.json();

      if (placeholderArtifacts.length === 0) {
        document.getElementById('cleanup-body').innerHTML = CLEANUP_SUCCESS;
      } else {
        const listHtml = placeholderArtifacts.map(renderCleanupItem).join('');
        document.getElementById('cleanup-body').innerHTML = renderCleanupWarning(placeholderArtifacts.length, listHtml);
        document.getElementById('cleanup-footer').style.display = 'flex';
      }
    }

    function closeCleanupModal() {
      document.getElementById('cleanup-modal').classList.remove('active');
    }

    async function fixPlaceholders() {
      const fixBtn = document.getElementById('fix-btn');
      fixBtn.disabled = true;
      fixBtn.innerHTML = '<div class="spinner" style="width: 14px; height: 14px; margin-right: 0.5rem;"></div>Fixing...';

      const res = await fetch('/api/cleanup/fix', { method: 'POST' });
      const result = await res.json();

      if (result.success) {
        showToast(\`Fixed \${result.fixed} artifact\${result.fixed === 1 ? '' : 's'}\`, 'success');
        closeCleanupModal();
        await Promise.all([loadStats(), loadArtifacts()]);
      } else {
        showToast('Failed to fix artifacts', 'error');
      }

      fixBtn.disabled = false;
      fixBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.5rem;"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>Fix All Names';
    }

    // ============ SHARE COLLECTION MODAL ============

    let currentShareSlug = null;

    async function openShareModal(slug) {
      currentShareSlug = slug;
      const collection = allCollections.find(c => c.slug === slug);
      if (!collection) return;

      document.getElementById('share-collection-name').textContent = collection.name;

      // Check if already shared
      if (collection.is_public && collection.share_token) {
        // Already shared - show URL
        const shareUrl = window.location.origin + '/share/' + collection.share_token;
        document.getElementById('share-url').value = shareUrl;
        document.getElementById('share-url-container').style.display = 'block';
        document.getElementById('share-settings').style.display = 'none';
        document.getElementById('enable-sharing-btn').style.display = 'none';
        document.getElementById('disable-sharing-btn').style.display = 'inline-flex';
      } else {
        // Not shared yet - show settings
        document.getElementById('share-url-container').style.display = 'none';
        document.getElementById('share-settings').style.display = 'block';
        document.getElementById('enable-sharing-btn').style.display = 'inline-flex';
        document.getElementById('disable-sharing-btn').style.display = 'none';
      }

      document.getElementById('share-modal').classList.add('active');
    }

    function closeShareModal() {
      document.getElementById('share-modal').classList.remove('active');
      currentShareSlug = null;
    }

    async function enableSharing() {
      if (!currentShareSlug) return;

      const settings = {
        showThumbnails: document.getElementById('share-show-thumbnails').checked,
        layout: document.getElementById('share-layout').value
      };

      const btn = document.getElementById('enable-sharing-btn');
      btn.disabled = true;
      btn.textContent = 'Enabling...';

      try {
        const res = await fetch(\`/api/collections/\${currentShareSlug}/share\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ settings })
        });

        const result = await res.json();

        if (result.success) {
          showToast('Collection shared successfully!', 'success');

          // Update UI to show share URL
          document.getElementById('share-url').value = result.shareUrl;
          document.getElementById('share-url-container').style.display = 'block';
          document.getElementById('share-settings').style.display = 'none';
          document.getElementById('enable-sharing-btn').style.display = 'none';
          document.getElementById('disable-sharing-btn').style.display = 'inline-flex';

          // Reload collections to update state
          await loadCollections();
        } else {
          showToast('Failed to enable sharing', 'error');
        }
      } catch (error) {
        showToast('Failed to enable sharing', 'error');
      }

      btn.disabled = false;
      btn.textContent = 'Enable Sharing';
    }

    async function disableSharing() {
      if (!currentShareSlug) return;

      if (!confirm('Are you sure you want to stop sharing this collection? The existing share link will no longer work.')) {
        return;
      }

      const btn = document.getElementById('disable-sharing-btn');
      btn.disabled = true;
      btn.textContent = 'Disabling...';

      try {
        const res = await fetch(\`/api/collections/\${currentShareSlug}/share\`, {
          method: 'DELETE'
        });

        const result = await res.json();

        if (result.success) {
          showToast('Sharing disabled', 'success');
          closeShareModal();
          await loadCollections();
        } else {
          showToast('Failed to disable sharing', 'error');
        }
      } catch (error) {
        showToast('Failed to disable sharing', 'error');
      }

      btn.disabled = false;
      btn.textContent = 'Stop Sharing';
    }

    function copyShareUrl() {
      const input = document.getElementById('share-url');
      input.select();
      input.setSelectionRange(0, 99999); // For mobile devices

      navigator.clipboard.writeText(input.value).then(() => {
        showToast('Share URL copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Failed to copy URL', 'error');
      });
    }

    // Export/Import
    async function exportData() {
      window.location.href = '/api/export';
    }

    async function importData(event) {
      const file = event.target.files[0];
      if (!file) return;

      const text = await file.text();
      const data = JSON.parse(text);

      const res = await fetch('/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      const result = await res.json();
      showToast(\`Imported \${result.imported} artifacts (\${result.skipped} skipped)\`, 'success');
      await Promise.all([loadStats(), loadCollections(), loadTags(), loadArtifacts()]);
      event.target.value = '';
    }

    // Toast
    function showToast(message, type = 'success') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = \`toast \${type}\`;
      toast.innerHTML = \`
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          \${type === 'success'
            ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
            : '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'}
        </svg>
        <span>\${escapeHtml(message)}</span>
      \`;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 5000);
    }
  </script>
</body>
</html>`;
}
