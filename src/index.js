// Official Clerk SDK for JWT verification
import { verifyToken, createClerkClient } from '@clerk/backend';

// Favicon SVG with accessibility title and optimized grouped paths
const ADMIN_FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctitle%3EURLsToGo Admin Icon%3C/title%3E%3Crect width='32' height='32' rx='6' fill='%2309090b'/%3E%3Cg stroke='%238b5cf6' stroke-width='2.5' stroke-linecap='round' fill='none'%3E%3Cpath d='M18.5 10.5a4 4 0 0 1 5.66 5.66l-2.83 2.83a4 4 0 0 1-5.66 0'/%3E%3Cpath d='M13.5 21.5a4 4 0 0 1-5.66-5.66l2.83-2.83a4 4 0 0 1 5.66 0'/%3E%3C/g%3E%3C/svg%3E";

// Admin path constant - used for redirects and PWA start URL
const ADMIN_PATH = '/admin';

// =============================================================================
// PWA - Progressive Web App Assets
// =============================================================================

// PWA Manifest
const PWA_MANIFEST = {
  name: 'URLsToGo',
  short_name: 'URLsToGo',
  description: 'Fast, free URL shortener powered by Cloudflare',
  start_url: ADMIN_PATH,
  display: 'standalone',
  background_color: '#09090b',
  theme_color: '#8b5cf6',
  orientation: 'any',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
  ]
};

// Service Worker JavaScript
const SERVICE_WORKER_JS = `
const CACHE_NAME = 'urlstogo-v1';
const STATIC_ASSETS = [
  '${ADMIN_PATH}',
  '/login',
  '/manifest.json'
];

// Install - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// Activate - clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch - network first, fallback to cache
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests and API calls
  if (event.request.method !== 'GET' || event.request.url.includes('/api/')) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Clone and cache successful responses
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
`;

// Generate SVG icon as PNG-like data (actually SVG but works for PWA)
function generatePWAIcon(size) {
  const iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" rx="${size * 0.1875}" fill="#09090b"/>
    <g stroke="#8b5cf6" stroke-width="${size * 0.08}" stroke-linecap="round" fill="none" transform="translate(${size * 0.25}, ${size * 0.25}) scale(${size / 32 * 0.5})">
      <path d="M18.5 10.5a4 4 0 0 1 5.66 5.66l-2.83 2.83a4 4 0 0 1-5.66 0"/>
      <path d="M13.5 21.5a4 4 0 0 1-5.66-5.66l2.83-2.83a4 4 0 0 1 5.66 0"/>
    </g>
  </svg>`;
  return iconSvg;
}

// =============================================================================
// SECURITY HELPER FUNCTIONS - XSS Prevention
// =============================================================================

// Escape HTML entities to prevent XSS in HTML content
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Escape for use in HTML attributes (especially in JS contexts like onclick)
function escapeAttr(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

// Escape for use in JavaScript string literals
function escapeJs(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/</g, '\\x3c')
    .replace(/>/g, '\\x3e');
}

// CORS headers for mobile app
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*', // Allow mobile app from any origin
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Cf-Access-Jwt-Assertion, Authorization',
  'Access-Control-Max-Age': '86400',
};

// JSON response with CORS headers (for API endpoints)
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS
    }
  });
}

// Error response with CORS headers
function errorResponse(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1);

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Get user email from Clerk JWT (with Cloudflare Access fallback)
    const userEmail = await getUserEmailWithFallback(request, env);

    // Public landing page at root
    if (path === '') {
      return new Response(getLandingPageHTML(), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    // Clerk login/signup pages
    if (path === 'login' || path === 'signup') {
      return new Response(getAuthPageHTML(env, path), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    // Serve design resource pages (no auth required)
    if (path === 'design-system') {
      return new Response(getDesignSystemHTML(), {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    if (path === 'mobile-mockup') {
      return new Response(getMobileMockupHTML(), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    // PWA Assets
    if (path === 'manifest.json') {
      return new Response(JSON.stringify(PWA_MANIFEST), {
        headers: { 'Content-Type': 'application/manifest+json' }
      });
    }
    if (path === 'sw.js') {
      return new Response(SERVICE_WORKER_JS, {
        headers: { 'Content-Type': 'application/javascript' }
      });
    }
    if (path === 'icon-192.png' || path === 'icon-512.png') {
      const size = path === 'icon-192.png' ? 192 : 512;
      return new Response(generatePWAIcon(size), {
        headers: { 'Content-Type': 'image/svg+xml' }
      });
    }

    // Public redirect - no auth needed
    if (path && !path.startsWith('admin') && !path.startsWith('api/')) {
      const link = await env.DB.prepare('SELECT id, destination, expires_at, password_hash FROM links WHERE code = ?').bind(path).first();
      if (link) {
        // Rate limit check for redirects (by IP)
        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rateLimit = await checkRateLimit(env, clientIP, 'redirect');
        if (!rateLimit.allowed) {
          return new Response('Too many requests. Please try again later.', {
            status: 429,
            headers: { 'Retry-After': '60' }
          });
        }

        // Check if link has expired
        if (link.expires_at && new Date(link.expires_at) < new Date()) {
          return new Response(getExpiredHTML(), {
            status: 410,
            headers: { 'Content-Type': 'text/html' }
          });
        }

        // Check if link is password protected
        if (link.password_hash) {
          // Handle POST request with password
          if (request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get('password') || '';
            const isValid = await verifyPassword(password, link.password_hash);

            if (!isValid) {
              return new Response(getPasswordHTML(path, true), {
                status: 401,
                headers: { 'Content-Type': 'text/html' }
              });
            }
            // Password correct, continue to redirect
          } else {
            // Show password prompt
            return new Response(getPasswordHTML(path, false), {
              status: 401,
              headers: { 'Content-Type': 'text/html' }
            });
          }
        }

        // Update click count
        await env.DB.prepare('UPDATE links SET clicks = clicks + 1 WHERE code = ?').bind(path).run();

        // Log click event with details from Cloudflare headers
        const clickData = parseClickData(request);
        await env.DB.prepare(`
          INSERT INTO click_events (link_id, referrer, user_agent, country, city, device_type, browser)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          link.id,
          clickData.referrer,
          clickData.userAgent,
          clickData.country,
          clickData.city,
          clickData.deviceType,
          clickData.browser
        ).run();

        return new Response(null, {
          status: 302,
          headers: {
            'Location': link.destination,
            'Cache-Control': 'private, no-cache, no-store, must-revalidate'
          }
        });
      }
      return new Response(get404HTML(path), {
        status: 404,
        headers: { 'Content-Type': 'text/html' }
      });
    }

    // Admin page - redirect to login if not authenticated
    if (path === 'admin') {
      if (!userEmail) {
        return Response.redirect(new URL('/login', url.origin).toString(), 302);
      }
      return new Response(getAdminHTML(userEmail, env), { headers: { 'Content-Type': 'text/html' } });
    }

    // Protected API routes require auth
    if (!userEmail) {
      return new Response(JSON.stringify({ error: 'Unauthorized - Please login' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    // === LINKS API ===

    // List user's links with categories and tags
    if (path === 'api/links' && request.method === 'GET') {
      const categoryFilter = url.searchParams.get('category');
      const tagFilter = url.searchParams.get('tag');
      const sort = url.searchParams.get('sort') || 'newest';

      let query = `
        SELECT l.id, l.code, l.destination, l.clicks, l.user_email, l.category_id, l.created_at, l.expires_at,
               l.description, CASE WHEN l.password_hash IS NOT NULL THEN 1 ELSE 0 END as is_protected,
               c.name as category_name, c.slug as category_slug, c.color as category_color,
               GROUP_CONCAT(t.name) as tags
        FROM links l
        LEFT JOIN categories c ON l.category_id = c.id
        LEFT JOIN link_tags lt ON l.id = lt.link_id
        LEFT JOIN tags t ON lt.tag_id = t.id
        WHERE l.user_email = ?
      `;
      const params = [userEmail];

      if (categoryFilter) {
        query += ' AND c.slug = ?';
        params.push(categoryFilter);
      }

      if (tagFilter) {
        query += ' AND l.id IN (SELECT lt2.link_id FROM link_tags lt2 JOIN tags t2 ON lt2.tag_id = t2.id WHERE t2.name = ? AND t2.user_email = ?)';
        params.push(tagFilter, userEmail);
      }

      query += ' GROUP BY l.id';

      // Sorting
      switch (sort) {
        case 'oldest': query += ' ORDER BY l.created_at ASC'; break;
        case 'clicks': query += ' ORDER BY l.clicks DESC'; break;
        case 'alpha': query += ' ORDER BY l.code ASC'; break;
        default: query += ' ORDER BY l.created_at DESC';
      }

      const { results } = await env.DB.prepare(query).bind(...params).all();

      // Parse tags string into array
      const links = results.map(link => ({
        ...link,
        tags: link.tags ? link.tags.split(',') : []
      }));

      return jsonResponse(links);
    }

    // Search links
    if (path === 'api/search' && request.method === 'GET') {
      // Rate limit check
      const rateLimit = await checkRateLimit(env, userEmail, 'api/search');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      const q = url.searchParams.get('q') || '';
      if (q.length < 2) {
        return jsonResponse([]);
      }

      const searchTerm = `%${q}%`;
      const { results } = await env.DB.prepare(`
        SELECT l.*, c.name as category_name, c.slug as category_slug, c.color as category_color
        FROM links l
        LEFT JOIN categories c ON l.category_id = c.id
        WHERE l.user_email = ? AND (l.code LIKE ? OR l.destination LIKE ? OR l.description LIKE ?)
        ORDER BY l.clicks DESC
        LIMIT 10
      `).bind(userEmail, searchTerm, searchTerm, searchTerm).all();

      return jsonResponse(results);
    }

    // Create new link
    if (path === 'api/links' && request.method === 'POST') {
      // Rate limit check
      const rateLimit = await checkRateLimit(env, userEmail, 'api/links:POST');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      const { code, destination, category_id, tags, expires_at, password, description } = await request.json();
      if (!code || !destination) {
        return jsonResponse({ error: 'Missing code or destination' }, { status: 400 });
      }

      // Validate short code
      const codeValidation = validateCode(code);
      if (!codeValidation.valid) {
        return jsonResponse({ error: codeValidation.error }, { status: 400 });
      }

      // Validate destination URL
      const urlValidation = validateUrl(destination);
      if (!urlValidation.valid) {
        return jsonResponse({ error: urlValidation.error }, { status: 400 });
      }

      // Check if code exists globally
      const existing = await env.DB.prepare('SELECT code FROM links WHERE code = ?').bind(codeValidation.code).first();
      if (existing) {
        return jsonResponse({ error: 'Code already taken' }, { status: 409 });
      }

      try {
        // Hash password if provided
        const passwordHash = password ? await hashPassword(password) : null;

        // Insert link with optional expiration, password, and description
        const result = await env.DB.prepare(
          'INSERT INTO links (code, destination, user_email, category_id, expires_at, password_hash, description) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(codeValidation.code, urlValidation.url, userEmail, category_id || null, expires_at || null, passwordHash, description || null).run();

        const linkId = result.meta.last_row_id;

        // Handle tags
        if (tags && Array.isArray(tags) && tags.length > 0) {
          for (const tagName of tags) {
            // Get or create tag
            let tag = await env.DB.prepare('SELECT id FROM tags WHERE name = ? AND user_email = ?').bind(tagName.toLowerCase(), userEmail).first();
            if (!tag) {
              const tagResult = await env.DB.prepare('INSERT INTO tags (name, user_email) VALUES (?, ?)').bind(tagName.toLowerCase(), userEmail).run();
              tag = { id: tagResult.meta.last_row_id };
            }
            // Link tag to link
            await env.DB.prepare('INSERT OR IGNORE INTO link_tags (link_id, tag_id) VALUES (?, ?)').bind(linkId, tag.id).run();
          }
        }

        return jsonResponse({ success: true, code, destination, id: linkId });
      } catch (e) {
        return jsonResponse({ error: 'Failed to create link: ' + e.message }, { status: 500 });
      }
    }

    // Update link
    if (path.startsWith('api/links/') && request.method === 'PUT') {
      const code = path.replace('api/links/', '');
      const { destination, category_id, tags, expires_at, password, remove_password, description } = await request.json();

      // Validate destination URL
      const urlValidation = validateUrl(destination);
      if (!urlValidation.valid) {
        return jsonResponse({ error: urlValidation.error }, { status: 400 });
      }

      // Get link
      const link = await env.DB.prepare('SELECT id FROM links WHERE code = ? AND user_email = ?').bind(code, userEmail).first();
      if (!link) {
        return jsonResponse({ error: 'Link not found' }, { status: 404 });
      }

      // Hash password if provided, or set to null if removing
      let passwordHash = undefined; // undefined means don't change
      if (remove_password) {
        passwordHash = null;
      } else if (password) {
        passwordHash = await hashPassword(password);
      }

      // Update link with expiration, optional password, and description
      if (passwordHash !== undefined) {
        await env.DB.prepare('UPDATE links SET destination = ?, category_id = ?, expires_at = ?, password_hash = ?, description = ? WHERE id = ?')
          .bind(urlValidation.url, category_id || null, expires_at || null, passwordHash, description || null, link.id).run();
      } else {
        await env.DB.prepare('UPDATE links SET destination = ?, category_id = ?, expires_at = ?, description = ? WHERE id = ?')
          .bind(urlValidation.url, category_id || null, expires_at || null, description || null, link.id).run();
      }

      // Update tags
      if (tags !== undefined) {
        // Remove existing tags
        await env.DB.prepare('DELETE FROM link_tags WHERE link_id = ?').bind(link.id).run();

        // Add new tags
        if (Array.isArray(tags)) {
          for (const tagName of tags) {
            let tag = await env.DB.prepare('SELECT id FROM tags WHERE name = ? AND user_email = ?').bind(tagName.toLowerCase(), userEmail).first();
            if (!tag) {
              const tagResult = await env.DB.prepare('INSERT INTO tags (name, user_email) VALUES (?, ?)').bind(tagName.toLowerCase(), userEmail).run();
              tag = { id: tagResult.meta.last_row_id };
            }
            await env.DB.prepare('INSERT OR IGNORE INTO link_tags (link_id, tag_id) VALUES (?, ?)').bind(link.id, tag.id).run();
          }
        }
      }

      return jsonResponse({ success: true });
    }

    // Delete link
    if (path.startsWith('api/links/') && request.method === 'DELETE') {
      // Rate limit check
      const rateLimit = await checkRateLimit(env, userEmail, 'api/links:DELETE');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      const code = path.replace('api/links/', '');
      await env.DB.prepare('DELETE FROM links WHERE code = ? AND user_email = ?').bind(code, userEmail).run();
      return jsonResponse({ success: true });
    }

    // Bulk delete links
    if (path === 'api/links/bulk-delete' && request.method === 'POST') {
      // Rate limit check
      const rateLimit = await checkRateLimit(env, userEmail, 'api/links:DELETE');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      const { codes } = await request.json();
      if (!codes || !Array.isArray(codes) || codes.length === 0) {
        return jsonResponse({ error: 'No links specified' }, { status: 400 });
      }

      // Limit bulk operations to 100 items
      if (codes.length > 100) {
        return jsonResponse({ error: 'Maximum 100 links per bulk operation' }, { status: 400 });
      }

      let deleted = 0;
      for (const code of codes) {
        const result = await env.DB.prepare('DELETE FROM links WHERE code = ? AND user_email = ?')
          .bind(code, userEmail).run();
        if (result.meta.changes > 0) deleted++;
      }

      return jsonResponse({ success: true, deleted });
    }

    // Bulk move links to category
    if (path === 'api/links/bulk-move' && request.method === 'POST') {
      const { codes, category_id } = await request.json();
      if (!codes || !Array.isArray(codes) || codes.length === 0) {
        return jsonResponse({ error: 'No links specified' }, { status: 400 });
      }

      // Verify category exists and belongs to user (or null to remove category)
      if (category_id) {
        const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ? AND user_email = ?')
          .bind(category_id, userEmail).first();
        if (!cat) {
          return jsonResponse({ error: 'Category not found' }, { status: 404 });
        }
      }

      let updated = 0;
      for (const code of codes) {
        const result = await env.DB.prepare('UPDATE links SET category_id = ? WHERE code = ? AND user_email = ?')
          .bind(category_id || null, code, userEmail).run();
        if (result.meta.changes > 0) updated++;
      }

      return jsonResponse({ success: true, updated });
    }

    // === PREVIEW LINKS API ===
    // Special endpoint for updating preview deployment URLs
    // Used by GitHub Actions to update shortlinks like "bricks-cc--preview" automatically

    // Create or update a preview link
    if (path.startsWith('api/preview-links/') && (request.method === 'PUT' || request.method === 'POST')) {
      // Rate limit check
      const rateLimit = await checkRateLimit(env, userEmail, 'api/preview-links:PUT');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      const code = path.replace('api/preview-links/', '');

      // Validate code format using standard validation
      const codeValidation = validateCode(code);
      if (!codeValidation.valid) {
        return jsonResponse({ error: codeValidation.error }, { status: 400 });
      }

      // Validate code ends with --preview
      if (!code.endsWith('--preview')) {
        return jsonResponse({
          error: 'Preview link codes must end with --preview (e.g., "my-app--preview")'
        }, { status: 400 });
      }

      const { destination } = await request.json();
      if (!destination) {
        return jsonResponse({ error: 'Missing destination URL' }, { status: 400 });
      }

      // Validate destination URL
      const urlValidation = validateUrl(destination);
      if (!urlValidation.valid) {
        return jsonResponse({ error: urlValidation.error }, { status: 400 });
      }

      // Check if link already exists
      const existingLink = await env.DB.prepare(
        'SELECT id, user_email FROM links WHERE code = ?'
      ).bind(code).first();

      if (existingLink) {
        // Verify ownership - only the owner or same API key user can update
        if (existingLink.user_email !== userEmail) {
          return jsonResponse({
            error: 'This preview link belongs to another user'
          }, { status: 403 });
        }

        // Update existing preview link
        await env.DB.prepare(
          'UPDATE links SET destination = ?, is_preview_link = 1 WHERE code = ?'
        ).bind(destination, code).run();

        return jsonResponse({
          success: true,
          action: 'updated',
          code,
          destination,
          url: `https://${url.host}/${code}`
        });
      } else {
        // Create new preview link
        try {
          await env.DB.prepare(
            'INSERT INTO links (code, destination, user_email, is_preview_link, description) VALUES (?, ?, ?, 1, ?)'
          ).bind(code, destination, userEmail, 'Auto-updated preview deployment link').run();

          return jsonResponse({
            success: true,
            action: 'created',
            code,
            destination,
            url: `https://${url.host}/${code}`
          });
        } catch (e) {
          // Log error internally but return generic message to user
          console.error('Preview link creation failed:', e);
          return jsonResponse({
            error: 'Failed to create preview link. Please check the code and try again.'
          }, { status: 500 });
        }
      }
    }

    // === CATEGORIES API ===

    // List categories
    if (path === 'api/categories' && request.method === 'GET') {
      const { results } = await env.DB.prepare(`
        SELECT c.*, COUNT(l.id) as link_count
        FROM categories c
        LEFT JOIN links l ON c.id = l.category_id
        WHERE c.user_email = ?
        GROUP BY c.id
        ORDER BY c.name ASC
      `).bind(userEmail).all();
      return jsonResponse(results);
    }

    // Create category
    if (path === 'api/categories' && request.method === 'POST') {
      const { name, color } = await request.json();
      if (!name) {
        return jsonResponse({ error: 'Missing name' }, { status: 400 });
      }

      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

      try {
        await env.DB.prepare('INSERT INTO categories (name, slug, color, user_email) VALUES (?, ?, ?, ?)')
          .bind(name, slug, color || 'gray', userEmail).run();
        return jsonResponse({ success: true, name, slug });
      } catch (e) {
        return jsonResponse({ error: 'Category already exists' }, { status: 409 });
      }
    }

    // Delete category
    if (path.startsWith('api/categories/') && request.method === 'DELETE') {
      const slug = path.replace('api/categories/', '');
      await env.DB.prepare('DELETE FROM categories WHERE slug = ? AND user_email = ?').bind(slug, userEmail).run();
      return jsonResponse({ success: true });
    }

    // === TAGS API ===

    // List tags with usage count
    if (path === 'api/tags' && request.method === 'GET') {
      const { results } = await env.DB.prepare(`
        SELECT t.*, COUNT(lt.link_id) as link_count
        FROM tags t
        LEFT JOIN link_tags lt ON t.id = lt.tag_id
        WHERE t.user_email = ?
        GROUP BY t.id
        ORDER BY link_count DESC
      `).bind(userEmail).all();
      return jsonResponse(results);
    }

    // === STATS API ===

    if (path === 'api/stats' && request.method === 'GET') {
      const linksResult = await env.DB.prepare('SELECT COUNT(*) as count, SUM(clicks) as clicks FROM links WHERE user_email = ?').bind(userEmail).first();
      const categoriesResult = await env.DB.prepare('SELECT COUNT(*) as count FROM categories WHERE user_email = ?').bind(userEmail).first();
      const tagsResult = await env.DB.prepare('SELECT COUNT(DISTINCT t.id) as count FROM tags t JOIN link_tags lt ON t.id = lt.tag_id JOIN links l ON lt.link_id = l.id WHERE l.user_email = ?').bind(userEmail).first();

      return jsonResponse({
        links: linksResult?.count || 0,
        clicks: linksResult?.clicks || 0,
        categories: categoriesResult?.count || 0,
        tags: tagsResult?.count || 0
      });
    }

    // === ANALYTICS API ===

    // Get analytics for a specific link
    if (path.startsWith('api/analytics/') && path !== 'api/analytics/overview' && request.method === 'GET') {
      const code = path.replace('api/analytics/', '');
      const days = parseInt(url.searchParams.get('days') || '30');

      // Get the link
      const link = await env.DB.prepare('SELECT id, code, destination, clicks FROM links WHERE code = ? AND user_email = ?')
        .bind(code, userEmail).first();

      if (!link) {
        return jsonResponse({ error: 'Link not found' }, { status: 404 });
      }

      // Get click events for this link
      const { results: clickEvents } = await env.DB.prepare(`
        SELECT clicked_at, referrer, country, city, device_type, browser
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days')
        ORDER BY clicked_at DESC
        LIMIT 1000
      `).bind(link.id, days).all();

      // Aggregate by day
      const { results: clicksByDay } = await env.DB.prepare(`
        SELECT DATE(clicked_at) as date, COUNT(*) as clicks
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY DATE(clicked_at)
        ORDER BY date ASC
      `).bind(link.id, days).all();

      // Aggregate by country
      const { results: clicksByCountry } = await env.DB.prepare(`
        SELECT country, COUNT(*) as clicks
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days') AND country != ''
        GROUP BY country
        ORDER BY clicks DESC
        LIMIT 10
      `).bind(link.id, days).all();

      // Aggregate by device
      const { results: clicksByDevice } = await env.DB.prepare(`
        SELECT device_type, COUNT(*) as clicks
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY device_type
        ORDER BY clicks DESC
      `).bind(link.id, days).all();

      // Aggregate by browser
      const { results: clicksByBrowser } = await env.DB.prepare(`
        SELECT browser, COUNT(*) as clicks
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY browser
        ORDER BY clicks DESC
      `).bind(link.id, days).all();

      // Top referrers
      const { results: topReferrers } = await env.DB.prepare(`
        SELECT
          CASE WHEN referrer = '' THEN 'Direct' ELSE referrer END as referrer,
          COUNT(*) as clicks
        FROM click_events
        WHERE link_id = ? AND clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY referrer
        ORDER BY clicks DESC
        LIMIT 10
      `).bind(link.id, days).all();

      return jsonResponse({
        link: { code: link.code, destination: link.destination, totalClicks: link.clicks },
        period: { days, from: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
        clicksByDay,
        clicksByCountry,
        clicksByDevice,
        clicksByBrowser,
        topReferrers,
        recentClicks: clickEvents.slice(0, 50)
      });
    }

    // Get overview analytics for all links
    if (path === 'api/analytics/overview' && request.method === 'GET') {
      const days = parseInt(url.searchParams.get('days') || '30');

      // Total clicks in period
      const totalInPeriod = await env.DB.prepare(`
        SELECT COUNT(*) as clicks
        FROM click_events ce
        JOIN links l ON ce.link_id = l.id
        WHERE l.user_email = ? AND ce.clicked_at >= datetime('now', '-' || ? || ' days')
      `).bind(userEmail, days).first();

      // Clicks by day
      const { results: clicksByDay } = await env.DB.prepare(`
        SELECT DATE(ce.clicked_at) as date, COUNT(*) as clicks
        FROM click_events ce
        JOIN links l ON ce.link_id = l.id
        WHERE l.user_email = ? AND ce.clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY DATE(ce.clicked_at)
        ORDER BY date ASC
      `).bind(userEmail, days).all();

      // Top performing links
      const { results: topLinks } = await env.DB.prepare(`
        SELECT l.code, l.destination, COUNT(ce.id) as recent_clicks, l.clicks as total_clicks
        FROM links l
        LEFT JOIN click_events ce ON l.id = ce.link_id AND ce.clicked_at >= datetime('now', '-' || ? || ' days')
        WHERE l.user_email = ?
        GROUP BY l.id
        ORDER BY recent_clicks DESC
        LIMIT 10
      `).bind(days, userEmail).all();

      // Clicks by country
      const { results: clicksByCountry } = await env.DB.prepare(`
        SELECT ce.country, COUNT(*) as clicks
        FROM click_events ce
        JOIN links l ON ce.link_id = l.id
        WHERE l.user_email = ? AND ce.clicked_at >= datetime('now', '-' || ? || ' days') AND ce.country != ''
        GROUP BY ce.country
        ORDER BY clicks DESC
        LIMIT 10
      `).bind(userEmail, days).all();

      // Clicks by device
      const { results: clicksByDevice } = await env.DB.prepare(`
        SELECT ce.device_type, COUNT(*) as clicks
        FROM click_events ce
        JOIN links l ON ce.link_id = l.id
        WHERE l.user_email = ? AND ce.clicked_at >= datetime('now', '-' || ? || ' days')
        GROUP BY ce.device_type
      `).bind(userEmail, days).all();

      return jsonResponse({
        period: { days },
        totalClicks: totalInPeriod?.clicks || 0,
        clicksByDay,
        topLinks,
        clicksByCountry,
        clicksByDevice
      });
    }

    // === EXPORT/IMPORT ===

    // Export
    if (path === 'api/export' && request.method === 'GET') {
      const { results: links } = await env.DB.prepare(`
        SELECT l.code, l.destination, l.clicks, l.created_at, c.slug as category,
               GROUP_CONCAT(t.name) as tags
        FROM links l
        LEFT JOIN categories c ON l.category_id = c.id
        LEFT JOIN link_tags lt ON l.id = lt.link_id
        LEFT JOIN tags t ON lt.tag_id = t.id
        WHERE l.user_email = ?
        GROUP BY l.id
        ORDER BY l.created_at DESC
      `).bind(userEmail).all();

      const { results: categories } = await env.DB.prepare('SELECT name, slug, color FROM categories WHERE user_email = ?').bind(userEmail).all();

      const exportData = {
        version: 2,
        exported_at: new Date().toISOString(),
        categories,
        links: links.map(l => ({ ...l, tags: l.tags ? l.tags.split(',') : [] }))
      };

      return new Response(JSON.stringify(exportData, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="links-export-${new Date().toISOString().split('T')[0]}.json"`
        }
      });
    }

    // Import
    if (path === 'api/import' && request.method === 'POST') {
      // Rate limit check (stricter for imports)
      const rateLimit = await checkRateLimit(env, userEmail, 'api/import');
      if (!rateLimit.allowed) return rateLimitExceeded(rateLimit);

      try {
        const data = await request.json();
        let imported = 0, skipped = 0;

        // Handle v2 format with categories
        if (data.version === 2 && data.categories) {
          for (const cat of data.categories) {
            try {
              await env.DB.prepare('INSERT OR IGNORE INTO categories (name, slug, color, user_email) VALUES (?, ?, ?, ?)')
                .bind(cat.name, cat.slug, cat.color || 'gray', userEmail).run();
            } catch (e) { /* ignore duplicates */ }
          }
        }

        const links = data.links || data; // Support both v1 and v2

        for (const link of links) {
          if (!link.code || !link.destination) continue;

          const existing = await env.DB.prepare('SELECT code FROM links WHERE code = ?').bind(link.code).first();
          if (existing) { skipped++; continue; }

          // Get category ID if specified
          let categoryId = null;
          if (link.category) {
            const cat = await env.DB.prepare('SELECT id FROM categories WHERE slug = ? AND user_email = ?').bind(link.category, userEmail).first();
            if (cat) categoryId = cat.id;
          }

          const result = await env.DB.prepare('INSERT INTO links (code, destination, user_email, clicks, category_id) VALUES (?, ?, ?, ?, ?)')
            .bind(link.code, link.destination, userEmail, link.clicks || 0, categoryId).run();

          // Handle tags
          if (link.tags && Array.isArray(link.tags)) {
            for (const tagName of link.tags) {
              let tag = await env.DB.prepare('SELECT id FROM tags WHERE name = ? AND user_email = ?').bind(tagName.toLowerCase(), userEmail).first();
              if (!tag) {
                const tagResult = await env.DB.prepare('INSERT INTO tags (name, user_email) VALUES (?, ?)').bind(tagName.toLowerCase(), userEmail).run();
                tag = { id: tagResult.meta.last_row_id };
              }
              await env.DB.prepare('INSERT OR IGNORE INTO link_tags (link_id, tag_id) VALUES (?, ?)').bind(result.meta.last_row_id, tag.id).run();
            }
          }

          imported++;
        }

        return jsonResponse({ success: true, imported, skipped });
      } catch (e) {
        return jsonResponse({ error: 'Invalid JSON format' }, { status: 400 });
      }
    }

    // =============================================================================
    // API KEY MANAGEMENT ENDPOINTS
    // =============================================================================

    // List API keys (without revealing full keys)
    if (path === 'api/keys' && request.method === 'GET') {
      const keys = await env.DB.prepare(`
        SELECT id, name, key_prefix, scopes, last_used_at, created_at, expires_at
        FROM api_keys WHERE user_email = ? ORDER BY created_at DESC
      `).bind(userEmail).all();
      return jsonResponse({ keys: keys.results });
    }

    // Create new API key
    if (path === 'api/keys' && request.method === 'POST') {
      const { name, scopes, expires_at } = await request.json();

      if (!name || name.length < 1) {
        return jsonResponse({ error: 'Name is required' }, { status: 400 });
      }

      // Generate key and hash it
      const apiKey = generateApiKey();
      const keyHash = await hashApiKey(apiKey);
      const keyPrefix = apiKey.slice(0, 11); // utg_ + first 7 chars

      await env.DB.prepare(`
        INSERT INTO api_keys (user_email, name, key_hash, key_prefix, scopes, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(userEmail, name, keyHash, keyPrefix, scopes || 'read,write', expires_at || null).run();

      // Return the full key only once (it can never be retrieved again)
      return jsonResponse({
        success: true,
        key: apiKey,
        name,
        prefix: keyPrefix,
        message: 'Save this key now - it cannot be shown again'
      });
    }

    // Delete API key
    if (path.startsWith('api/keys/') && request.method === 'DELETE') {
      const keyId = path.replace('api/keys/', '');
      await env.DB.prepare('DELETE FROM api_keys WHERE id = ? AND user_email = ?')
        .bind(keyId, userEmail).run();
      return jsonResponse({ success: true });
    }

    // Init default categories (one-time setup helper)
    if (path === 'api/init-categories' && request.method === 'POST') {
      const defaults = [
        { name: 'Work', slug: 'work', color: 'violet' },
        { name: 'Personal', slug: 'personal', color: 'pink' },
        { name: 'Social Media', slug: 'social', color: 'cyan' },
        { name: 'Marketing', slug: 'marketing', color: 'orange' },
        { name: 'Documentation', slug: 'docs', color: 'green' }
      ];

      for (const cat of defaults) {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO categories (name, slug, color, user_email) VALUES (?, ?, ?, ?)')
            .bind(cat.name, cat.slug, cat.color, userEmail).run();
        } catch (e) { /* ignore */ }
      }

      return jsonResponse({ success: true });
    }

    return new Response('Not found', { status: 404 });
  }
};

// =============================================================================
// JWT AUTHENTICATION - Clerk Integration (Official SDK)
// =============================================================================
// Using @clerk/backend for secure JWT verification
//
// Required environment variables (set in Cloudflare dashboard):
// - CLERK_PUBLISHABLE_KEY: pk_test_... or pk_live_...
// - CLERK_SECRET_KEY: sk_test_... or sk_live_... (as secret)
// =============================================================================

// Base64URL decode helper (for Cloudflare Access fallback)
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4;
  if (pad) str += '='.repeat(4 - pad);
  return atob(str);
}

// Get user info from Clerk session using official SDK
async function getUserEmail(request, env) {
  // Check for Clerk session token in cookie or Authorization header
  const cookies = request.headers.get('Cookie') || '';
  const authHeader = request.headers.get('Authorization') || '';

  let token = null;

  // Try Authorization header first (Bearer token)
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  // Try __session cookie (Clerk's default session cookie)
  if (!token) {
    const sessionMatch = cookies.match(/__session=([^;]+)/);
    if (sessionMatch) {
      token = sessionMatch[1];
    }
  }

  // Also check __clerk_db_jwt for development
  if (!token) {
    const devMatch = cookies.match(/__clerk_db_jwt=([^;]+)/);
    if (devMatch) {
      token = devMatch[1];
    }
  }

  if (!token) return null;

  // Verify the JWT using official Clerk SDK
  const secretKey = env.CLERK_SECRET_KEY;
  if (!secretKey) {
    console.error('CLERK_SECRET_KEY not configured');
    return null;
  }

  try {
    const payload = await verifyToken(token, {
      secretKey,
      // Clerk SDK handles JWKS fetching and caching automatically
    });

    if (!payload) return null;

    // Get user details from Clerk API to fetch email
    // Email is not included in JWT by default for security
    const userId = payload.sub;
    if (!userId) return null;

    const clerkClient = createClerkClient({ secretKey });
    const user = await clerkClient.users.getUser(userId);

    return user.emailAddresses?.[0]?.emailAddress ||
           user.primaryEmailAddress?.emailAddress ||
           userId; // Fall back to user ID if no email
  } catch (e) {
    console.error('Clerk user fetch error:', e.message);
    return null;
  }
}

// Legacy support: Also check Cloudflare Access JWT and API keys
async function getUserEmailWithFallback(request, env) {
  // First try Clerk
  const clerkEmail = await getUserEmail(request, env);
  if (clerkEmail) return clerkEmail;

  // Try API key authentication (for programmatic access)
  const apiKeyEmail = await validateApiKey(request, env);
  if (apiKeyEmail) return apiKeyEmail;

  // Fallback to Cloudflare Access for backwards compatibility
  const cfJwt = request.headers.get('Cf-Access-Jwt-Assertion');
  if (cfJwt) {
    try {
      const parts = cfJwt.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        return payload.email || null;
      }
    } catch (e) {
      // Ignore errors
    }
  }

  return null;
}

// =============================================================================
// API KEY AUTHENTICATION - Programmatic Access
// =============================================================================

// Generate a secure API key
function generateApiKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const key = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `utg_${key}`; // utg = URLsToGo
}

// Hash API key for storage (using SHA-256)
async function hashApiKey(key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Validate API key from request and return user email
async function validateApiKey(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const apiKeyHeader = request.headers.get('X-API-Key') || '';

  let apiKey = null;

  // Check Authorization header (Bearer token)
  if (authHeader.startsWith('Bearer utg_')) {
    apiKey = authHeader.slice(7);
  }
  // Check X-API-Key header
  else if (apiKeyHeader.startsWith('utg_')) {
    apiKey = apiKeyHeader;
  }

  if (!apiKey) return null;

  try {
    const keyHash = await hashApiKey(apiKey);
    const keyPrefix = apiKey.slice(0, 11); // utg_ + first 7 chars

    const result = await env.DB.prepare(`
      SELECT user_email, expires_at FROM api_keys
      WHERE key_hash = ? AND key_prefix = ?
    `).bind(keyHash, keyPrefix).first();

    if (!result) return null;

    // Check expiration
    if (result.expires_at && new Date(result.expires_at) < new Date()) {
      return null;
    }

    // Update last_used_at
    await env.DB.prepare(`
      UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ?
    `).bind(keyHash).run();

    return result.user_email;
  } catch (e) {
    console.error('API key validation error:', e.message);
    return null;
  }
}

// Parse click data from request headers
function parseClickData(request) {
  const userAgent = request.headers.get('User-Agent') || '';
  const referrer = request.headers.get('Referer') || '';

  // Cloudflare provides geo data in headers
  const country = request.cf?.country || request.headers.get('CF-IPCountry') || '';
  const city = request.cf?.city || '';

  // Parse device type and browser from User-Agent
  const deviceType = parseDeviceType(userAgent);
  const browser = parseBrowser(userAgent);

  return { userAgent, referrer, country, city, deviceType, browser };
}

// Parse device type from User-Agent
function parseDeviceType(ua) {
  const lowerUA = ua.toLowerCase();
  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(lowerUA)) {
    return 'mobile';
  } else if (/tablet|ipad|playbook|silk/i.test(lowerUA)) {
    return 'tablet';
  } else if (/bot|crawler|spider|crawling/i.test(lowerUA)) {
    return 'bot';
  }
  return 'desktop';
}

// Parse browser from User-Agent
function parseBrowser(ua) {
  if (/edg/i.test(ua)) return 'Edge';
  if (/chrome/i.test(ua) && !/edg/i.test(ua)) return 'Chrome';
  if (/safari/i.test(ua) && !/chrome/i.test(ua)) return 'Safari';
  if (/firefox/i.test(ua)) return 'Firefox';
  if (/opera|opr/i.test(ua)) return 'Opera';
  if (/msie|trident/i.test(ua)) return 'IE';
  return 'Other';
}

// Rate limiting configuration
// These defaults can be overridden via environment variables in wrangler.toml:
//   [vars]
//   RATE_LIMIT_CREATE = "30"
//   RATE_LIMIT_DELETE = "30"
//   RATE_LIMIT_SEARCH = "60"
//   RATE_LIMIT_IMPORT = "5"
//   RATE_LIMIT_REDIRECT = "300"
//   RATE_LIMIT_DEFAULT = "100"
//   RATE_LIMIT_WINDOW = "60"
function getRateLimits(env) {
  const windowSeconds = parseInt(env?.RATE_LIMIT_WINDOW) || 60;
  return {
    'api/links:POST': { limit: parseInt(env?.RATE_LIMIT_CREATE) || 30, windowSeconds },
    'api/links:DELETE': { limit: parseInt(env?.RATE_LIMIT_DELETE) || 30, windowSeconds },
    'api/preview-links:PUT': { limit: parseInt(env?.RATE_LIMIT_PREVIEW) || 30, windowSeconds },
    'api/search': { limit: parseInt(env?.RATE_LIMIT_SEARCH) || 60, windowSeconds },
    'api/import': { limit: parseInt(env?.RATE_LIMIT_IMPORT) || 5, windowSeconds },
    'redirect': { limit: parseInt(env?.RATE_LIMIT_REDIRECT) || 300, windowSeconds },
    'default': { limit: parseInt(env?.RATE_LIMIT_DEFAULT) || 100, windowSeconds }
  };
}

// Check rate limit - returns { allowed: boolean, remaining: number, resetAt: Date }
async function checkRateLimit(env, identifier, endpoint) {
  const rateLimits = getRateLimits(env);
  const config = rateLimits[endpoint] || rateLimits['default'];
  const windowStart = new Date(Date.now() - config.windowSeconds * 1000).toISOString();

  // Clean up old entries (older than 5 minutes)
  await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < datetime("now", "-5 minutes")').run();

  // Get current count
  const existing = await env.DB.prepare(`
    SELECT request_count, window_start FROM rate_limits
    WHERE identifier = ? AND endpoint = ? AND window_start > ?
  `).bind(identifier, endpoint, windowStart).first();

  if (existing) {
    if (existing.request_count >= config.limit) {
      const resetAt = new Date(new Date(existing.window_start).getTime() + config.windowSeconds * 1000);
      return { allowed: false, remaining: 0, resetAt };
    }

    // Increment counter
    await env.DB.prepare(`
      UPDATE rate_limits SET request_count = request_count + 1
      WHERE identifier = ? AND endpoint = ?
    `).bind(identifier, endpoint).run();

    return { allowed: true, remaining: config.limit - existing.request_count - 1, resetAt: null };
  }

  // Create new entry
  await env.DB.prepare(`
    INSERT OR REPLACE INTO rate_limits (identifier, endpoint, request_count, window_start)
    VALUES (?, ?, 1, CURRENT_TIMESTAMP)
  `).bind(identifier, endpoint).run();

  return { allowed: true, remaining: config.limit - 1, resetAt: null };
}

// Get rate limit response headers
function getRateLimitHeaders(env, result, endpoint) {
  const rateLimits = getRateLimits(env);
  const config = rateLimits[endpoint] || rateLimits['default'];
  return {
    'X-RateLimit-Limit': config.limit.toString(),
    'X-RateLimit-Remaining': Math.max(0, result.remaining).toString(),
    'X-RateLimit-Reset': result.resetAt ? Math.floor(result.resetAt.getTime() / 1000).toString() : ''
  };
}

// Rate limit exceeded response
function rateLimitExceeded(result) {
  return new Response(JSON.stringify({
    error: 'Rate limit exceeded',
    retryAfter: result.resetAt ? Math.ceil((result.resetAt.getTime() - Date.now()) / 1000) : 60
  }), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'Retry-After': result.resetAt ? Math.ceil((result.resetAt.getTime() - Date.now()) / 1000).toString() : '60'
    }
  });
}

// Validate URL format
function validateUrl(url) {
  if (!url || typeof url !== 'string') {
    return { valid: false, error: 'URL is required' };
  }

  // Trim whitespace
  url = url.trim();

  // Check for minimum length
  if (url.length < 10) {
    return { valid: false, error: 'URL is too short' };
  }

  // Check for maximum length
  if (url.length > 2048) {
    return { valid: false, error: 'URL is too long (max 2048 characters)' };
  }

  // Try to parse as URL
  try {
    const parsed = new URL(url);

    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }

    // Check for valid hostname
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return { valid: false, error: 'Invalid hostname' };
    }

    // Block potentially dangerous patterns
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.startsWith('127.') || hostname.startsWith('0.')) {
      return { valid: false, error: 'Local URLs are not allowed' };
    }

    return { valid: true, url: parsed.href };
  } catch (e) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

// Validate short code format
function validateCode(code) {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Short code is required' };
  }

  // Trim whitespace
  code = code.trim();

  // Check length
  if (code.length < 2) {
    return { valid: false, error: 'Short code must be at least 2 characters' };
  }
  if (code.length > 50) {
    return { valid: false, error: 'Short code must be at most 50 characters' };
  }

  // Only allow alphanumeric, hyphens, and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
    return { valid: false, error: 'Short code can only contain letters, numbers, hyphens, and underscores' };
  }

  // Reserved paths
  const reserved = ['admin', 'api', 'static', 'assets', 'favicon', 'robots', 'sitemap'];
  if (reserved.includes(code.toLowerCase())) {
    return { valid: false, error: 'This short code is reserved' };
  }

  return { valid: true, code };
}

// =============================================================================
// PASSWORD HASHING - PBKDF2 with 100,000 iterations (OWASP recommended)
// =============================================================================

// Hash password using PBKDF2 with random salt
async function hashPassword(password) {
  // Generate 16-byte random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  // Import password as key material
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive key using PBKDF2 with 100,000 iterations (OWASP recommended)
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 32 bytes
  );

  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');

  // Return pbkdf2:salt:hash format (prefixed to identify algorithm)
  return 'pbkdf2:' + saltHex + ':' + hashHex;
}

// Verify password against stored hash (supports legacy SHA-256 and new PBKDF2)
async function verifyPassword(password, storedHash) {
  const encoder = new TextEncoder();

  // Check if it's new PBKDF2 format (pbkdf2:salt:hash)
  if (storedHash.startsWith('pbkdf2:')) {
    const parts = storedHash.split(':');
    if (parts.length !== 3) return false;

    const saltHex = parts[1];
    const storedHashHex = parts[2];

    // Convert salt hex back to Uint8Array
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    // Derive key using same parameters
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    const computedHash = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Use constant-time comparison to prevent timing attacks
    return timingSafeEqual(computedHash, storedHashHex);
  }

  // Legacy format: salt:hash (old SHA-256 salted)
  const [salt, hash] = storedHash.split(':');

  if (hash) {
    // Old salted SHA-256 format
    const data = encoder.encode(salt + password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const computedHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    return timingSafeEqual(computedHash, hash);
  }

  // Very old unsalted format (legacy fallback)
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const computedHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return timingSafeEqual(computedHash, storedHash);
}

// Constant-time string comparison to prevent timing attacks
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Generate HTML for password prompt
function getPasswordHTML(code, error = false) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Required - URLsToGo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #09090b;
      color: #fafafa;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      text-align: center;
      padding: 40px;
      max-width: 400px;
    }
    .icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 24px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon svg { width: 40px; height: 40px; color: white; }
    h1 { font-size: 28px; margin-bottom: 12px; }
    p { color: #a1a1aa; font-size: 16px; margin-bottom: 24px; }
    form { display: flex; flex-direction: column; gap: 16px; }
    input {
      padding: 12px 16px;
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 8px;
      color: #fafafa;
      font-size: 16px;
    }
    input:focus { outline: none; border-color: #6366f1; }
    button {
      padding: 12px 24px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      border: none;
      border-radius: 8px;
      color: white;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
    }
    button:hover { opacity: 0.9; }
    .error { color: #f87171; font-size: 14px; margin-top: -8px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <h1>Password Required</h1>
    <p>This link is protected. Please enter the password to continue.</p>
    <form method="POST">
      <input type="password" name="password" placeholder="Enter password" required autofocus>
      ${error ? '<div class="error">Incorrect password. Please try again.</div>' : ''}
      <button type="submit">Unlock Link</button>
    </form>
  </div>
</body>
</html>`;
}

// Generate HTML for login/signup pages with Clerk
function getAuthPageHTML(env, mode = 'login') {
  const publishableKey = env.CLERK_PUBLISHABLE_KEY || '';
  const isSignup = mode === 'signup';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${isSignup ? 'Sign Up' : 'Login'} - URLsToGo</title>
  <meta name="description" content="${isSignup ? 'Create your URLsToGo account' : 'Login to URLsToGo'}">
  <link rel="icon" href="${ADMIN_FAVICON}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-primary: #09090b;
      --bg-secondary: #18181b;
      --bg-tertiary: #27272a;
      --text-primary: #fafafa;
      --text-secondary: #a1a1aa;
      --text-muted: #71717a;
      --accent-indigo: #6366f1;
      --accent-purple: #a855f7;
      --accent-violet: #8b5cf6;
      --border-color: #27272a;
      --gradient-primary: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.6;
    }

    /* Animated gradient background */
    .auth-page {
      position: relative;
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 24px;
      overflow: hidden;
    }

    .auth-page::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background:
        radial-gradient(ellipse at 30% 20%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
        radial-gradient(ellipse at 70% 80%, rgba(168, 85, 247, 0.15) 0%, transparent 50%);
      animation: gradientShift 15s ease-in-out infinite;
      pointer-events: none;
    }

    @keyframes gradientShift {
      0%, 100% { transform: translate(0, 0) rotate(0deg); }
      33% { transform: translate(2%, 2%) rotate(1deg); }
      66% { transform: translate(-2%, -1%) rotate(-1deg); }
    }

    /* Grid pattern overlay */
    .auth-page::after {
      content: '';
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
      background-size: 60px 60px;
      pointer-events: none;
    }

    /* Navigation */
    .nav {
      position: relative;
      z-index: 10;
      padding: 20px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
      border-bottom: 1px solid var(--border-color);
    }

    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-primary);
    }

    .nav-logo {
      width: 40px;
      height: 40px;
      background: var(--gradient-primary);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .nav-logo svg { width: 22px; height: 22px; color: white; }

    .nav-title {
      font-size: 20px;
      font-weight: 700;
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    /* Auth container */
    .auth-container {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 440px;
    }

    .auth-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px;
      box-shadow: 0 20px 50px rgba(0,0,0,0.5);
    }

    .auth-header {
      text-align: center;
      margin-bottom: 32px;
    }

    .auth-logo {
      width: 64px;
      height: 64px;
      background: var(--gradient-primary);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 20px;
    }

    .auth-logo svg { width: 32px; height: 32px; color: white; }

    .auth-title {
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 8px;
    }

    .auth-subtitle {
      color: var(--text-secondary);
      font-size: 15px;
    }

    /* Clerk container styling */
    #clerk-auth {
      min-height: 300px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .auth-loading {
      text-align: center;
      padding: 40px;
      color: var(--text-muted);
    }

    .auth-loading-spinner {
      width: 32px;
      height: 32px;
      border: 3px solid var(--border-color);
      border-top-color: var(--accent-violet);
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* Auth toggle */
    .auth-toggle {
      text-align: center;
      margin-top: 24px;
      padding-top: 24px;
      border-top: 1px solid var(--border-color);
      color: var(--text-secondary);
      font-size: 14px;
    }

    .auth-toggle a {
      color: var(--accent-violet);
      text-decoration: none;
      font-weight: 500;
    }

    .auth-toggle a:hover {
      text-decoration: underline;
    }

    /* Error state */
    .auth-error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      color: #fca5a5;
      font-size: 14px;
      display: none;
    }

    .auth-error.visible {
      display: block;
    }

    /* Clerk component overrides */
    .cl-rootBox {
      width: 100%;
    }

    .cl-card {
      background: transparent !important;
      border: none !important;
      box-shadow: none !important;
    }

    .cl-socialButtonsBlockButton {
      background: var(--bg-tertiary) !important;
      border: 1px solid var(--border-color) !important;
    }

    .cl-formButtonPrimary {
      background: var(--gradient-primary) !important;
    }
  </style>
</head>
<body>
  <!-- Navigation -->
  <nav class="nav">
    <a href="/" class="nav-brand">
      <div class="nav-logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
        </svg>
      </div>
      <span class="nav-title">URLsToGo</span>
    </a>
  </nav>

  <!-- Auth Page -->
  <div class="auth-page">
    <div class="auth-container">
      <div class="auth-card">
        <div class="auth-header">
          <div class="auth-logo">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
          </div>
          <h1 class="auth-title">${isSignup ? 'Create Account' : 'Welcome Back'}</h1>
          <p class="auth-subtitle">${isSignup ? 'Start shortening URLs in seconds' : 'Sign in to manage your links'}</p>
        </div>

        <div id="auth-error" class="auth-error"></div>

        <div id="clerk-auth">
          <div class="auth-loading">
            <div class="auth-loading-spinner"></div>
            <p>Loading...</p>
          </div>
        </div>

        <div class="auth-toggle">
          ${isSignup
            ? 'Already have an account? <a href="/login">Sign in</a>'
            : "Don't have an account? <a href=\"/signup\">Sign up</a>"}
        </div>
      </div>
    </div>
  </div>

  <!-- Clerk JS SDK -->
  <script>
    // Configuration
    const CLERK_PUBLISHABLE_KEY = '${publishableKey}';

    // Shared appearance config for Clerk components
    const CLERK_APPEARANCE = {
      variables: {
        colorPrimary: '#8b5cf6',
        colorBackground: '#18181b',
        colorText: '#fafafa',
        colorTextSecondary: '#a1a1aa',
        colorInputBackground: '#27272a',
        colorInputText: '#fafafa',
        borderRadius: '0.75rem'
      }
    };

    if (!CLERK_PUBLISHABLE_KEY) {
      document.getElementById('auth-error').textContent = 'Authentication not configured. Please set CLERK_PUBLISHABLE_KEY.';
      document.getElementById('auth-error').classList.add('visible');
      document.getElementById('clerk-auth').innerHTML = '';
    } else {
      // Load Clerk SDK using their official pattern
      window.__clerk_publishable_key = CLERK_PUBLISHABLE_KEY;

      const script = document.createElement('script');
      script.setAttribute('data-clerk-publishable-key', CLERK_PUBLISHABLE_KEY);
      script.src = 'https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js';
      script.async = true;
      script.crossOrigin = 'anonymous';

      script.onload = function() {
        // Wait for Clerk to be available on window
        let timeoutId;
        const checkClerk = setInterval(() => {
          if (window.Clerk) {
            clearInterval(checkClerk);
            clearTimeout(timeoutId);
            initClerk();
          }
        }, 50);

        // Timeout after 5 seconds
        timeoutId = setTimeout(() => {
          clearInterval(checkClerk);
          if (!window.Clerk) {
            document.getElementById('auth-error').textContent = 'Authentication timed out. Please refresh the page.';
            document.getElementById('auth-error').classList.add('visible');
            document.getElementById('clerk-auth').innerHTML = '';
          }
        }, 5000);
      };

      script.onerror = () => {
        document.getElementById('auth-error').textContent = 'Failed to load authentication. Please refresh the page.';
        document.getElementById('auth-error').classList.add('visible');
        document.getElementById('clerk-auth').innerHTML = '';
      };

      document.head.appendChild(script);
    }

    async function initClerk() {
      try {
        const clerk = window.Clerk;
        if (!clerk) throw new Error('Clerk not available');

        await clerk.load();

        // Check if already signed in
        if (clerk.user) {
          window.location.href = '${ADMIN_PATH}';
          return;
        }

        // Mount the appropriate component
        const container = document.getElementById('clerk-auth');
        container.innerHTML = '';

        ${isSignup ? `
        clerk.mountSignUp(container, {
          fallbackRedirectUrl: '${ADMIN_PATH}',
          signInUrl: '/login',
          appearance: CLERK_APPEARANCE
        });
        ` : `
        clerk.mountSignIn(container, {
          fallbackRedirectUrl: '${ADMIN_PATH}',
          signUpUrl: '/signup',
          appearance: CLERK_APPEARANCE
        });
        `}
      } catch (error) {
        console.error('Clerk initialization error:', error.message);
        document.getElementById('auth-error').textContent = 'Authentication error: ' + error.message;
        document.getElementById('auth-error').classList.add('visible');
        document.getElementById('clerk-auth').innerHTML = '';
      }
    }
  </script>
</body>
</html>`;
}

// Generate HTML for 404 page
// Generate HTML for public landing page
function getLandingPageHTML() {
  // Reusable SVG icons to reduce duplication
  const LINK_ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>URLsToGo - Fast, Free URL Shortener</title>
  <meta name="description" content="Shorten URLs instantly with URLsToGo. Lightning-fast, secure, and powered by Cloudflare's global edge network.">
  <link rel="icon" href="${ADMIN_FAVICON}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-primary: #09090b;
      --bg-secondary: #18181b;
      --bg-tertiary: #27272a;
      --text-primary: #fafafa;
      --text-secondary: #a1a1aa;
      --text-muted: #71717a;
      --accent-indigo: #6366f1;
      --accent-purple: #a855f7;
      --accent-violet: #8b5cf6;
      --border-color: #27272a;
      --gradient-primary: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      overflow-x: hidden;
      line-height: 1.6;
    }

    /* Animated gradient background */
    .hero {
      position: relative;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .hero::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background:
        radial-gradient(ellipse at 20% 30%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.15) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 50%, rgba(139, 92, 246, 0.1) 0%, transparent 60%);
      animation: gradientShift 15s ease-in-out infinite;
      pointer-events: none;
    }

    @keyframes gradientShift {
      0%, 100% { transform: translate(0, 0) rotate(0deg); }
      33% { transform: translate(2%, 2%) rotate(1deg); }
      66% { transform: translate(-2%, -1%) rotate(-1deg); }
    }

    /* Grid pattern overlay */
    .hero::after {
      content: '';
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
      background-size: 60px 60px;
      pointer-events: none;
    }

    /* Navigation */
    .nav {
      position: relative;
      z-index: 10;
      padding: 20px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
    }

    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-primary);
    }

    .nav-logo {
      width: 40px;
      height: 40px;
      background: var(--gradient-primary);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .nav-logo svg { width: 22px; height: 22px; color: white; }

    .nav-title {
      font-size: 20px;
      font-weight: 700;
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .nav-link {
      padding: 10px 18px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      border-radius: 8px;
      transition: all 0.2s;
    }

    .nav-link:hover {
      color: var(--text-primary);
      background: var(--bg-secondary);
    }

    .nav-cta {
      padding: 10px 20px;
      background: var(--gradient-primary);
      color: white;
      text-decoration: none;
      font-size: 14px;
      font-weight: 600;
      border-radius: 8px;
      transition: all 0.2s;
    }

    .nav-cta:hover {
      opacity: 0.9;
      transform: translateY(-1px);
    }

    /* Hero content */
    .hero-content {
      position: relative;
      z-index: 10;
      flex: 1;
      display: flex;
      align-items: center;
      padding: 40px 24px 80px;
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
    }

    .hero-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 60px;
      align-items: center;
      width: 100%;
    }

    @media (max-width: 968px) {
      .hero-grid {
        grid-template-columns: 1fr;
        text-align: center;
        gap: 48px;
      }
    }

    .hero-text {
      max-width: 560px;
    }

    @media (max-width: 968px) {
      .hero-text {
        max-width: 100%;
        margin: 0 auto;
      }
    }

    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      background: rgba(139, 92, 246, 0.1);
      border: 1px solid rgba(139, 92, 246, 0.2);
      border-radius: 100px;
      font-size: 13px;
      font-weight: 500;
      color: var(--accent-violet);
      margin-bottom: 24px;
    }

    .hero-badge-dot {
      width: 6px;
      height: 6px;
      background: var(--accent-violet);
      border-radius: 50%;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    .hero-title {
      font-size: clamp(40px, 5vw, 60px);
      font-weight: 700;
      line-height: 1.1;
      margin-bottom: 24px;
      letter-spacing: -0.02em;
    }

    .hero-title-gradient {
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .hero-description {
      font-size: 18px;
      color: var(--text-secondary);
      margin-bottom: 36px;
      line-height: 1.7;
    }

    .hero-actions {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 48px;
    }

    @media (max-width: 968px) {
      .hero-actions {
        justify-content: center;
        flex-wrap: wrap;
      }
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 14px 28px;
      font-size: 15px;
      font-weight: 600;
      text-decoration: none;
      border-radius: 10px;
      transition: all 0.2s;
      cursor: pointer;
      border: none;
    }

    .btn-primary {
      background: var(--gradient-primary);
      color: white;
      box-shadow: 0 4px 20px rgba(99, 102, 241, 0.3);
    }

    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 30px rgba(99, 102, 241, 0.4);
    }

    .btn-secondary {
      background: var(--bg-secondary);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
    }

    .btn-secondary:hover {
      background: var(--bg-tertiary);
      border-color: var(--text-muted);
    }

    /* Stats */
    .hero-stats {
      display: flex;
      gap: 40px;
    }

    @media (max-width: 968px) {
      .hero-stats {
        justify-content: center;
      }
    }

    .stat {
      text-align: left;
    }

    @media (max-width: 968px) {
      .stat {
        text-align: center;
      }
    }

    .stat-value {
      font-size: 28px;
      font-weight: 700;
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .stat-label {
      font-size: 13px;
      color: var(--text-muted);
      font-weight: 500;
    }

    /* Dashboard mockup */
    .hero-visual {
      position: relative;
    }

    .dashboard-mockup {
      position: relative;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow:
        0 0 0 1px rgba(255,255,255,0.05),
        0 20px 50px rgba(0,0,0,0.5),
        0 0 100px rgba(99, 102, 241, 0.1);
      transform: perspective(1000px) rotateY(-5deg) rotateX(2deg);
      transition: transform 0.5s ease;
    }

    .dashboard-mockup:hover {
      transform: perspective(1000px) rotateY(-2deg) rotateX(1deg);
    }

    @media (max-width: 968px) {
      .dashboard-mockup {
        transform: none;
        max-width: 500px;
        margin: 0 auto;
      }
      .dashboard-mockup:hover {
        transform: none;
      }
    }

    .mockup-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 16px;
      background: var(--bg-primary);
      border-bottom: 1px solid var(--border-color);
    }

    .mockup-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }

    .mockup-dot.red { background: #ff5f57; }
    .mockup-dot.yellow { background: #febc2e; }
    .mockup-dot.green { background: #28c840; }

    .mockup-url {
      flex: 1;
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      background: var(--bg-secondary);
      padding: 6px 12px;
      border-radius: 6px;
      margin-left: 16px;
    }

    .mockup-content {
      padding: 20px;
    }

    .mockup-sidebar {
      display: flex;
      gap: 20px;
    }

    .mockup-nav {
      width: 180px;
      padding-right: 20px;
      border-right: 1px solid var(--border-color);
    }

    .mockup-nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 4px;
    }

    .mockup-nav-item.active {
      background: rgba(139, 92, 246, 0.1);
      color: var(--accent-violet);
    }

    .mockup-nav-icon {
      width: 18px;
      height: 18px;
      border-radius: 4px;
      background: var(--bg-tertiary);
    }

    .mockup-nav-item.active .mockup-nav-icon {
      background: var(--accent-violet);
    }

    .mockup-main {
      flex: 1;
    }

    .mockup-card {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .mockup-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    .mockup-card-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .mockup-badge {
      font-size: 11px;
      padding: 4px 10px;
      background: rgba(40, 200, 64, 0.1);
      color: #28c840;
      border-radius: 100px;
      font-weight: 500;
    }

    .mockup-links {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .mockup-link {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px;
      background: var(--bg-secondary);
      border-radius: 8px;
    }

    .mockup-link-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .mockup-link-icon {
      width: 32px;
      height: 32px;
      background: var(--gradient-primary);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .mockup-link-icon svg {
      width: 16px;
      height: 16px;
      color: white;
    }

    .mockup-link-text {
      font-size: 13px;
      color: var(--text-primary);
      font-weight: 500;
    }

    .mockup-link-url {
      font-size: 11px;
      color: var(--text-muted);
    }

    .mockup-link-clicks {
      font-size: 12px;
      color: var(--accent-violet);
      font-weight: 600;
    }

    /* Floating elements */
    .floating-card {
      position: absolute;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 14px 18px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.4);
      animation: float 6s ease-in-out infinite;
    }

    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-10px); }
    }

    .floating-card-1 {
      top: -20px;
      right: -30px;
      animation-delay: -2s;
    }

    .floating-card-2 {
      bottom: 40px;
      left: -40px;
      animation-delay: -4s;
    }

    @media (max-width: 968px) {
      .floating-card {
        display: none;
      }
    }

    .floating-stat {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .floating-stat-icon {
      width: 36px;
      height: 36px;
      background: rgba(40, 200, 64, 0.1);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #28c840;
    }

    .floating-stat-icon--indigo {
      background: rgba(99, 102, 241, 0.1);
      color: #6366f1;
    }

    .floating-stat-value {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-primary);
    }

    .floating-stat-label {
      font-size: 11px;
      color: var(--text-muted);
    }

    /* Features section */
    .features-section {
      position: relative;
      z-index: 10;
      padding: 80px 24px;
      background: var(--bg-secondary);
      border-top: 1px solid var(--border-color);
    }

    .features-container {
      max-width: 1200px;
      margin: 0 auto;
    }

    .features-header {
      text-align: center;
      margin-bottom: 60px;
    }

    .features-title {
      font-size: 36px;
      font-weight: 700;
      margin-bottom: 16px;
    }

    .features-subtitle {
      font-size: 18px;
      color: var(--text-secondary);
      max-width: 600px;
      margin: 0 auto;
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 24px;
    }

    .feature-card {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 28px;
      transition: all 0.3s;
    }

    .feature-card:hover {
      border-color: var(--accent-violet);
      transform: translateY(-4px);
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
    }

    .feature-icon {
      width: 48px;
      height: 48px;
      background: var(--gradient-primary);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 20px;
    }

    .feature-icon svg {
      width: 24px;
      height: 24px;
      color: white;
    }

    .feature-name {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 10px;
      color: var(--text-primary);
    }

    .feature-desc {
      font-size: 14px;
      color: var(--text-secondary);
      line-height: 1.6;
    }

    /* How It Works section */
    .how-it-works {
      position: relative;
      z-index: 10;
      padding: 100px 24px;
      background: var(--bg-primary);
      border-top: 1px solid var(--border-color);
      overflow: hidden;
    }

    .how-it-works::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 800px;
      height: 800px;
      background: radial-gradient(ellipse at center, rgba(139, 92, 246, 0.08) 0%, transparent 70%);
      pointer-events: none;
    }

    .how-it-works-container {
      max-width: 1200px;
      margin: 0 auto;
      position: relative;
    }

    .how-it-works-header {
      text-align: center;
      margin-bottom: 80px;
    }

    .how-it-works-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 16px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.2);
      border-radius: 100px;
      font-size: 13px;
      font-weight: 500;
      color: var(--accent-indigo);
      margin-bottom: 20px;
    }

    .how-it-works-title {
      font-size: 40px;
      font-weight: 700;
      margin-bottom: 16px;
      letter-spacing: -0.02em;
    }

    .how-it-works-subtitle {
      font-size: 18px;
      color: var(--text-secondary);
      max-width: 500px;
      margin: 0 auto;
    }

    .steps-container {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 24px;
      position: relative;
    }

    @media (max-width: 868px) {
      .steps-container {
        grid-template-columns: 1fr;
        max-width: 400px;
        margin: 0 auto;
      }
    }

    /* Connecting line between steps */
    .steps-line {
      position: absolute;
      top: 60px;
      left: calc(16.67% + 40px);
      right: calc(16.67% + 40px);
      height: 2px;
      background: linear-gradient(90deg, var(--accent-indigo), var(--accent-purple), var(--accent-violet));
      opacity: 0.3;
    }

    @media (max-width: 868px) {
      .steps-line {
        display: none;
      }
    }

    .step-card {
      position: relative;
      text-align: center;
      padding: 32px 24px;
    }

    .step-number-wrapper {
      position: relative;
      width: 80px;
      height: 80px;
      margin: 0 auto 28px;
    }

    .step-number-bg {
      position: absolute;
      inset: 0;
      background: var(--gradient-primary);
      border-radius: 20px;
      opacity: 0.1;
      transform: rotate(6deg);
      transition: all 0.3s;
    }

    .step-card:hover .step-number-bg {
      transform: rotate(0deg);
      opacity: 0.2;
    }

    .step-number {
      position: relative;
      width: 80px;
      height: 80px;
      background: var(--bg-secondary);
      border: 2px solid var(--border-color);
      border-radius: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      font-weight: 700;
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      transition: all 0.3s;
    }

    .step-card:hover .step-number {
      border-color: var(--accent-violet);
      box-shadow: 0 0 30px rgba(139, 92, 246, 0.2);
    }

    .step-icon {
      position: absolute;
      bottom: -8px;
      right: -8px;
      width: 36px;
      height: 36px;
      background: var(--gradient-primary);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
    }

    .step-icon svg {
      width: 18px;
      height: 18px;
      color: white;
    }

    .step-title {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 12px;
      color: var(--text-primary);
    }

    .step-description {
      font-size: 15px;
      color: var(--text-secondary);
      line-height: 1.6;
      max-width: 280px;
      margin: 0 auto;
    }

    /* Animated arrow between steps on desktop */
    .step-arrow {
      display: none;
    }

    @media (min-width: 869px) {
      .step-arrow {
        display: flex;
        align-items: center;
        justify-content: center;
        position: absolute;
        top: 52px;
        width: 32px;
        height: 32px;
        color: var(--accent-violet);
        animation: arrowPulse 2s ease-in-out infinite;
      }

      .step-arrow-1 {
        left: calc(33.33% - 16px);
      }

      .step-arrow-2 {
        left: calc(66.67% - 16px);
      }

      @keyframes arrowPulse {
        0%, 100% { opacity: 0.5; transform: translateX(0); }
        50% { opacity: 1; transform: translateX(4px); }
      }
    }

    /* Footer */
    .footer {
      position: relative;
      z-index: 10;
      padding: 40px 24px;
      border-top: 1px solid var(--border-color);
      text-align: center;
    }

    .footer-content {
      max-width: 1200px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    @media (max-width: 640px) {
      .footer-content {
        flex-direction: column;
        gap: 16px;
      }
    }

    .footer-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-secondary);
      font-size: 14px;
      text-decoration: none;
      transition: color 0.2s;
    }

    .footer-brand:hover {
      color: var(--text-primary);
    }

    .footer-logo {
      width: 24px;
      height: 24px;
      background: var(--gradient-primary);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .footer-logo svg {
      width: 14px;
      height: 14px;
      color: white;
    }

    .footer-text {
      color: var(--text-muted);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="hero">
    <!-- Navigation -->
    <nav class="nav">
      <a href="/" class="nav-brand">
        <div class="nav-logo">
          \${LINK_ICON}
        </div>
        <span class="nav-title">URLsToGo</span>
      </a>
      <div class="nav-links">
        <a href="#features" class="nav-link">Features</a>
        <a href="#how-it-works" class="nav-link">How It Works</a>
        <a href="/admin" class="nav-cta">Dashboard</a>
      </div>
    </nav>

    <!-- Hero Content -->
    <div class="hero-content">
      <div class="hero-grid">
        <div class="hero-text">
          <div class="hero-badge">
            <span class="hero-badge-dot"></span>
            Powered by Cloudflare Edge
          </div>
          <h1 class="hero-title">
            Shorten URLs<br>
            <span class="hero-title-gradient">at the speed of light</span>
          </h1>
          <p class="hero-description">
            Create, manage, and track your shortened URLs with our lightning-fast platform.
            Organize with categories and tags, get real-time analytics, and deploy globally on Cloudflare's edge network.
          </p>
          <div class="hero-actions">
            <a href="/admin" class="btn btn-primary">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M5 12h14"/>
                <path d="m12 5 7 7-7 7"/>
              </svg>
              Get Started Free
            </a>
            <a href="#features" class="btn btn-secondary">
              Learn More
            </a>
          </div>
          <div class="hero-stats">
            <div class="stat">
              <div class="stat-value">&lt;50ms</div>
              <div class="stat-label">Global Latency</div>
            </div>
            <div class="stat">
              <div class="stat-value">300+</div>
              <div class="stat-label">Edge Locations</div>
            </div>
            <div class="stat">
              <div class="stat-value">99.9%</div>
              <div class="stat-label">Uptime SLA</div>
            </div>
          </div>
        </div>

        <div class="hero-visual">
          <!-- Floating stats -->
          <div class="floating-card floating-card-1">
            <div class="floating-stat">
              <div class="floating-stat-icon">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/>
                  <polyline points="16 7 22 7 22 13"/>
                </svg>
              </div>
              <div>
                <div class="floating-stat-value">+127%</div>
                <div class="floating-stat-label">Click growth</div>
              </div>
            </div>
          </div>

          <div class="floating-card floating-card-2">
            <div class="floating-stat">
              <div class="floating-stat-icon floating-stat-icon--indigo">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10"/>
                  <polyline points="12 6 12 12 16 14"/>
                </svg>
              </div>
              <div>
                <div class="floating-stat-value">12ms</div>
                <div class="floating-stat-label">Avg response</div>
              </div>
            </div>
          </div>

          <!-- Dashboard mockup -->
          <div class="dashboard-mockup">
            <div class="mockup-header">
              <div class="mockup-dot red"></div>
              <div class="mockup-dot yellow"></div>
              <div class="mockup-dot green"></div>
              <div class="mockup-url">urlstogo.cloud/admin</div>
            </div>
            <div class="mockup-content">
              <div class="mockup-sidebar">
                <div class="mockup-nav">
                  <div class="mockup-nav-item active">
                    <div class="mockup-nav-icon"></div>
                    <span>All Links</span>
                  </div>
                  <div class="mockup-nav-item">
                    <div class="mockup-nav-icon"></div>
                    <span>Categories</span>
                  </div>
                  <div class="mockup-nav-item">
                    <div class="mockup-nav-icon"></div>
                    <span>Analytics</span>
                  </div>
                  <div class="mockup-nav-item">
                    <div class="mockup-nav-icon"></div>
                    <span>Settings</span>
                  </div>
                </div>
                <div class="mockup-main">
                  <div class="mockup-card">
                    <div class="mockup-card-header">
                      <div class="mockup-card-title">Recent Links</div>
                      <div class="mockup-badge">Live</div>
                    </div>
                    <div class="mockup-links">
                      <div class="mockup-link">
                        <div class="mockup-link-left">
                          <div class="mockup-link-icon">
                            \${LINK_ICON}
                          </div>
                          <div>
                            <div class="mockup-link-text">urlstogo.cloud/abc123</div>
                            <div class="mockup-link-url">github.com/project</div>
                          </div>
                        </div>
                        <div class="mockup-link-clicks">2,847 clicks</div>
                      </div>
                      <div class="mockup-link">
                        <div class="mockup-link-left">
                          <div class="mockup-link-icon">
                            \${LINK_ICON}
                          </div>
                          <div>
                            <div class="mockup-link-text">urlstogo.cloud/docs</div>
                            <div class="mockup-link-url">documentation.site</div>
                          </div>
                        </div>
                        <div class="mockup-link-clicks">1,234 clicks</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Features Section -->
  <section id="features" class="features-section">
    <div class="features-container">
      <div class="features-header">
        <h2 class="features-title">Everything you need</h2>
        <p class="features-subtitle">
          A complete URL management solution with powerful features built for speed and simplicity.
        </p>
      </div>
      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
          </div>
          <h3 class="feature-name">Lightning Fast</h3>
          <p class="feature-desc">
            Redirects in under 50ms globally. Powered by Cloudflare's edge network spanning 300+ cities worldwide.
          </p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <h3 class="feature-name">Enterprise Security</h3>
          <p class="feature-desc">
            Protected by Cloudflare Access with SSO integration. Your links and data are always secure.
          </p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M3 3v18h18"/>
              <path d="m19 9-5 5-4-4-3 3"/>
            </svg>
          </div>
          <h3 class="feature-name">Real-time Analytics</h3>
          <p class="feature-desc">
            Track clicks, referrers, and geographic data in real-time. Understand how your links perform.
          </p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/>
              <path d="M7 7h.01"/>
            </svg>
          </div>
          <h3 class="feature-name">Categories & Tags</h3>
          <p class="feature-desc">
            Organize your links with custom categories and tags. Find any link instantly with powerful search.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- How It Works Section -->
  <section id="how-it-works" class="how-it-works">
    <div class="how-it-works-container">
      <div class="how-it-works-header">
        <div class="how-it-works-badge">Simple & Fast</div>
        <h2 class="how-it-works-title">How It Works</h2>
        <p class="how-it-works-subtitle">
          Get started in seconds. No signup required, just paste and go.
        </p>
      </div>

      <div class="steps-container">
        <!-- Connecting line -->
        <div class="steps-line"></div>

        <!-- Animated arrows -->
        <div class="step-arrow step-arrow-1">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M5 12h14"/>
            <path d="m12 5 7 7-7 7"/>
          </svg>
        </div>
        <div class="step-arrow step-arrow-2">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M5 12h14"/>
            <path d="m12 5 7 7-7 7"/>
          </svg>
        </div>

        <!-- Step 1 -->
        <div class="step-card">
          <div class="step-number-wrapper">
            <div class="step-number-bg"></div>
            <div class="step-number">1</div>
            <div class="step-icon">
              \${LINK_ICON}
            </div>
          </div>
          <h3 class="step-title">Paste Your URL</h3>
          <p class="step-description">
            Enter any long URL into the dashboard. Customize your short code or let us generate one automatically.
          </p>
        </div>

        <!-- Step 2 -->
        <div class="step-card">
          <div class="step-number-wrapper">
            <div class="step-number-bg"></div>
            <div class="step-number">2</div>
            <div class="step-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="18" cy="5" r="3"/>
                <circle cx="6" cy="12" r="3"/>
                <circle cx="18" cy="19" r="3"/>
                <line x1="8.59" x2="15.42" y1="13.51" y2="17.49"/>
                <line x1="15.41" x2="8.59" y1="6.51" y2="10.49"/>
              </svg>
            </div>
          </div>
          <h3 class="step-title">Share Anywhere</h3>
          <p class="step-description">
            Copy your short link and share it on social media, emails, messages, or anywhere you need.
          </p>
        </div>

        <!-- Step 3 -->
        <div class="step-card">
          <div class="step-number-wrapper">
            <div class="step-number-bg"></div>
            <div class="step-number">3</div>
            <div class="step-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M3 3v18h18"/>
                <path d="m19 9-5 5-4-4-3 3"/>
              </svg>
            </div>
          </div>
          <h3 class="step-title">Track Performance</h3>
          <p class="step-description">
            Monitor clicks, analyze traffic sources, and optimize your campaigns with real-time analytics.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="footer">
    <div class="footer-content">
      <a href="/" class="footer-brand">
        <div class="footer-logo">
          \${LINK_ICON}
        </div>
        URLsToGo
      </a>
      <div class="footer-text">
        Powered by Cloudflare Workers
      </div>
    </div>
  </footer>
</body>
</html>`;
}

function get404HTML(code) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Not Found - URLsToGo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #09090b;
      color: #fafafa;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      text-align: center;
      padding: 40px;
    }
    .icon {
      width: 100px;
      height: 100px;
      margin: 0 auto 24px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon svg { width: 50px; height: 50px; color: white; }
    .code-404 {
      font-size: 72px;
      font-weight: 700;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      line-height: 1;
      margin-bottom: 16px;
    }
    h1 { font-size: 28px; margin-bottom: 12px; }
    p { color: #a1a1aa; font-size: 16px; max-width: 400px; margin: 0 auto 24px; }
    .code-display {
      display: inline-block;
      padding: 8px 16px;
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 8px;
      font-family: monospace;
      font-size: 14px;
      color: #a855f7;
      margin-bottom: 24px;
    }
    .home-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      border-radius: 8px;
      color: white;
      text-decoration: none;
      font-weight: 500;
      transition: opacity 0.2s;
    }
    .home-link:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <div class="container">
    <div class="code-404">404</div>
    <h1>Link Not Found</h1>
    <p>The short link you're looking for doesn't exist or may have been removed.</p>
    <div class="code-display">/${code}</div>
    <div>
      <a href="/" class="home-link">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
          <polyline points="9 22 9 12 15 12 15 22"/>
        </svg>
        Go Home
      </a>
    </div>
  </div>
</body>
</html>`;
}

// Generate HTML for expired links
function getExpiredHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Expired - URLsToGo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #09090b;
      color: #fafafa;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      text-align: center;
      padding: 40px;
    }
    .icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 24px;
      background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon svg { width: 40px; height: 40px; color: white; }
    h1 { font-size: 28px; margin-bottom: 12px; }
    p { color: #a1a1aa; font-size: 16px; max-width: 400px; margin: 0 auto; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <polyline points="12 6 12 12 16 14"/>
      </svg>
    </div>
    <h1>Link Expired</h1>
    <p>This short link is no longer active. It may have reached its expiration date.</p>
  </div>
</body>
</html>`;
}

function getAdminHTML(userEmail, env) {
  const clerkPublishableKey = env?.CLERK_PUBLISHABLE_KEY || '';

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>URLsToGo - Admin</title>
  <meta name="description" content="Manage your shortened URLs">
  <meta name="theme-color" content="#8b5cf6">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="URLsToGo">
  <link rel="icon" type="image/svg+xml" href="${ADMIN_FAVICON}">
  <link rel="manifest" href="/manifest.json">
  <link rel="apple-touch-icon" href="/icon-192.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  ${clerkPublishableKey ? `<script data-clerk-publishable-key="${clerkPublishableKey}" src="https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js" crossorigin="anonymous"></script>` : ''}
  <style>
    :root {
      --background: 0.1430 0.0219 293.0857;
      --foreground: 0.9842 0.0034 247.8575;
      --card: 0.1831 0.0284 289.8409;
      --card-foreground: 0.9842 0.0034 247.8575;
      --popover: 0.1831 0.0284 289.8409;
      --popover-foreground: 0.9842 0.0034 247.8575;
      --primary: 0.6056 0.2189 292.7172;
      --primary-foreground: 1.0000 0 0;
      --secondary: 0.2352 0.0362 290.5754;
      --secondary-foreground: 0.9842 0.0034 247.8575;
      --muted: 0.2352 0.0362 290.5754;
      --muted-foreground: 0.7000 0.0100 285.0000;
      --accent: 0.3043 0.0569 286.7954;
      --accent-foreground: 0.9842 0.0034 247.8575;
      --destructive: 0.6368 0.2078 25.3313;
      --destructive-foreground: 1.0000 0 0;
      --border: 0.2352 0.0362 290.5754;
      --input: 0.2352 0.0362 290.5754;
      --ring: 0.6056 0.2189 292.7172;
      --radius: 0.75rem;
      --indigo: 0.6056 0.2189 292.7172;
      --purple: 0.6368 0.2078 307.3313;
      --cat-work: 0.6850 0.2190 307.0000;
      --cat-personal: 0.6520 0.2450 340.0000;
      --cat-social: 0.6000 0.1700 210.0000;
      --cat-marketing: 0.6800 0.2000 50.0000;
      --cat-docs: 0.5800 0.1500 165.0000;
    }
    /* Light mode variables */
    .light {
      --background: 0.9946 0.0026 286.3519;
      --foreground: 0.1430 0.0219 293.0857;
      --card: 1.0000 0 0;
      --card-foreground: 0.1430 0.0219 293.0857;
      --popover: 1.0000 0 0;
      --popover-foreground: 0.1430 0.0219 293.0857;
      --primary: 0.6056 0.2189 292.7172;
      --primary-foreground: 1.0000 0 0;
      --secondary: 0.9276 0.0058 264.5313;
      --secondary-foreground: 0.2781 0.0296 256.8480;
      --muted: 0.9276 0.0058 264.5313;
      --muted-foreground: 0.5000 0.0150 280.0000;
      --accent: 0.9433 0.0284 294.5878;
      --accent-foreground: 0.4320 0.2106 292.7591;
      --destructive: 0.6368 0.2078 25.3313;
      --destructive-foreground: 1.0000 0 0;
      --border: 0.9288 0.0126 255.5078;
      --input: 0.9288 0.0126 255.5078;
      --ring: 0.6056 0.2189 292.7172;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      background: oklch(var(--background));
      color: oklch(var(--foreground));
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    .app-layout { display: flex; min-height: 100vh; }

    /* Sidebar */
    .sidebar {
      width: 256px;
      background: oklch(var(--card));
      border-right: 1px solid oklch(var(--border));
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0; left: 0; bottom: 0;
      z-index: 40;
    }
    .sidebar-header {
      height: 56px;
      padding: 0 16px;
      display: flex;
      align-items: center;
      border-bottom: 1px solid oklch(var(--border));
    }
    .logo { display: flex; align-items: center; gap: 8px; }
    .logo-icon {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
    }
    .logo-icon svg { width: 18px; height: 18px; color: white; }
    .logo-text { font-size: 16px; font-weight: 600; letter-spacing: -0.025em; }
    .sidebar-content { flex: 1; padding: 16px 12px; overflow-y: auto; }
    .nav-group { margin-bottom: 24px; }
    .nav-group-label {
      padding: 0 12px; margin-bottom: 4px;
      font-size: 12px; font-weight: 500;
      color: oklch(var(--muted-foreground));
    }
    .nav-item {
      display: flex; align-items: center; gap: 12px;
      padding: 8px 12px;
      border-radius: calc(var(--radius) - 2px);
      color: oklch(var(--muted-foreground));
      font-size: 14px;
      cursor: pointer;
      transition: all 150ms;
    }
    .nav-item:hover { background: oklch(var(--accent)); color: oklch(var(--accent-foreground)); }
    .nav-item:active { transform: scale(0.98); opacity: 0.9; }
    .nav-item.active { background: oklch(var(--secondary)); color: oklch(var(--secondary-foreground)); }
    .nav-item-icon { width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; }
    .nav-item-icon svg { width: 16px; height: 16px; }
    .nav-item-badge { margin-left: auto; font-size: 12px; color: oklch(var(--muted-foreground)); }
    .cat-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .cat-dot.work, .cat-dot.violet { background: oklch(var(--cat-work)); }
    .cat-dot.personal, .cat-dot.pink { background: oklch(var(--cat-personal)); }
    .cat-dot.social, .cat-dot.cyan { background: oklch(var(--cat-social)); }
    .cat-dot.marketing, .cat-dot.orange { background: oklch(var(--cat-marketing)); }
    .cat-dot.docs, .cat-dot.green { background: oklch(var(--cat-docs)); }
    .cat-dot.gray { background: oklch(var(--muted-foreground)); }
    .sidebar-footer { padding: 12px; border-top: 1px solid oklch(var(--border)); }
    .user-button {
      display: flex; align-items: center; gap: 12px;
      width: 100%; padding: 8px 12px;
      border-radius: calc(var(--radius) - 2px);
      background: transparent; border: none;
      color: oklch(var(--foreground));
      cursor: pointer;
      transition: background 150ms;
      text-align: left;
    }
    .user-button:hover { background: oklch(var(--accent)); }
    .user-button-icon { margin-left: auto; opacity: 0.5; }
    .hidden-input { display: none; }
    .avatar {
      width: 32px; height: 32px;
      border-radius: 50%;
      background: linear-gradient(135deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%);
      display: flex; align-items: center; justify-content: center;
      font-size: 12px; font-weight: 600; color: white;
    }
    .user-info { flex: 1; min-width: 0; }
    .user-name { font-size: 14px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .user-email { font-size: 12px; color: oklch(var(--muted-foreground)); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    /* Main */
    .main { flex: 1; margin-left: 256px; display: flex; flex-direction: column; }
    .header {
      height: 56px;
      background: oklch(var(--background));
      border-bottom: 1px solid oklch(var(--border));
      display: flex; align-items: center;
      padding: 0 24px; gap: 16px;
      position: sticky; top: 0; z-index: 30;
    }

    /* Search */
    .search { flex: 1; max-width: 512px; position: relative; }
    .search-trigger {
      display: flex; align-items: center;
      width: 100%; height: 36px; padding: 0 12px;
      background: oklch(var(--secondary));
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      color: oklch(var(--muted-foreground));
      font-size: 14px;
      cursor: pointer;
      transition: all 150ms;
    }
    .search-trigger:hover { background: oklch(var(--accent)); }
    .search-trigger svg { width: 16px; height: 16px; margin-right: 8px; flex-shrink: 0; }
    .search-trigger span { flex: 1; text-align: left; }
    .search-kbd {
      display: inline-flex; align-items: center; gap: 2px;
      font-size: 11px; font-family: inherit;
      background: oklch(var(--muted));
      padding: 2px 6px; border-radius: 4px;
      color: oklch(var(--muted-foreground));
    }
    .search-dialog {
      position: absolute;
      top: calc(100% + 8px); left: 0; right: 0;
      background: oklch(var(--popover));
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
      overflow: hidden;
      display: none;
      z-index: 50;
    }
    .search-dialog.open { display: block; animation: fadeIn 150ms ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
    .search-input-wrapper {
      display: flex; align-items: center;
      padding: 12px;
      border-bottom: 1px solid oklch(var(--border));
    }
    .search-input-wrapper svg { width: 16px; height: 16px; color: oklch(var(--muted-foreground)); margin-right: 8px; flex-shrink: 0; }
    .search-input {
      flex: 1;
      background: transparent; border: none; outline: none;
      color: oklch(var(--foreground));
      font-size: 14px;
    }
    .search-input::placeholder { color: oklch(var(--muted-foreground)); }
    .search-spinner {
      width: 16px; height: 16px;
      border: 2px solid oklch(var(--muted));
      border-top-color: oklch(var(--foreground));
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
      display: none;
    }
    .search-spinner.loading { display: block; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .search-results { max-height: 300px; overflow-y: auto; padding: 4px; }
    .search-group { padding: 8px 8px 4px; }
    .search-group-label { font-size: 12px; font-weight: 500; color: oklch(var(--muted-foreground)); padding: 0 8px 4px; }
    .search-item {
      display: flex; align-items: center; gap: 12px;
      padding: 8px 12px;
      border-radius: calc(var(--radius) - 2px);
      cursor: pointer;
      transition: background 150ms;
    }
    .search-item:hover { background: oklch(var(--accent)); }
    .search-item-code {
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 13px;
      color: oklch(var(--indigo));
      background: oklch(var(--indigo) / 0.1);
      padding: 2px 8px; border-radius: 4px;
    }
    .search-item-url {
      flex: 1; font-size: 13px;
      color: oklch(var(--muted-foreground));
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .search-empty { padding: 24px; text-align: center; color: oklch(var(--muted-foreground)); }
    .header-actions { display: flex; align-items: center; gap: 8px; }
    .page { flex: 1; padding: 24px; }

    /* Buttons */
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 8px;
      height: 36px; padding: 0 16px;
      font-size: 14px; font-weight: 500;
      border-radius: var(--radius);
      border: none;
      cursor: pointer;
      transition: all 150ms;
      white-space: nowrap;
    }
    .btn svg { width: 16px; height: 16px; }
    .btn-default { background: linear-gradient(135deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%); color: white; border: none; }
    .btn-default:hover { opacity: 0.9; }
    .btn-secondary { background: oklch(var(--secondary)); color: oklch(var(--secondary-foreground)); border: 1px solid oklch(var(--border)); }
    .btn-secondary:hover { background: oklch(var(--accent)); }
    .btn-outline { background: transparent; color: oklch(var(--foreground)); border: 1px solid oklch(var(--border)); }
    .btn-outline:hover { background: oklch(var(--accent)); }
    .btn-ghost { background: transparent; color: oklch(var(--foreground)); }
    .btn-ghost:hover { background: oklch(var(--accent)); }
    .btn-destructive { background: oklch(var(--destructive)); color: oklch(var(--destructive-foreground)); }
    .btn-destructive:hover { background: oklch(var(--destructive) / 0.9); }
    .btn-sm { height: 32px; padding: 0 12px; font-size: 13px; }
    .btn-icon { width: 36px; height: 36px; padding: 0; }
    .btn-icon.sm { width: 32px; height: 32px; }
    /* Touch feedback - active states for mobile */
    .btn:active { transform: scale(0.97); opacity: 0.9; }
    .btn-icon:active { transform: scale(0.92); }

    /* Card */
    .card { background: oklch(var(--card)); border: 1px solid oklch(var(--border)); border-radius: var(--radius); }
    .card-header { display: flex; flex-direction: column; padding: 24px 24px 0; }
    .card-header.row { flex-direction: row; align-items: center; justify-content: space-between; }
    .card-title { font-size: 18px; font-weight: 600; letter-spacing: -0.025em; }
    .card-description { font-size: 14px; color: oklch(var(--muted-foreground)); margin-top: 4px; }
    .card-content { padding: 24px; }

    /* Form */
    .input {
      display: flex; height: 40px; width: 100%; padding: 0 12px;
      background: oklch(var(--background));
      border: 1px solid oklch(var(--input));
      border-radius: var(--radius);
      font-size: 16px; color: oklch(var(--foreground));
      transition: all 150ms;
    }
    .input:focus { outline: none; border-color: oklch(var(--ring)); box-shadow: 0 0 0 2px oklch(var(--background)), 0 0 0 4px oklch(var(--ring) / 0.3); }
    .input::placeholder { color: oklch(var(--muted-foreground)); }
    .label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 8px; }
    .select {
      display: flex; height: 40px; width: 100%; padding: 0 12px;
      background: oklch(var(--background));
      border: 1px solid oklch(var(--input));
      border-radius: var(--radius);
      font-size: 16px; color: oklch(var(--foreground));
      cursor: pointer; appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%23a1a1aa' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 12px center;
      padding-right: 40px;
      transition: all 150ms;
    }
    .select:focus { outline: none; border-color: oklch(var(--ring)); box-shadow: 0 0 0 2px oklch(var(--background)), 0 0 0 4px oklch(var(--ring) / 0.3); }
    .select.sm { height: 32px; font-size: 13px; }

    /* Tags */
    .badge {
      display: inline-flex; align-items: center;
      padding: 2px 10px;
      font-size: 12px; font-weight: 500;
      border-radius: 9999px;
      border: 1px solid transparent;
    }
    .badge-secondary { background: oklch(var(--secondary)); color: oklch(var(--secondary-foreground)); border-color: oklch(var(--border)); }
    .badge-outline { background: transparent; color: oklch(var(--foreground)); border-color: oklch(var(--border)); }
    .badge-cat {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 10px;
      font-size: 12px; font-weight: 500;
      border-radius: var(--radius);
    }
    .badge-cat.work, .badge-cat.violet { background: oklch(var(--cat-work) / 0.15); color: oklch(var(--cat-work)); }
    .badge-cat.personal, .badge-cat.pink { background: oklch(var(--cat-personal) / 0.15); color: oklch(var(--cat-personal)); }
    .badge-cat.social, .badge-cat.cyan { background: oklch(var(--cat-social) / 0.15); color: oklch(var(--cat-social)); }
    .badge-cat.marketing, .badge-cat.orange { background: oklch(var(--cat-marketing) / 0.15); color: oklch(var(--cat-marketing)); }
    .badge-cat.docs, .badge-cat.green { background: oklch(var(--cat-docs) / 0.15); color: oklch(var(--cat-docs)); }
    .badge-cat.gray { background: oklch(var(--muted)); color: oklch(var(--muted-foreground)); }
    .tag-input {
      display: flex; flex-wrap: wrap; gap: 6px;
      min-height: 40px; padding: 6px 8px;
      background: oklch(var(--background));
      border: 1px solid oklch(var(--input));
      border-radius: var(--radius);
      transition: all 150ms;
    }
    .tag-input:focus-within { border-color: oklch(var(--ring)); box-shadow: 0 0 0 2px oklch(var(--background)), 0 0 0 4px oklch(var(--ring) / 0.3); }
    .tag-input input {
      flex: 1; min-width: 80px;
      background: transparent; border: none; outline: none;
      font-size: 14px; color: oklch(var(--foreground));
    }
    .tag-input input::placeholder { color: oklch(var(--muted-foreground)); }
    .tag {
      display: inline-flex; align-items: center; gap: 4px;
      padding: 2px 8px;
      background: oklch(var(--secondary));
      border-radius: var(--radius);
      font-size: 13px;
    }
    .tag-close {
      display: flex; width: 14px; height: 14px;
      align-items: center; justify-content: center;
      border-radius: 2px;
      color: oklch(var(--muted-foreground));
      cursor: pointer;
      transition: all 150ms;
    }
    .tag-close:hover { background: oklch(var(--destructive)); color: oklch(var(--destructive-foreground)); }

    /* Table */
    .table-wrapper { overflow-x: auto; }
    .table { width: 100%; border-collapse: collapse; font-size: 14px; }
    .table th {
      height: 48px; padding: 0 16px;
      text-align: left; font-weight: 500;
      color: oklch(var(--muted-foreground));
      background: oklch(var(--muted) / 0.5);
      border-bottom: 1px solid oklch(var(--border));
    }
    .table td { height: 56px; padding: 0 16px; border-bottom: 1px solid oklch(var(--border)); vertical-align: middle; }
    .table tr:last-child td { border-bottom: none; }
    .table tr:hover td { background: oklch(var(--muted) / 0.3); }
    .cell-link { display: flex; align-items: center; gap: 8px; }
    .cell-link a {
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 13px;
      color: oklch(var(--indigo));
      background: oklch(var(--indigo) / 0.1);
      padding: 4px 10px;
      border-radius: var(--radius);
      text-decoration: none;
      transition: all 150ms;
    }
    .cell-link a:hover { background: oklch(var(--indigo)); color: white; }
    .cell-url { max-width: 280px; color: oklch(var(--muted-foreground)); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-decoration: none; display: block; }
    .cell-url:hover { color: oklch(var(--foreground)); }
    .cell-tags { display: flex; flex-wrap: wrap; gap: 4px; }
    .cell-clicks { display: inline-flex; align-items: center; gap: 4px; color: hsl(142 76% 46%); }
    .cell-clicks svg { width: 14px; height: 14px; }
    .cell-date { color: oklch(var(--muted-foreground)); font-size: 13px; }
    .cell-actions { display: flex; gap: 4px; justify-content: flex-end; opacity: 0; transition: opacity 150ms; }
    .table tr:hover .cell-actions { opacity: 1; }

    /* Stats */
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { padding: 24px; }
    .stat-label { font-size: 14px; color: oklch(var(--muted-foreground)); margin-bottom: 8px; }
    .stat-value { font-size: 32px; font-weight: 700; letter-spacing: -0.025em; line-height: 1; }

    /* Form Grid */
    .form-grid { display: grid; grid-template-columns: 1fr 2fr 1fr 1fr auto; gap: 16px; align-items: end; }
    .form-group { display: flex; flex-direction: column; gap: 8px; }

    /* Pagination */
    .pagination { display: flex; align-items: center; justify-content: space-between; padding: 16px 24px; border-top: 1px solid oklch(var(--border)); }
    .pagination-info { font-size: 14px; color: oklch(var(--muted-foreground)); }
    .pagination-controls { display: flex; gap: 4px; }
    .pagination-btn {
      width: 32px; height: 32px;
      display: flex; align-items: center; justify-content: center;
      background: transparent;
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      color: oklch(var(--foreground));
      font-size: 13px;
      cursor: pointer;
      transition: all 150ms;
    }
    .pagination-btn:hover:not(:disabled) { background: oklch(var(--accent)); }
    .pagination-btn.active { background: oklch(var(--primary)); color: oklch(var(--primary-foreground)); border-color: oklch(var(--primary)); }
    .pagination-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    /* Modal */
    .modal-overlay {
      position: fixed; inset: 0;
      background: rgb(0 0 0 / 0.8);
      display: flex; align-items: center; justify-content: center;
      z-index: 100;
      opacity: 0; visibility: hidden;
      transition: opacity 150ms, visibility 150ms;
    }
    .modal-overlay.open { opacity: 1; visibility: visible; }
    .modal {
      width: 100%; max-width: 500px;
      background: oklch(var(--card));
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.25);
      transform: scale(0.95);
      transition: transform 150ms;
    }
    .modal-overlay.open .modal { transform: scale(1); }
    .modal-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 16px 24px;
      border-bottom: 1px solid oklch(var(--border));
    }
    .modal-title { font-size: 16px; font-weight: 600; }
    .modal-body { padding: 24px; }
    .modal-footer {
      display: flex; justify-content: flex-end; gap: 8px;
      padding: 16px 24px;
      border-top: 1px solid oklch(var(--border));
    }

    /* Toast */
    .toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 100; display: flex; flex-direction: column; gap: 8px; }
    .toast {
      display: flex; align-items: center; gap: 12px;
      padding: 16px;
      background: oklch(var(--card));
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
      min-width: 320px;
      animation: slideIn 200ms ease;
    }
    @keyframes slideIn { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
    .toast-icon { width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; }
    .toast-icon.success { color: hsl(142 76% 46%); }
    .toast-icon.error { color: hsl(0 84% 60%); }
    .toast-content { flex: 1; }
    .toast-title { font-weight: 500; }
    .toast-description { font-size: 13px; color: oklch(var(--muted-foreground)); }
    .toast-close { color: oklch(var(--muted-foreground)); cursor: pointer; background: none; border: none; }
    .toast-close:hover { color: oklch(var(--foreground)); }

    /* Dev Tools Floating Button */
    .dev-tools-fab { position: fixed; bottom: 24px; left: 24px; z-index: 90; }
    .dev-tools-btn {
      width: 48px; height: 48px;
      background: linear-gradient(135deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%);
      border: none; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; box-shadow: 0 4px 12px oklch(var(--indigo) / 0.4);
      transition: transform 150ms, box-shadow 150ms;
    }
    .dev-tools-btn:hover { transform: scale(1.05); box-shadow: 0 6px 20px oklch(var(--indigo) / 0.5); }
    .dev-tools-btn svg { width: 22px; height: 22px; color: white; }
    .dev-tools-menu {
      position: absolute; bottom: 56px; left: 0;
      background: oklch(var(--card)); border: 1px solid oklch(var(--border));
      border-radius: var(--radius); padding: 8px; min-width: 200px;
      box-shadow: 0 10px 25px rgb(0 0 0 / 0.3);
      opacity: 0; visibility: hidden; transform: translateY(8px);
      transition: opacity 150ms, visibility 150ms, transform 150ms;
    }
    .dev-tools-fab.open .dev-tools-menu { opacity: 1; visibility: visible; transform: translateY(0); }
    .dev-tools-menu-title { padding: 8px 12px; font-size: 11px; font-weight: 600; color: oklch(var(--muted-foreground)); text-transform: uppercase; letter-spacing: 0.05em; }
    .dev-tools-menu-item {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 12px; border-radius: calc(var(--radius) - 4px);
      color: oklch(var(--foreground)); text-decoration: none; font-size: 14px;
      transition: background 150ms;
    }
    .dev-tools-menu-item:hover { background: oklch(var(--accent)); }
    .dev-tools-menu-item svg { width: 16px; height: 16px; color: oklch(var(--muted-foreground)); }
    @media (max-width: 768px) { .dev-tools-fab { bottom: 80px; } }

    /* Mobile Menu Button */
    .mobile-menu-btn {
      display: none;
      padding: 0.5rem;
      background: none;
      border: none;
      color: oklch(var(--foreground));
      cursor: pointer;
      border-radius: 6px;
      min-width: 44px;
      min-height: 44px;
      align-items: center;
      justify-content: center;
    }
    .mobile-menu-btn:hover { background: oklch(var(--muted)); }

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
      display: block;
      opacity: 1;
    }

    /* Responsive */
    @media (max-width: 1024px) {
      .stats-grid { grid-template-columns: repeat(2, 1fr); }
      .form-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 768px) {
      .mobile-menu-btn { display: flex; }
      .mobile-overlay.active { display: block; }
      .sidebar {
        transform: translateX(-100%);
        transition: transform 0.3s ease;
        z-index: 50;
        width: 85%;
        max-width: 320px;
      }
      .sidebar.open { transform: translateX(0); }
      .main { margin-left: 0; }
      .header { padding: 0.75rem 1rem; gap: 0.5rem; }
      .search { flex: 1; }
      .search-trigger { padding: 0.5rem 0.75rem; }
      .search-kbd { display: none; }
      .header-actions { gap: 0.25rem; }
      .header-actions .btn { padding: 0.5rem; }
      .stats-grid { grid-template-columns: 1fr 1fr; gap: 0.5rem; }
      .stat-card { padding: 1rem; }
      .stat-value { font-size: 1.5rem; }
      .form-grid { grid-template-columns: 1fr; }
      .content { padding: 1rem; }
      .content-header { flex-direction: column; align-items: flex-start; gap: 0.75rem; }
      /* Links table mobile optimizations */
      .links-table { font-size: 0.8125rem; }
      .links-table th, .links-table td { padding: 0 8px; height: 48px; }
      .links-table th:nth-child(3), .links-table td:nth-child(3) { display: none; } /* Destination */
      .links-table th:nth-child(4), .links-table td:nth-child(4) { display: none; } /* Category */
      .links-table th:nth-child(5), .links-table td:nth-child(5) { display: none; } /* Tags */
      .links-table th:nth-child(7), .links-table td:nth-child(7) { display: none; } /* Created */
      .cell-checkbox { width: 32px; }
      .cell-link a { padding: 3px 6px; font-size: 12px; }
      .cell-link .copy-btn { display: none; }
      .cell-actions { opacity: 1; gap: 2px; }
      .cell-actions .icon-btn { width: 32px; height: 32px; min-width: 32px; }
      .pagination { padding: 12px 16px; flex-wrap: wrap; gap: 8px; }
      .pagination-info { font-size: 12px; }
      /* Prevent iOS zoom on input focus - minimum 16px */
      input, select, textarea, .select.sm, .tag-input input { font-size: 16px; }
    }
    @media (max-width: 480px) {
      /* Extra small screens - show only essential columns */
      .links-table th:nth-child(6), .links-table td:nth-child(6) { display: none; } /* Clicks */
      .cell-actions .icon-btn:not(:first-child):not(:last-child) { display: none; } /* Hide middle actions, keep QR and delete */
      .content { padding: 0.75rem; }
      .content-header h1 { font-size: 1.25rem; }
    }

    /* Analytics Styles */
    .analytics-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }
    .analytics-grid.cols-3 { grid-template-columns: repeat(3, 1fr); }
    @media (max-width: 1024px) { .analytics-grid { grid-template-columns: 1fr; } }

    .chart-container { padding: 16px; height: 200px; position: relative; }
    .chart-bars { display: flex; align-items: flex-end; gap: 4px; height: 160px; padding-top: 20px; }
    .chart-bar {
      flex: 1;
      background: linear-gradient(180deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%);
      border-radius: 4px 4px 0 0;
      min-width: 8px;
      position: relative;
      transition: all 150ms;
    }
    .chart-bar:hover { opacity: 0.8; }
    .chart-bar-label {
      position: absolute;
      bottom: -20px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 10px;
      color: oklch(var(--muted-foreground));
      white-space: nowrap;
    }
    .chart-bar-value {
      position: absolute;
      top: -18px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 11px;
      font-weight: 500;
      color: oklch(var(--foreground));
    }

    .pie-chart { display: flex; gap: 16px; align-items: center; }
    .pie-visual {
      width: 120px; height: 120px;
      border-radius: 50%;
      position: relative;
      flex-shrink: 0;
    }
    .pie-legend { flex: 1; }
    .pie-legend-item {
      display: flex; align-items: center; gap: 8px;
      padding: 4px 0;
      font-size: 13px;
    }
    .pie-legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .pie-legend-value { margin-left: auto; color: oklch(var(--muted-foreground)); }

    .list-stat { padding: 16px; }
    .list-stat-item {
      display: flex; align-items: center; justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid oklch(var(--border));
    }
    .list-stat-item:last-child { border-bottom: none; }
    .list-stat-label { font-size: 13px; color: oklch(var(--foreground)); }
    .list-stat-value { font-size: 13px; font-weight: 500; color: oklch(var(--indigo)); }
    .list-stat-bar {
      height: 4px;
      background: oklch(var(--indigo));
      border-radius: 2px;
      margin-top: 4px;
    }

    .analytics-modal .modal { max-width: 900px; }
    .analytics-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 16px;
    }
    .analytics-period {
      display: flex; gap: 4px;
    }
    .period-btn {
      padding: 6px 12px;
      font-size: 13px;
      background: transparent;
      border: 1px solid oklch(var(--border));
      border-radius: var(--radius);
      color: oklch(var(--muted-foreground));
      cursor: pointer;
      transition: all 150ms;
    }
    .period-btn:hover { background: oklch(var(--accent)); }
    .period-btn.active { background: oklch(var(--primary)); color: oklch(var(--primary-foreground)); border-color: oklch(var(--primary)); }

    .recent-clicks-table { max-height: 300px; overflow-y: auto; }
    .recent-clicks-table table { width: 100%; font-size: 12px; }
    .recent-clicks-table th, .recent-clicks-table td { padding: 8px; text-align: left; }
    .recent-clicks-table th { background: oklch(var(--muted) / 0.5); position: sticky; top: 0; }

    /* Analytics page view */
    .page-analytics { display: none; }
    .page-analytics.active { display: block; }
    .page-links { display: block; }
    .page-links.hidden { display: none; }

    /* Bulk actions */
    .bulk-actions {
      display: none;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: oklch(var(--indigo) / 0.1);
      border: 1px solid oklch(var(--indigo) / 0.3);
      border-radius: var(--radius);
      margin-bottom: 16px;
    }
    .bulk-actions.visible { display: flex; }
    .bulk-actions-count {
      font-size: 14px;
      font-weight: 500;
      color: oklch(var(--indigo));
    }
    .bulk-actions-buttons { display: flex; gap: 8px; margin-left: auto; }
    .cell-checkbox { width: 48px; text-align: center; }
    .cell-checkbox input {
      width: 20px; height: 20px; cursor: pointer;
      /* Expand touch target to 44px minimum */
      padding: 12px;
      margin: -12px;
      -webkit-tap-highlight-color: transparent;
    }

    /* =================================================================
       MOBILE-FIRST UI - iOS-Style Components
       ================================================================= */

    /* Bottom Tab Bar */
    .tab-bar {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      height: 83px;
      background: hsl(var(--background) / 0.95);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-top: 1px solid hsl(var(--border));
      display: none;
      align-items: flex-start;
      padding: 8px 0 0;
      padding-bottom: env(safe-area-inset-bottom, 25px);
      z-index: 100;
    }

    .tab-item {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
      padding: 8px 4px;
      color: hsl(var(--muted-foreground));
      font-size: 10px;
      font-weight: 500;
      background: none;
      border: none;
      cursor: pointer;
      min-height: 48px;
      transition: color 150ms ease;
    }

    .tab-item.active { color: hsl(var(--indigo)); }
    .tab-item:active { transform: scale(0.95); opacity: 0.8; }
    .tab-item svg { width: 24px; height: 24px; }

    /* Floating Action Button */
    .fab-container {
      position: relative;
      flex: 1;
      display: flex;
      justify-content: center;
    }

    .fab {
      position: absolute;
      bottom: 16px;
      width: 56px;
      height: 56px;
      background: linear-gradient(135deg, hsl(var(--indigo)) 0%, hsl(271 91% 65%) 100%);
      border-radius: 16px;
      border: none;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 20px hsl(var(--indigo) / 0.4);
      cursor: pointer;
      transition: transform 150ms ease, box-shadow 150ms ease;
    }

    .fab:active { transform: scale(0.95); }
    .fab svg { width: 24px; height: 24px; color: white; stroke-width: 2.5; }

    /* Mobile Link Cards */
    .mobile-links { display: none; padding: 0 16px 100px; }

    .link-card {
      background: hsl(var(--card));
      border: 1px solid hsl(var(--border));
      border-radius: 16px;
      padding: 16px;
      margin-bottom: 12px;
      transition: transform 150ms ease;
    }

    .link-card:active { transform: scale(0.98); }

    .link-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
    }

    .link-card-code {
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 16px;
      font-weight: 600;
      color: hsl(var(--indigo));
      background: hsl(var(--indigo) / 0.1);
      padding: 6px 12px;
      border-radius: 8px;
      text-decoration: none;
    }

    .link-card-actions { display: flex; gap: 8px; }

    .link-card-action {
      width: 36px;
      height: 36px;
      background: hsl(var(--muted));
      border: none;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      color: hsl(var(--foreground));
    }

    .link-card-action svg { width: 18px; height: 18px; }

    .link-card-url {
      font-size: 14px;
      color: hsl(var(--muted-foreground));
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-bottom: 12px;
    }

    .link-card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .link-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: hsl(var(--muted-foreground));
    }

    .link-card-clicks {
      display: flex;
      align-items: center;
      gap: 4px;
      color: hsl(142 76% 46%);
      font-weight: 500;
    }

    .link-card-category {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 500;
      background: hsl(var(--muted));
    }

    /* Mobile Header */
    .mobile-header {
      display: none;
      padding: 12px 16px;
      padding-top: calc(12px + env(safe-area-inset-top, 0));
      background: hsl(var(--background));
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .mobile-header-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .mobile-header-title {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }

    .mobile-header-actions { display: flex; gap: 8px; }

    .header-icon-btn {
      width: 36px;
      height: 36px;
      background: hsl(var(--muted));
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      border: none;
      color: hsl(var(--foreground));
      cursor: pointer;
    }

    .header-icon-btn svg { width: 18px; height: 18px; }

    /* Mobile Search Bar */
    .search-bar-mobile {
      height: 40px;
      background: hsl(var(--muted));
      border-radius: 12px;
      display: flex;
      align-items: center;
      padding: 0 14px;
      gap: 10px;
    }

    .search-bar-mobile svg {
      width: 18px;
      height: 18px;
      color: hsl(var(--muted-foreground));
      flex-shrink: 0;
    }

    .search-bar-mobile input {
      flex: 1;
      background: none;
      border: none;
      outline: none;
      font-size: 16px;
      color: hsl(var(--foreground));
    }

    .search-bar-mobile input::placeholder {
      color: hsl(var(--muted-foreground));
    }

    /* Mobile Stats */
    .mobile-stats {
      display: none;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      padding: 0 16px;
      margin-bottom: 16px;
    }

    .mobile-stat-card {
      background: hsl(var(--card));
      border: 1px solid hsl(var(--border));
      border-radius: 16px;
      padding: 16px;
    }

    .mobile-stat-value {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.025em;
    }

    .mobile-stat-label {
      font-size: 12px;
      color: hsl(var(--muted-foreground));
      margin-top: 4px;
    }

    /* iOS-Style Bottom Sheet */
    .sheet-overlay {
      position: fixed;
      inset: 0;
      background: rgb(0 0 0 / 0.5);
      z-index: 200;
      opacity: 0;
      visibility: hidden;
      transition: opacity 200ms ease, visibility 200ms ease;
    }

    .sheet-overlay.open {
      opacity: 1;
      visibility: visible;
    }

    .sheet {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: hsl(var(--card));
      border-radius: 20px 20px 0 0;
      max-height: 90vh;
      transform: translateY(100%);
      transition: transform 300ms cubic-bezier(0.32, 0.72, 0, 1);
      z-index: 201;
      display: flex;
      flex-direction: column;
      padding-bottom: env(safe-area-inset-bottom, 0);
    }

    .sheet-overlay.open .sheet {
      transform: translateY(0);
    }

    .sheet-handle {
      display: flex;
      justify-content: center;
      padding: 12px 0 8px;
    }

    .sheet-handle::before {
      content: '';
      width: 36px;
      height: 5px;
      background: hsl(var(--muted));
      border-radius: 3px;
    }

    .sheet-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 20px 16px;
      border-bottom: 1px solid hsl(var(--border));
    }

    .sheet-title {
      font-size: 18px;
      font-weight: 600;
    }

    .sheet-close {
      width: 32px;
      height: 32px;
      background: hsl(var(--muted));
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      border: none;
      cursor: pointer;
      color: hsl(var(--foreground));
    }

    .sheet-body {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      -webkit-overflow-scrolling: touch;
    }

    .sheet-footer {
      padding: 16px 20px;
      border-top: 1px solid hsl(var(--border));
      display: flex;
      gap: 12px;
    }

    .sheet-footer .btn { flex: 1; min-height: 50px; font-size: 16px; }

    .form-group-mobile { margin-bottom: 20px; }
    .form-group-mobile .label { margin-bottom: 10px; font-size: 14px; font-weight: 500; }
    .form-group-mobile .input,
    .form-group-mobile .select {
      height: 50px;
      font-size: 16px;
      padding: 0 16px;
      border-radius: 12px;
    }

    /* Mobile-only display rules */
    @media (max-width: 768px) {
      .tab-bar { display: flex; }
      .mobile-header { display: block; }
      .mobile-links { display: block; }
      .mobile-stats { display: grid; }

      /* Hide desktop elements */
      .sidebar { display: none !important; }
      .header { display: none !important; }
      .content { display: none !important; }
      .main { margin-left: 0 !important; }

      body {
        padding-bottom: 83px;
        padding-top: env(safe-area-inset-top, 0);
      }
    }

    /* Animations */
    @keyframes cardIn {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }

    .link-card {
      animation: cardIn 200ms ease backwards;
    }

    .link-card:nth-child(1) { animation-delay: 0ms; }
    .link-card:nth-child(2) { animation-delay: 50ms; }
    .link-card:nth-child(3) { animation-delay: 100ms; }
    .link-card:nth-child(4) { animation-delay: 150ms; }
    .link-card:nth-child(5) { animation-delay: 200ms; }
  </style>
</head>
<body>
  <!-- Mobile Header -->
  <header class="mobile-header" role="banner" aria-label="Mobile header">
    <div class="mobile-header-top">
      <h1 class="mobile-header-title">Links</h1>
      <div class="mobile-header-actions">
        <button class="header-icon-btn" onclick="openMobileSearch()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
          </svg>
        </button>
        <button class="header-icon-btn" onclick="toggleMobileMenu()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>
          </svg>
        </button>
      </div>
    </div>
    <div class="search-bar-mobile" id="mobileSearchBar">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
      </svg>
      <input type="text" placeholder="Search links..." id="mobileSearchInput" oninput="filterMobileLinks(this.value)">
    </div>
  </header>

  <!-- Mobile Stats -->
  <div class="mobile-stats" id="mobileStats">
    <div class="mobile-stat-card">
      <div class="mobile-stat-value" id="mobileStatLinks">0</div>
      <div class="mobile-stat-label">Total Links</div>
    </div>
    <div class="mobile-stat-card">
      <div class="mobile-stat-value" id="mobileStatClicks">0</div>
      <div class="mobile-stat-label">Total Clicks</div>
    </div>
  </div>

  <!-- Mobile Links -->
  <div class="mobile-links" id="mobileLinksContainer">
    <!-- Cards rendered by JS -->
  </div>

  <!-- Bottom Tab Bar -->
  <nav class="tab-bar" id="tabBar" aria-label="Main navigation" role="tablist">
    <button class="tab-item active" data-tab="links" onclick="switchMobileTab('links')" role="tab" aria-selected="true" aria-label="Links">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
      </svg>
      <span>Links</span>
    </button>
    <button class="tab-item" data-tab="stats" onclick="switchMobileTab('stats')" role="tab" aria-selected="false" aria-label="Statistics">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/>
      </svg>
      <span>Stats</span>
    </button>
    <div class="fab-container">
      <button class="fab" onclick="openCreateSheet()" aria-label="Create new link">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 5v14M5 12h14"/>
        </svg>
      </button>
    </div>
    <button class="tab-item" data-tab="categories" onclick="switchMobileTab('categories')" role="tab" aria-selected="false" aria-label="Categories">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/>
        <rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>
      </svg>
      <span>Categories</span>
    </button>
    <button class="tab-item" data-tab="settings" onclick="switchMobileTab('settings')" role="tab" aria-selected="false" aria-label="Settings">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
      <span>Settings</span>
    </button>
  </nav>

  <!-- Create Link Sheet (iOS-style bottom sheet) -->
  <div class="sheet-overlay" id="createSheet" onclick="if(event.target === this) closeCreateSheet()">
    <div class="sheet">
      <div class="sheet-handle"></div>
      <div class="sheet-header">
        <h3 class="sheet-title">New Link</h3>
        <button class="sheet-close" onclick="closeCreateSheet()" aria-label="Close sheet">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true">
            <path d="M18 6 6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div class="sheet-body">
        <div class="form-group-mobile">
          <label class="label">Short Code</label>
          <input type="text" class="input" id="sheetNewCode" placeholder="my-link (optional)">
        </div>
        <div class="form-group-mobile">
          <label class="label">Destination URL</label>
          <input type="url" class="input" id="sheetNewDestination" placeholder="https://example.com" required>
        </div>
        <div class="form-group-mobile">
          <label class="label">Category</label>
          <select class="select" id="sheetNewCategory">
            <option value="">No category</option>
          </select>
        </div>
        <div class="form-group-mobile">
          <label class="label">Description (optional)</label>
          <input type="text" class="input" id="sheetNewDescription" placeholder="Brief note">
        </div>
      </div>
      <div class="sheet-footer">
        <button class="btn btn-outline" onclick="closeCreateSheet()">Cancel</button>
        <button class="btn btn-default" onclick="createLinkFromSheet()">Create Link</button>
      </div>
    </div>
  </div>

  <!-- Mobile Overlay -->
  <div class="mobile-overlay" id="mobileOverlay" onclick="closeMobileMenu()" role="presentation" aria-hidden="true"></div>

  <div class="app-layout">
    <!-- Sidebar -->
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <div class="logo">
          <div class="logo-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
          </div>
          <span class="logo-text">URLsToGo</span>
        </div>
      </div>

      <div class="sidebar-content">
        <div class="nav-group">
          <div class="nav-item active" onclick="filterByCategory(null)" data-nav="links">
            <span class="nav-item-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
              </svg>
            </span>
            <span>All Links</span>
            <span class="nav-item-badge" id="totalLinksNav">0</span>
          </div>
          <div class="nav-item" onclick="showAnalyticsOverview()" data-nav="analytics">
            <span class="nav-item-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 3v18h18"/>
                <path d="m19 9-5 5-4-4-3 3"/>
              </svg>
            </span>
            <span>Analytics</span>
          </div>
        </div>

        <div class="nav-group">
          <div class="nav-group-label">Categories</div>
          <div id="categoriesNav"></div>
          <div class="nav-item" style="color: oklch(var(--muted-foreground));" onclick="promptAddCategory()">
            <span class="nav-item-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 14px; height: 14px;">
                <path d="M5 12h14"/>
                <path d="M12 5v14"/>
              </svg>
            </span>
            <span>Add Category</span>
          </div>
        </div>

        <div class="nav-group">
          <div class="nav-group-label">Popular Tags</div>
          <div id="tagsNav" style="padding: 0 12px; display: flex; flex-wrap: wrap; gap: 6px;"></div>
        </div>

        <div class="nav-group">
          <div class="nav-group-label">Settings</div>
          <div class="nav-item" onclick="showApiKeysModal()">
            <div class="nav-item-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
            </div>
            <span>API Keys</span>
          </div>
        </div>
      </div>

      <div class="sidebar-footer">
        <button class="user-button" id="logoutBtn">
          <div class="avatar">${userEmail.charAt(0).toUpperCase()}</div>
          <div class="user-info">
            <div class="user-name">${userEmail.split('@')[0]}</div>
            <div class="user-email">${userEmail}</div>
          </div>
          <svg class="user-button-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
            <polyline points="16 17 21 12 16 7"/>
            <line x1="21" x2="9" y1="12" y2="12"/>
          </svg>
        </button>
      </div>
    </aside>

    <!-- Main -->
    <main class="main">
      <header class="header">
        <button class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleMobileMenu()" aria-label="Open menu">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <line x1="3" y1="6" x2="21" y2="6"/>
            <line x1="3" y1="12" x2="21" y2="12"/>
            <line x1="3" y1="18" x2="21" y2="18"/>
          </svg>
        </button>
        <div class="search">
          <button class="search-trigger" id="searchTrigger">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.3-4.3"/>
            </svg>
            <span>Search links...</span>
            <kbd class="search-kbd"><span style="font-size: 14px;">&#8984;</span>K</kbd>
          </button>
          <div class="search-dialog" id="searchDialog">
            <div class="search-input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.3-4.3"/>
              </svg>
              <input type="text" class="search-input" placeholder="Type to search..." id="searchInput">
              <div class="search-spinner" id="searchSpinner"></div>
            </div>
            <div class="search-results" id="searchResults">
              <div class="search-empty">Type to search your links</div>
            </div>
          </div>
        </div>
        <div class="header-actions">
          <button class="btn btn-ghost btn-icon sm" onclick="toggleTheme()" title="Toggle theme" id="themeToggle">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-icon-dark">
              <circle cx="12" cy="12" r="4"/>
              <path d="M12 2v2"/>
              <path d="M12 20v2"/>
              <path d="m4.93 4.93 1.41 1.41"/>
              <path d="m17.66 17.66 1.41 1.41"/>
              <path d="M2 12h2"/>
              <path d="M20 12h2"/>
              <path d="m6.34 17.66-1.41 1.41"/>
              <path d="m19.07 4.93-1.41 1.41"/>
            </svg>
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-icon-light" style="display: none;">
              <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>
            </svg>
          </button>
          <button class="btn btn-outline btn-sm" onclick="exportLinks()">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" x2="12" y1="3" y2="15"/>
            </svg>
            Export
          </button>
          <button class="btn btn-outline btn-sm" id="importBtn" type="button">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" x2="12" y1="15" y2="3"/>
            </svg>
            Import
          </button>
          <input type="file" id="importFile" accept=".json" class="hidden-input">
        </div>
      </header>

      <div class="page">
        <!-- Stats -->
        <div class="stats-grid">
          <div class="card stat-card">
            <div class="stat-label">Total Links</div>
            <div class="stat-value" id="statLinks">0</div>
          </div>
          <div class="card stat-card">
            <div class="stat-label">Total Clicks</div>
            <div class="stat-value" id="statClicks">0</div>
          </div>
          <div class="card stat-card">
            <div class="stat-label">Categories</div>
            <div class="stat-value" id="statCategories">0</div>
          </div>
          <div class="card stat-card">
            <div class="stat-label">Unique Tags</div>
            <div class="stat-value" id="statTags">0</div>
          </div>
        </div>

        <!-- Create Form -->
        <div class="card" style="margin-bottom: 24px;">
          <div class="card-header">
            <h2 class="card-title">Create New Link</h2>
            <p class="card-description">Add a new shortened link with optional category and tags.</p>
          </div>
          <div class="card-content">
            <div class="form-grid">
              <div class="form-group">
                <label class="label">Short Code</label>
                <input type="text" class="input" id="newCode" placeholder="my-link">
              </div>
              <div class="form-group">
                <label class="label">Destination URL</label>
                <div style="display: flex; gap: 8px;">
                  <input type="url" class="input" id="newDestination" placeholder="https://example.com/your-long-url" style="flex: 1;">
                  <button type="button" class="btn btn-outline btn-sm" onclick="toggleUTMBuilder()" title="UTM Parameters">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                    UTM
                  </button>
                </div>
              </div>
              <div class="form-group" style="grid-column: span 2;">
                <label class="label">Description (optional)</label>
                <input type="text" class="input" id="newDescription" placeholder="Brief note about this link">
              </div>
              <!-- UTM Builder Panel -->
              <div id="utmBuilder" style="grid-column: 1 / -1; display: none; padding: 16px; background: oklch(var(--muted) / 0.3); border-radius: var(--radius); margin-top: -8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                  <span style="font-size: 13px; font-weight: 500;">UTM Parameters</span>
                  <button type="button" class="btn btn-ghost btn-sm" onclick="toggleUTMBuilder()">Close</button>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                  <div>
                    <label class="label" style="font-size: 12px;">Source *</label>
                    <input type="text" class="input" id="utmSource" placeholder="google, newsletter" style="height: 36px;">
                  </div>
                  <div>
                    <label class="label" style="font-size: 12px;">Medium *</label>
                    <input type="text" class="input" id="utmMedium" placeholder="cpc, email, social" style="height: 36px;">
                  </div>
                  <div>
                    <label class="label" style="font-size: 12px;">Campaign *</label>
                    <input type="text" class="input" id="utmCampaign" placeholder="spring_sale" style="height: 36px;">
                  </div>
                  <div>
                    <label class="label" style="font-size: 12px;">Term (optional)</label>
                    <input type="text" class="input" id="utmTerm" placeholder="running+shoes" style="height: 36px;">
                  </div>
                  <div>
                    <label class="label" style="font-size: 12px;">Content (optional)</label>
                    <input type="text" class="input" id="utmContent" placeholder="logolink" style="height: 36px;">
                  </div>
                  <div style="display: flex; align-items: flex-end;">
                    <button type="button" class="btn btn-default btn-sm" onclick="applyUTM()" style="width: 100%;">Apply UTM</button>
                  </div>
                </div>
              </div>
              <div class="form-group">
                <label class="label">Category</label>
                <select class="select" id="newCategory">
                  <option value="">No category</option>
                </select>
              </div>
              <div class="form-group">
                <label class="label">Tags</label>
                <div class="tag-input" id="tagInput">
                  <input type="text" placeholder="Add tag..." id="newTagInput">
                </div>
              </div>
              <div class="form-group">
                <label class="label">Expires</label>
                <select class="select" id="newExpires">
                  <option value="">Never</option>
                  <option value="1h">1 hour</option>
                  <option value="24h">24 hours</option>
                  <option value="7d">7 days</option>
                  <option value="30d">30 days</option>
                  <option value="90d">90 days</option>
                  <option value="custom">Custom date</option>
                </select>
              </div>
              <div class="form-group" id="customExpiryGroup" style="display: none;">
                <label class="label">Expiry Date</label>
                <input type="datetime-local" class="input" id="newExpiresCustom">
              </div>
              <div class="form-group">
                <label class="label">Password</label>
                <input type="password" class="input" id="newPassword" placeholder="Optional">
              </div>
              <div class="form-group">
                <label class="label">&nbsp;</label>
                <button class="btn btn-default" style="height: 40px;" onclick="createLink()">Create Link</button>
              </div>
            </div>
          </div>
        </div>

        <!-- Bulk Actions Bar -->
        <div class="bulk-actions" id="bulkActions">
          <span class="bulk-actions-count"><span id="bulkCount">0</span> selected</span>
          <button class="btn btn-outline btn-sm" onclick="clearSelection()">Clear</button>
          <div class="bulk-actions-buttons">
            <select class="select sm" id="bulkMoveCategory" style="width: 150px;">
              <option value="">Move to category...</option>
            </select>
            <button class="btn btn-secondary btn-sm" onclick="bulkMove()">Move</button>
            <button class="btn btn-destructive btn-sm" onclick="bulkDelete()">Delete Selected</button>
          </div>
        </div>

        <!-- Links Table -->
        <div class="card">
          <div class="card-header row">
            <div>
              <h2 class="card-title">Your Links</h2>
              <p class="card-description">Manage all your shortened URLs.</p>
            </div>
            <div style="display: flex; gap: 8px;">
              <select class="select sm" style="width: 150px;" id="filterCategory" onchange="loadLinks()">
                <option value="">All Categories</option>
              </select>
              <select class="select sm" style="width: 150px;" id="sortLinks" onchange="loadLinks()">
                <option value="newest">Sort: Newest</option>
                <option value="oldest">Sort: Oldest</option>
                <option value="clicks">Sort: Most Clicks</option>
                <option value="alpha">Sort: A-Z</option>
              </select>
            </div>
          </div>
          <div class="table-wrapper">
            <table class="table links-table">
              <thead>
                <tr>
                  <th class="cell-checkbox"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                  <th>Short Link</th>
                  <th>Destination</th>
                  <th>Category</th>
                  <th>Tags</th>
                  <th>Clicks</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="linksTable"></tbody>
            </table>
          </div>
          <div class="pagination" id="pagination" style="display: none;">
            <div class="pagination-info" id="paginationInfo"></div>
            <div class="pagination-controls" id="paginationControls"></div>
          </div>
        </div>
      </div>
    </main>
  </div>

  <!-- Dev Tools FAB -->
  <div class="dev-tools-fab" id="devToolsFab">
    <button class="dev-tools-btn" onclick="toggleDevTools()" title="Design Tools">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
    </button>
    <div class="dev-tools-menu">
      <div class="dev-tools-menu-title">Design Resources</div>
      <a href="/design-system" target="_blank" class="dev-tools-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>
        Design System
      </a>
      <a href="/mobile-mockup" target="_blank" class="dev-tools-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/></svg>
        Mobile App Mockup
      </a>
    </div>
  </div>

  <div class="toast-container" id="toastContainer"></div>

  <!-- Edit Modal -->
  <div class="modal-overlay" id="editModal">
    <div class="modal">
      <div class="modal-header">
        <h3 class="modal-title">Edit Link</h3>
        <button class="btn btn-ghost btn-icon sm" onclick="closeEditModal()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="editCode">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="label">Short Code</label>
          <input type="text" class="input" id="editCodeDisplay" disabled style="opacity: 0.6;">
        </div>
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="label">Destination URL</label>
          <input type="url" class="input" id="editDestination" placeholder="https://example.com">
        </div>
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="label">Description</label>
          <input type="text" class="input" id="editDescription" placeholder="Brief note about this link">
        </div>
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="label">Category</label>
          <select class="select" id="editCategory">
            <option value="">No category</option>
          </select>
        </div>
        <div class="form-group">
          <label class="label">Tags</label>
          <div class="tag-input" id="editTagInput">
            <input type="text" placeholder="Add tag..." id="editTagInputField">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="label">Expires</label>
          <div style="display: flex; gap: 8px;">
            <select class="select" id="editExpires" style="flex: 1;">
              <option value="">Never</option>
              <option value="1h">1 hour from now</option>
              <option value="24h">24 hours from now</option>
              <option value="7d">7 days from now</option>
              <option value="30d">30 days from now</option>
              <option value="custom">Custom date</option>
            </select>
          </div>
        </div>
        <div class="form-group" id="editCustomExpiryGroup" style="display: none; margin-top: 8px;">
          <input type="datetime-local" class="input" id="editExpiresCustom">
        </div>
        <div id="currentExpiryInfo" style="margin-top: 8px; font-size: 12px; color: oklch(var(--muted-foreground));"></div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="label">Password Protection</label>
          <div id="editPasswordInfo" style="font-size: 12px; color: oklch(var(--muted-foreground)); margin-bottom: 8px;"></div>
          <input type="password" class="input" id="editPassword" placeholder="New password (leave blank to keep current)">
          <label style="display: flex; align-items: center; gap: 12px; margin-top: 8px; font-size: 16px; color: oklch(var(--muted-foreground)); cursor: pointer; min-height: 44px;">
            <input type="checkbox" id="editRemovePassword" style="width: 20px; height: 20px; min-width: 20px;">
            Remove password protection
          </label>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="closeEditModal()">Cancel</button>
        <button class="btn btn-default" onclick="saveEdit()">Save Changes</button>
      </div>
    </div>
  </div>

  <!-- QR Code Modal -->
  <div class="modal-overlay" id="qrModal">
    <div class="modal" style="max-width: 400px;">
      <div class="modal-header">
        <h3 class="modal-title">QR Code</h3>
        <button class="btn btn-ghost btn-icon sm" onclick="closeQRModal()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      </div>
      <div class="modal-body" style="text-align: center;">
        <div id="qrCodeContainer" style="background: white; padding: 24px; border-radius: 8px; display: inline-block; margin-bottom: 16px;"></div>
        <div style="margin-bottom: 8px;">
          <code style="font-size: 14px; color: oklch(var(--indigo));" id="qrLinkUrl"></code>
        </div>
        <p style="font-size: 13px; color: oklch(var(--muted-foreground));">Scan to visit this link</p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="closeQRModal()">Close</button>
        <button class="btn btn-default" onclick="downloadQR()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" x2="12" y1="15" y2="3"/>
          </svg>
          Download PNG
        </button>
      </div>
    </div>
  </div>

  <!-- Analytics Modal -->
  <div class="modal-overlay analytics-modal" id="analyticsModal">
    <div class="modal">
      <div class="modal-header">
        <h3 class="modal-title">Link Analytics: <span id="analyticsLinkCode"></span></h3>
        <button class="btn btn-ghost btn-icon sm" onclick="closeAnalyticsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      </div>
      <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
        <div class="analytics-header">
          <div>
            <div style="font-size: 13px; color: oklch(var(--muted-foreground));">Total Clicks</div>
            <div style="font-size: 24px; font-weight: 700;" id="analyticsTotalClicks">0</div>
          </div>
          <div class="analytics-period">
            <button class="period-btn" onclick="loadLinkAnalytics(currentAnalyticsCode, 7)">7d</button>
            <button class="period-btn active" onclick="loadLinkAnalytics(currentAnalyticsCode, 30)">30d</button>
            <button class="period-btn" onclick="loadLinkAnalytics(currentAnalyticsCode, 90)">90d</button>
          </div>
        </div>

        <div class="card" style="margin-bottom: 16px;">
          <div class="card-header" style="padding: 12px 16px;">
            <h4 style="font-size: 14px; font-weight: 500;">Clicks Over Time</h4>
          </div>
          <div class="chart-container">
            <div class="chart-bars" id="analyticsClicksChart"></div>
          </div>
        </div>

        <div class="analytics-grid">
          <div class="card">
            <div class="card-header" style="padding: 12px 16px;">
              <h4 style="font-size: 14px; font-weight: 500;">By Country</h4>
            </div>
            <div class="list-stat" id="analyticsCountries"></div>
          </div>
          <div class="card">
            <div class="card-header" style="padding: 12px 16px;">
              <h4 style="font-size: 14px; font-weight: 500;">By Device</h4>
            </div>
            <div class="list-stat" id="analyticsDevices"></div>
          </div>
        </div>

        <div class="analytics-grid">
          <div class="card">
            <div class="card-header" style="padding: 12px 16px;">
              <h4 style="font-size: 14px; font-weight: 500;">By Browser</h4>
            </div>
            <div class="list-stat" id="analyticsBrowsers"></div>
          </div>
          <div class="card">
            <div class="card-header" style="padding: 12px 16px;">
              <h4 style="font-size: 14px; font-weight: 500;">Top Referrers</h4>
            </div>
            <div class="list-stat" id="analyticsReferrers"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-header" style="padding: 12px 16px;">
            <h4 style="font-size: 14px; font-weight: 500;">Recent Clicks</h4>
          </div>
          <div class="recent-clicks-table">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Country</th>
                  <th>Device</th>
                  <th>Browser</th>
                  <th>Referrer</th>
                </tr>
              </thead>
              <tbody id="analyticsRecentClicks"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- API Keys Modal -->
  <div class="modal-overlay" id="apiKeysModal">
    <div class="modal" style="max-width: 600px;">
      <div class="modal-header">
        <h3 class="modal-title">API Keys</h3>
        <button class="btn btn-ghost btn-icon sm" onclick="closeApiKeysModal()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      </div>
      <div class="modal-body">
        <p style="font-size: 14px; color: oklch(var(--muted-foreground)); margin-bottom: 16px;">
          API keys allow external services to access your links programmatically.
        </p>

        <!-- Create new key form -->
        <div class="card" style="margin-bottom: 16px; padding: 16px;">
          <div style="display: flex; gap: 8px; align-items: flex-end;">
            <div style="flex: 1;">
              <label class="label">New API Key</label>
              <input type="text" class="input" id="newApiKeyName" placeholder="Key name (e.g., jb-cloud-app-tracker)">
            </div>
            <button class="btn btn-default" onclick="createApiKey()">Create</button>
          </div>
        </div>

        <!-- New key display (shown once after creation) -->
        <div id="newKeyDisplay" style="display: none; margin-bottom: 16px;">
          <div class="card" style="padding: 16px; background: oklch(var(--indigo) / 0.1); border-color: oklch(var(--indigo));">
            <div style="font-size: 12px; font-weight: 500; color: oklch(var(--indigo)); margin-bottom: 8px;">
              Save this key now - it won't be shown again!
            </div>
            <code id="newKeyValue" style="display: block; padding: 12px; background: oklch(var(--background)); border-radius: var(--radius); font-size: 13px; word-break: break-all;"></code>
            <button class="btn btn-outline btn-sm" style="margin-top: 8px;" onclick="copyNewKey()">Copy to Clipboard</button>
          </div>
        </div>

        <!-- Existing keys list -->
        <div id="apiKeysList">
          <div style="text-align: center; padding: 24px; color: oklch(var(--muted-foreground));">Loading...</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Confirmation Modal -->
  <div class="modal-overlay" id="confirmModal" style="display: none;">
    <div class="modal" style="max-width: 400px;">
      <div class="modal-header">
        <h3 class="modal-title" id="confirmModalTitle">Confirm</h3>
        <button class="btn btn-ghost btn-icon sm" onclick="closeConfirmModal()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      </div>
      <div class="modal-body">
        <p id="confirmModalMessage" style="font-size: 14px; color: oklch(var(--foreground)); margin-bottom: 20px;"></p>
        <div style="display: flex; gap: 8px; justify-content: flex-end;">
          <button class="btn btn-outline" onclick="closeConfirmModal()">Cancel</button>
          <button class="btn btn-destructive" id="confirmModalAction" onclick="executeConfirmAction()">Delete</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    // XSS Prevention - Escape functions for safe HTML rendering
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }
    function escapeAttr(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/\\\\/g,'\\\\\\\\');
    }

    // Confirmation modal functions
    let confirmModalCallback = null;

    function showConfirmModal(title, message, actionText, callback) {
      document.getElementById('confirmModalTitle').textContent = title;
      document.getElementById('confirmModalMessage').textContent = message;
      document.getElementById('confirmModalAction').textContent = actionText;
      confirmModalCallback = callback;
      document.getElementById('confirmModal').style.display = 'flex';
    }

    function closeConfirmModal() {
      document.getElementById('confirmModal').style.display = 'none';
      confirmModalCallback = null;
    }

    function executeConfirmAction() {
      if (confirmModalCallback) {
        confirmModalCallback();
      }
      closeConfirmModal();
    }

    const baseUrl = window.location.origin;
    const shortlinkBase = 'https://go.urlstogo.cloud';
    const CLERK_PUBLISHABLE_KEY = '${clerkPublishableKey}';
    let allLinks = [];
    let allCategories = [];
    let allTags = [];
    let newTags = [];
    let currentPage = 1;
    const perPage = 10;
    let currentCategory = null;

    // Global Clerk instance for session management
    let clerkInstance = null;

    // Initialize Clerk for session management
    async function initClerk() {
      if (CLERK_PUBLISHABLE_KEY && window.Clerk) {
        try {
          clerkInstance = window.Clerk;
          await clerkInstance.load();
        } catch (e) {
          console.error('Clerk load error:', e.message);
        }
      }
    }

    // Initialize Clerk on page load (wait for script to be ready with polling)
    function waitForClerk() {
      let attempts = 0;
      const maxAttempts = 100; // 5 seconds total (50ms * 100)

      const checkClerk = setInterval(() => {
        attempts++;
        if (window.Clerk) {
          clearInterval(checkClerk);
          initClerk();
        } else if (attempts >= maxAttempts) {
          clearInterval(checkClerk);
          console.error('Clerk SDK failed to load within timeout');
        }
      }, 50);
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', waitForClerk);
    } else {
      waitForClerk();
    }

    // Initialize
    async function init() {
      await Promise.all([loadStats(), loadCategories(), loadTags(), loadLinks()]);
      // Try to init default categories if none exist
      if (allCategories.length === 0) {
        await fetch('/api/init-categories', { method: 'POST' });
        await loadCategories();
      }
    }

    // Mobile menu functions
    // Dev Tools FAB
    function toggleDevTools() {
      document.getElementById('devToolsFab').classList.toggle('open');
    }
    document.addEventListener('click', (e) => {
      const fab = document.getElementById('devToolsFab');
      if (fab && !fab.contains(e.target)) fab.classList.remove('open');
    });

    function toggleMobileMenu() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('mobileOverlay');
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
      const overlay = document.getElementById('mobileOverlay');
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
      document.body.style.overflow = '';
    }

    async function loadStats() {
      const res = await fetch('/api/stats');
      const stats = await res.json();
      document.getElementById('statLinks').textContent = stats.links.toLocaleString();
      document.getElementById('statClicks').textContent = stats.clicks.toLocaleString();
      document.getElementById('statCategories').textContent = stats.categories;
      document.getElementById('statTags').textContent = stats.tags;
      document.getElementById('totalLinksNav').textContent = stats.links;
    }

    async function loadCategories() {
      const res = await fetch('/api/categories');
      allCategories = await res.json();

      // Update sidebar (escape user-controlled data)
      const nav = document.getElementById('categoriesNav');
      nav.innerHTML = allCategories.map(cat => \`
        <div class="nav-item" onclick="filterByCategory('\${escapeAttr(cat.slug)}')">
          <span class="cat-dot \${escapeAttr(cat.color)}"></span>
          <span>\${escapeHtml(cat.name)}</span>
          <span class="nav-item-badge">\${parseInt(cat.link_count) || 0}</span>
        </div>
      \`).join('');

      // Update form selects (escape user-controlled data)
      const options = '<option value="">No category</option>' + allCategories.map(cat => \`<option value="\${escapeAttr(cat.id)}">\${escapeHtml(cat.name)}</option>\`).join('');
      document.getElementById('newCategory').innerHTML = options;
      document.getElementById('filterCategory').innerHTML = '<option value="">All Categories</option>' + allCategories.map(cat => \`<option value="\${escapeAttr(cat.slug)}">\${escapeHtml(cat.name)}</option>\`).join('');
    }

    async function loadTags() {
      const res = await fetch('/api/tags');
      allTags = await res.json();

      const nav = document.getElementById('tagsNav');
      nav.innerHTML = allTags.slice(0, 8).map(tag => \`
        <span class="badge badge-secondary" style="cursor: pointer;" onclick="filterByTag('\${escapeAttr(tag.name)}')">\${escapeHtml(tag.name)}</span>
      \`).join('');
    }

    async function loadLinks() {
      const category = document.getElementById('filterCategory').value;
      const sort = document.getElementById('sortLinks').value;

      let url = '/api/links?sort=' + sort;
      if (category) url += '&category=' + category;

      const res = await fetch(url);
      allLinks = await res.json();
      renderLinks();
    }

    function renderLinks() {
      const tbody = document.getElementById('linksTable');
      const start = (currentPage - 1) * perPage;
      const pageLinks = allLinks.slice(start, start + perPage);

      if (pageLinks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 48px; color: oklch(var(--muted-foreground));">No links found. Create your first one above!</td></tr>';
        document.getElementById('pagination').style.display = 'none';
        return;
      }

      tbody.innerHTML = pageLinks.map(link => {
        const date = new Date(link.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        const safeCode = escapeAttr(link.code);
        const safeCodeHtml = escapeHtml(link.code);
        const safeDest = escapeAttr(link.destination);
        const safeDestHtml = escapeHtml(link.destination);
        const catBadge = link.category_name ? \`<span class="badge-cat \${escapeAttr(link.category_color)}"><span class="cat-dot \${escapeAttr(link.category_color)}"></span>\${escapeHtml(link.category_name)}</span>\` : '<span style="color: oklch(var(--muted-foreground))">-</span>';
        const tags = link.tags.length ? link.tags.map(t => \`<span class="badge badge-outline">\${escapeHtml(t)}</span>\`).join('') : '<span style="color: oklch(var(--muted-foreground))">-</span>';

        return \`
          <tr data-code="\${safeCode}">
            <td class="cell-checkbox"><input type="checkbox" class="link-checkbox" value="\${safeCode}" onchange="updateBulkSelection()"></td>
            <td>
              <div class="cell-link">
                \${link.is_protected ? '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: oklch(var(--indigo)); flex-shrink: 0;" title="Password protected"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>' : ''}
                <a href="\${baseUrl}/\${safeCode}" target="_blank">/\${safeCodeHtml}</a>
                <button class="btn btn-ghost btn-icon sm" onclick="copyLink('\${safeCode}')" title="Copy">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
                    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                  </svg>
                </button>
              </div>
            </td>
            <td><a href="\${safeDest}" target="_blank" class="cell-url" title="\${safeDest}">\${safeDestHtml}</a></td>
            <td>\${catBadge}</td>
            <td><div class="cell-tags">\${tags}</div></td>
            <td>
              <span class="cell-clicks">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/>
                  <polyline points="16 7 22 7 22 13"/>
                </svg>
                \${parseInt(link.clicks).toLocaleString()}
              </span>
            </td>
            <td class="cell-date">
              \${escapeHtml(date)}
              \${link.expires_at ? getExpiryBadge(link.expires_at) : ''}
            </td>
            <td>
              <div class="cell-actions">
                <button class="btn btn-ghost btn-icon sm" onclick="showQRCode('\${safeCode}')" title="QR Code">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect width="5" height="5" x="3" y="3" rx="1"/>
                    <rect width="5" height="5" x="16" y="3" rx="1"/>
                    <rect width="5" height="5" x="3" y="16" rx="1"/>
                    <path d="M21 16h-3a2 2 0 0 0-2 2v3"/>
                    <path d="M21 21v.01"/>
                    <path d="M12 7v3a2 2 0 0 1-2 2H7"/>
                    <path d="M3 12h.01"/>
                    <path d="M12 3h.01"/>
                    <path d="M12 16v.01"/>
                    <path d="M16 12h1"/>
                    <path d="M21 12v.01"/>
                    <path d="M12 21v-1"/>
                  </svg>
                </button>
                <button class="btn btn-ghost btn-icon sm" onclick="showLinkAnalytics('\${safeCode}')" title="Analytics">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M3 3v18h18"/>
                    <path d="m19 9-5 5-4-4-3 3"/>
                  </svg>
                </button>
                <button class="btn btn-ghost btn-icon sm" onclick='openEditModal(\${JSON.stringify(link).replace(/'/g, "&#39;")})' title="Edit">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>
                    <path d="m15 5 4 4"/>
                  </svg>
                </button>
                <button class="btn btn-ghost btn-icon sm" onclick="deleteLink('\${safeCode}')" title="Delete">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M3 6h18"/>
                    <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                    <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
                  </svg>
                </button>
              </div>
            </td>
          </tr>
        \`;
      }).join('');

      // Pagination
      const totalPages = Math.ceil(allLinks.length / perPage);
      if (totalPages > 1) {
        document.getElementById('pagination').style.display = 'flex';
        document.getElementById('paginationInfo').textContent = \`Showing \${start + 1}-\${Math.min(start + perPage, allLinks.length)} of \${allLinks.length} links\`;

        let controls = \`<button class="pagination-btn" \${currentPage === 1 ? 'disabled' : ''} onclick="goToPage(\${currentPage - 1})"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></button>\`;
        for (let i = 1; i <= totalPages; i++) {
          if (i === 1 || i === totalPages || (i >= currentPage - 1 && i <= currentPage + 1)) {
            controls += \`<button class="pagination-btn \${i === currentPage ? 'active' : ''}" onclick="goToPage(\${i})">\${i}</button>\`;
          } else if (i === currentPage - 2 || i === currentPage + 2) {
            controls += '<button class="pagination-btn" disabled>...</button>';
          }
        }
        controls += \`<button class="pagination-btn" \${currentPage === totalPages ? 'disabled' : ''} onclick="goToPage(\${currentPage + 1})"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg></button>\`;
        document.getElementById('paginationControls').innerHTML = controls;
      } else {
        document.getElementById('pagination').style.display = 'none';
      }
    }

    function goToPage(page) {
      currentPage = page;
      renderLinks();
    }

    function filterByCategory(slug) {
      document.getElementById('filterCategory').value = slug || '';
      currentPage = 1;
      loadLinks();

      // Update active state
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      if (!slug) {
        document.querySelector('.nav-item').classList.add('active');
      }
    }

    function filterByTag(tag) {
      // For now, just show toast - could add tag filtering
      showToast('Tag filtering coming soon!', 'Showing links tagged with: ' + tag);
    }

    async function createLink() {
      const code = document.getElementById('newCode').value.trim();
      const destination = document.getElementById('newDestination').value.trim();
      const description = document.getElementById('newDescription').value.trim() || null;
      const category_id = document.getElementById('newCategory').value || null;
      const expires_at = getExpirationDate('newExpires', 'newExpiresCustom');
      const password = document.getElementById('newPassword').value || null;

      if (!code || !destination) {
        showToast('Missing fields', 'Please enter both code and destination', 'error');
        return;
      }

      const res = await fetch('/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, destination, description, category_id, tags: newTags, expires_at, password })
      });

      if (res.ok) {
        document.getElementById('newCode').value = '';
        document.getElementById('newDestination').value = '';
        document.getElementById('newDescription').value = '';
        document.getElementById('newCategory').value = '';
        document.getElementById('newExpires').value = '';
        document.getElementById('newExpiresCustom').value = '';
        document.getElementById('newPassword').value = '';
        document.getElementById('customExpiryGroup').style.display = 'none';
        newTags = [];
        renderNewTags();
        showToast('Link created', password ? 'Password-protected link created' : 'Your new short link is ready to use');
        await Promise.all([loadLinks(), loadStats(), loadCategories(), loadTags()]);
      } else {
        const data = await res.json();
        showToast('Error', data.error || 'Failed to create link', 'error');
      }
    }

    // Get expiration date from select and custom input
    function getExpirationDate(selectId, customId) {
      const select = document.getElementById(selectId);
      const custom = document.getElementById(customId);
      const value = select.value;

      if (!value) return null;
      if (value === 'custom') return custom.value ? new Date(custom.value).toISOString() : null;

      const now = new Date();
      switch (value) {
        case '1h': return new Date(now.getTime() + 60 * 60 * 1000).toISOString();
        case '24h': return new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
        case '7d': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
        case '30d': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
        case '90d': return new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString();
        default: return null;
      }
    }

    // Toggle custom expiry input visibility
    document.getElementById('newExpires').addEventListener('change', (e) => {
      document.getElementById('customExpiryGroup').style.display = e.target.value === 'custom' ? 'block' : 'none';
    });
    document.getElementById('editExpires').addEventListener('change', (e) => {
      document.getElementById('editCustomExpiryGroup').style.display = e.target.value === 'custom' ? 'block' : 'none';
    });

    // UTM Builder functions
    function toggleUTMBuilder() {
      const builder = document.getElementById('utmBuilder');
      builder.style.display = builder.style.display === 'none' ? 'block' : 'none';
    }

    function applyUTM() {
      const source = document.getElementById('utmSource').value.trim();
      const medium = document.getElementById('utmMedium').value.trim();
      const campaign = document.getElementById('utmCampaign').value.trim();
      const term = document.getElementById('utmTerm').value.trim();
      const content = document.getElementById('utmContent').value.trim();

      if (!source || !medium || !campaign) {
        showToast('Missing UTM parameters', 'Source, Medium, and Campaign are required', 'error');
        return;
      }

      const destInput = document.getElementById('newDestination');
      let url = destInput.value.trim();

      if (!url) {
        showToast('Missing URL', 'Please enter a destination URL first', 'error');
        return;
      }

      try {
        const urlObj = new URL(url);

        // Add UTM parameters
        urlObj.searchParams.set('utm_source', source);
        urlObj.searchParams.set('utm_medium', medium);
        urlObj.searchParams.set('utm_campaign', campaign);
        if (term) urlObj.searchParams.set('utm_term', term);
        if (content) urlObj.searchParams.set('utm_content', content);

        destInput.value = urlObj.href;

        // Clear UTM fields and close builder
        document.getElementById('utmSource').value = '';
        document.getElementById('utmMedium').value = '';
        document.getElementById('utmCampaign').value = '';
        document.getElementById('utmTerm').value = '';
        document.getElementById('utmContent').value = '';
        toggleUTMBuilder();

        showToast('UTM Applied', 'UTM parameters added to destination URL');
      } catch (e) {
        showToast('Invalid URL', 'Please enter a valid URL first', 'error');
      }
    }

    // Get expiry badge HTML
    function getExpiryBadge(expiresAt) {
      const expiry = new Date(expiresAt);
      const now = new Date();
      const diffMs = expiry - now;
      const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

      if (diffMs < 0) {
        return '<span style="display: inline-block; margin-left: 6px; padding: 2px 6px; font-size: 10px; background: hsl(0 84% 60% / 0.15); color: hsl(0 84% 60%); border-radius: 4px;">Expired</span>';
      } else if (diffDays <= 1) {
        return '<span style="display: inline-block; margin-left: 6px; padding: 2px 6px; font-size: 10px; background: hsl(38 92% 50% / 0.15); color: hsl(38 92% 50%); border-radius: 4px;">Expires soon</span>';
      } else if (diffDays <= 7) {
        return \`<span style="display: inline-block; margin-left: 6px; padding: 2px 6px; font-size: 10px; background: oklch(var(--muted)); color: oklch(var(--muted-foreground)); border-radius: 4px;">\${diffDays}d left</span>\`;
      }
      return '';
    }

    async function deleteLink(code) {
      if (!confirm('Delete this link? This cannot be undone.')) return;

      await fetch('/api/links/' + code, { method: 'DELETE' });
      showToast('Link deleted', 'The link has been removed');
      await Promise.all([loadLinks(), loadStats(), loadCategories()]);
    }

    function copyLink(code) {
      navigator.clipboard.writeText(shortlinkBase + '/' + code);
      showToast('Copied!', 'Link copied to clipboard');
    }

    function exportLinks() {
      window.location.href = '/api/export';
      showToast('Exporting', 'Your links are being downloaded');
    }

    async function logout() {
      // Try Clerk signOut first using the global instance
      if (clerkInstance && typeof clerkInstance.signOut === 'function') {
        try {
          await clerkInstance.signOut();
          window.location.href = '/login';
          return;
        } catch (e) {
          console.error('Clerk signOut error:', e.message);
        }
      }
      // Fallback to Cloudflare Access logout
      window.location.href = '/cdn-cgi/access/logout';
    }

    async function importLinks(event) {
      const file = event.target.files[0];
      if (!file) return;

      try {
        const text = await file.text();
        const data = JSON.parse(text);

        const res = await fetch('/api/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });

        const result = await res.json();
        if (res.ok) {
          showToast('Import complete', \`Imported \${result.imported} links (\${result.skipped} skipped)\`);
          await Promise.all([loadLinks(), loadStats(), loadCategories(), loadTags()]);
        } else {
          showToast('Import failed', result.error || 'Unknown error', 'error');
        }
      } catch (e) {
        showToast('Invalid file', 'Could not parse JSON file', 'error');
      }

      event.target.value = '';
    }

    function promptAddCategory() {
      const name = prompt('Enter category name:');
      if (!name) return;

      const colors = ['violet', 'pink', 'cyan', 'orange', 'green', 'gray'];
      const color = colors[Math.floor(Math.random() * colors.length)];

      fetch('/api/categories', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, color })
      }).then(() => {
        showToast('Category created', 'New category: ' + name);
        loadCategories();
      });
    }

    // Tag input handling
    const tagInputEl = document.getElementById('newTagInput');
    tagInputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault();
        const tag = tagInputEl.value.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (tag && !newTags.includes(tag)) {
          newTags.push(tag);
          renderNewTags();
        }
        tagInputEl.value = '';
      } else if (e.key === 'Backspace' && !tagInputEl.value && newTags.length) {
        newTags.pop();
        renderNewTags();
      }
    });

    function renderNewTags() {
      const container = document.getElementById('tagInput');
      const input = document.getElementById('newTagInput');
      container.innerHTML = '';
      newTags.forEach((tag, i) => {
        const el = document.createElement('span');
        el.className = 'tag';
        el.innerHTML = escapeHtml(tag) + '<span class="tag-close" onclick="removeNewTag(' + i + ')"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></span>';
        container.appendChild(el);
      });
      container.appendChild(input);
    }

    function removeNewTag(index) {
      newTags.splice(index, 1);
      renderNewTags();
    }

    // Search
    const searchTrigger = document.getElementById('searchTrigger');
    const searchDialog = document.getElementById('searchDialog');
    const searchInput = document.getElementById('searchInput');
    const searchSpinner = document.getElementById('searchSpinner');
    const searchResults = document.getElementById('searchResults');
    let searchTimeout = null;

    searchTrigger.addEventListener('click', () => {
      searchDialog.classList.add('open');
      searchInput.focus();
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.search')) searchDialog.classList.remove('open');
    });

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchDialog.classList.add('open');
        searchInput.focus();
      }
      if (e.key === 'Escape') searchDialog.classList.remove('open');
    });

    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.trim();
      if (searchTimeout) clearTimeout(searchTimeout);

      if (q.length < 2) {
        searchResults.innerHTML = '<div class="search-empty">Type to search your links</div>';
        searchSpinner.classList.remove('loading');
        return;
      }

      searchSpinner.classList.add('loading');

      searchTimeout = setTimeout(async () => {
        try {
          const res = await fetch('/api/search?q=' + encodeURIComponent(q));
          const results = await res.json();

          if (results.length === 0) {
            searchResults.innerHTML = '<div class="search-empty">No results found</div>';
          } else {
            searchResults.innerHTML = '<div class="search-group"><div class="search-group-label">Results</div>' +
              results.map(link => \`
                <div class="search-item" onclick="window.open('\${baseUrl}/\${escapeAttr(link.code)}', '_blank')">
                  <span class="search-item-code">/\${escapeHtml(link.code)}</span>
                  <span class="search-item-url">\${escapeHtml(link.destination)}</span>
                </div>
              \`).join('') + '</div>';
          }
        } finally {
          searchSpinner.classList.remove('loading');
        }
      }, 300);
    });

    // Toast
    function showToast(title, description, type = 'success') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = \`
        <div class="toast-icon \${type}">
          \${type === 'success' ? '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' : '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>'}
        </div>
        <div class="toast-content">
          <div class="toast-title">\${title}</div>
          <div class="toast-description">\${description}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
      \`;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 5000);
    }

    // Keyboard shortcuts for form
    document.getElementById('newCode').addEventListener('keypress', e => {
      if (e.key === 'Enter') document.getElementById('newDestination').focus();
    });
    document.getElementById('newDestination').addEventListener('keypress', e => {
      if (e.key === 'Enter') createLink();
    });

    // Edit Modal
    let editTags = [];

    function openEditModal(link) {
      document.getElementById('editCode').value = link.code;
      document.getElementById('editCodeDisplay').value = '/' + link.code;
      document.getElementById('editDestination').value = link.destination;
      document.getElementById('editDescription').value = link.description || '';
      document.getElementById('editCategory').value = link.category_id || '';

      // Populate category dropdown
      const catSelect = document.getElementById('editCategory');
      catSelect.innerHTML = '<option value="">No category</option>' + allCategories.map(cat =>
        \`<option value="\${cat.id}" \${cat.id === link.category_id ? 'selected' : ''}>\${cat.name}</option>\`
      ).join('');

      // Set tags
      editTags = link.tags ? [...link.tags] : [];
      renderEditTags();

      // Set expiration info
      const expiryInfo = document.getElementById('currentExpiryInfo');
      const expiresSelect = document.getElementById('editExpires');
      const customGroup = document.getElementById('editCustomExpiryGroup');
      const customInput = document.getElementById('editExpiresCustom');

      expiresSelect.value = '';
      customGroup.style.display = 'none';
      customInput.value = '';

      if (link.expires_at) {
        const expiryDate = new Date(link.expires_at);
        const isExpired = expiryDate < new Date();
        expiryInfo.innerHTML = \`Current: \${expiryDate.toLocaleString()}\${isExpired ? ' <span style="color: hsl(0 84% 60%);">(Expired)</span>' : ''}\`;
        // Set to custom and populate the date
        expiresSelect.value = 'custom';
        customGroup.style.display = 'block';
        customInput.value = expiryDate.toISOString().slice(0, 16);
      } else {
        expiryInfo.textContent = 'Current: Never expires';
      }

      // Set password info
      const passwordInfo = document.getElementById('editPasswordInfo');
      document.getElementById('editPassword').value = '';
      document.getElementById('editRemovePassword').checked = false;
      if (link.is_protected) {
        passwordInfo.innerHTML = '<span style="color: oklch(var(--indigo));">This link is password protected</span>';
      } else {
        passwordInfo.textContent = 'No password set';
      }

      document.getElementById('editModal').classList.add('open');
    }

    function closeEditModal() {
      document.getElementById('editModal').classList.remove('open');
      editTags = [];
    }

    async function saveEdit() {
      const code = document.getElementById('editCode').value;
      const destination = document.getElementById('editDestination').value.trim();
      const description = document.getElementById('editDescription').value.trim() || null;
      const category_id = document.getElementById('editCategory').value || null;
      const expires_at = getExpirationDate('editExpires', 'editExpiresCustom');
      const password = document.getElementById('editPassword').value || null;
      const remove_password = document.getElementById('editRemovePassword').checked;

      if (!destination) {
        showToast('Missing destination', 'Please enter a destination URL', 'error');
        return;
      }

      const res = await fetch('/api/links/' + code, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destination, description, category_id, tags: editTags, expires_at, password, remove_password })
      });

      if (res.ok) {
        closeEditModal();
        showToast('Link updated', 'Your changes have been saved');
        await Promise.all([loadLinks(), loadStats(), loadCategories(), loadTags()]);
      } else {
        const data = await res.json();
        showToast('Error', data.error || 'Failed to update link', 'error');
      }
    }

    function renderEditTags() {
      const container = document.getElementById('editTagInput');
      const input = document.getElementById('editTagInputField');
      container.innerHTML = '';
      editTags.forEach((tag, i) => {
        const el = document.createElement('span');
        el.className = 'tag';
        el.innerHTML = escapeHtml(tag) + '<span class="tag-close" onclick="removeEditTag(' + i + ')"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></span>';
        container.appendChild(el);
      });
      container.appendChild(input);
    }

    function removeEditTag(index) {
      editTags.splice(index, 1);
      renderEditTags();
    }

    // Edit tag input handling
    document.getElementById('editTagInputField').addEventListener('keydown', (e) => {
      const input = e.target;
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault();
        const tag = input.value.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (tag && !editTags.includes(tag)) {
          editTags.push(tag);
          renderEditTags();
        }
        input.value = '';
      } else if (e.key === 'Backspace' && !input.value && editTags.length) {
        editTags.pop();
        renderEditTags();
      }
    });

    // Close modal on escape or backdrop click
    document.getElementById('editModal').addEventListener('click', (e) => {
      if (e.target.id === 'editModal') closeEditModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && document.getElementById('editModal').classList.contains('open')) {
        closeEditModal();
      }
    });

    // Setup event listeners
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('importBtn').addEventListener('click', function() {
      document.getElementById('importFile').click();
    });
    document.getElementById('importFile').addEventListener('change', importLinks);

    // Analytics
    let currentAnalyticsCode = null;

    async function showLinkAnalytics(code) {
      currentAnalyticsCode = code;
      document.getElementById('analyticsLinkCode').textContent = '/' + code;
      document.getElementById('analyticsModal').classList.add('open');
      await loadLinkAnalytics(code, 30);
    }

    async function loadLinkAnalytics(code, days) {
      // Update period buttons
      document.querySelectorAll('.period-btn').forEach(btn => {
        btn.classList.toggle('active', btn.textContent === days + 'd');
      });

      const res = await fetch('/api/analytics/' + code + '?days=' + days);
      const data = await res.json();

      // Total clicks
      document.getElementById('analyticsTotalClicks').textContent = data.link.totalClicks.toLocaleString();

      // Clicks chart
      renderClicksChart(data.clicksByDay, days);

      // Countries
      renderListStats('analyticsCountries', data.clicksByCountry, 'country');

      // Devices
      renderListStats('analyticsDevices', data.clicksByDevice, 'device_type');

      // Browsers
      renderListStats('analyticsBrowsers', data.clicksByBrowser, 'browser');

      // Referrers
      renderListStats('analyticsReferrers', data.topReferrers, 'referrer');

      // Recent clicks
      renderRecentClicks(data.recentClicks);
    }

    function renderClicksChart(clicksByDay, days) {
      const container = document.getElementById('analyticsClicksChart');

      if (!clicksByDay || clicksByDay.length === 0) {
        container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: oklch(var(--muted-foreground));">No click data yet</div>';
        return;
      }

      // Fill in missing dates
      const dateMap = {};
      clicksByDay.forEach(d => { dateMap[d.date] = d.clicks; });

      const dates = [];
      for (let i = days - 1; i >= 0; i--) {
        const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
        const dateStr = date.toISOString().split('T')[0];
        dates.push({ date: dateStr, clicks: dateMap[dateStr] || 0 });
      }

      const maxClicks = Math.max(...dates.map(d => d.clicks), 1);

      // Only show labels for some bars to avoid crowding
      const labelInterval = days <= 7 ? 1 : days <= 30 ? 5 : 10;

      container.innerHTML = dates.map((d, i) => {
        const height = (d.clicks / maxClicks) * 140;
        const showLabel = i % labelInterval === 0 || i === dates.length - 1;
        const dateLabel = new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

        return \`
          <div class="chart-bar" style="height: \${Math.max(height, 4)}px;" title="\${dateLabel}: \${d.clicks} clicks">
            \${d.clicks > 0 ? \`<span class="chart-bar-value">\${d.clicks}</span>\` : ''}
            \${showLabel ? \`<span class="chart-bar-label">\${dateLabel}</span>\` : ''}
          </div>
        \`;
      }).join('');
    }

    function renderListStats(containerId, items, labelKey) {
      const container = document.getElementById(containerId);

      if (!items || items.length === 0) {
        container.innerHTML = '<div style="padding: 16px; text-align: center; color: oklch(var(--muted-foreground)); font-size: 13px;">No data</div>';
        return;
      }

      const maxClicks = Math.max(...items.map(i => i.clicks));

      container.innerHTML = items.slice(0, 5).map(item => {
        const label = item[labelKey] || 'Unknown';
        const barWidth = Math.min(100, Math.max(0, (item.clicks / maxClicks) * 100));

        return \`
          <div class="list-stat-item">
            <div style="flex: 1;">
              <div class="list-stat-label">\${escapeHtml(label)}</div>
              <div class="list-stat-bar" style="width: \${barWidth}%;"></div>
            </div>
            <span class="list-stat-value">\${parseInt(item.clicks).toLocaleString()}</span>
          </div>
        \`;
      }).join('');
    }

    function renderRecentClicks(clicks) {
      const container = document.getElementById('analyticsRecentClicks');

      if (!clicks || clicks.length === 0) {
        container.innerHTML = '<tr><td colspan="5" style="text-align: center; color: oklch(var(--muted-foreground));">No recent clicks</td></tr>';
        return;
      }

      container.innerHTML = clicks.map(click => {
        const time = new Date(click.clicked_at).toLocaleString('en-US', {
          month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
        });
        let referrer = 'Direct';
        if (click.referrer) {
          try {
            referrer = new URL(click.referrer).hostname;
          } catch {
            referrer = click.referrer.substring(0, 30) + (click.referrer.length > 30 ? '...' : '');
          }
        }

        return \`
          <tr>
            <td>\${escapeHtml(time)}</td>
            <td>\${escapeHtml(click.country || '-')}</td>
            <td>\${escapeHtml(click.device_type || '-')}</td>
            <td>\${escapeHtml(click.browser || '-')}</td>
            <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis;">\${escapeHtml(referrer)}</td>
          </tr>
        \`;
      }).join('');
    }

    function closeAnalyticsModal() {
      document.getElementById('analyticsModal').classList.remove('open');
      currentAnalyticsCode = null;
    }

    // Analytics overview page
    async function showAnalyticsOverview() {
      // Update nav active state
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      document.querySelector('[data-nav="analytics"]').classList.add('active');

      // For now, show a toast - we could expand this to a full page
      showToast('Analytics Overview', 'Click on individual link analytics buttons to see detailed stats');
    }

    // Close analytics modal on escape or backdrop click
    document.getElementById('analyticsModal').addEventListener('click', (e) => {
      if (e.target.id === 'analyticsModal') closeAnalyticsModal();
    });

    // QR Code functionality
    let currentQRCode = null;

    function showQRCode(code) {
      const url = shortlinkBase + '/' + code;
      document.getElementById('qrLinkUrl').textContent = url;
      document.getElementById('qrModal').classList.add('open');

      // Generate QR code
      const container = document.getElementById('qrCodeContainer');
      container.innerHTML = '';

      try {
        const qr = generateQR(url);
        const svg = qrToSVG(qr, 200);
        container.innerHTML = svg;
        currentQRCode = { code, url, svg };
      } catch (e) {
        container.innerHTML = '<p style="color: #666;">Failed to generate QR code</p>';
      }
    }

    function closeQRModal() {
      document.getElementById('qrModal').classList.remove('open');
      currentQRCode = null;
    }

    // =============================================================================
    // API KEYS MODAL
    // =============================================================================

    async function showApiKeysModal() {
      document.getElementById('apiKeysModal').classList.add('open');
      document.getElementById('newKeyDisplay').style.display = 'none';
      document.getElementById('newApiKeyName').value = '';
      await loadApiKeys();
    }

    function closeApiKeysModal() {
      document.getElementById('apiKeysModal').classList.remove('open');
    }

    async function loadApiKeys() {
      const container = document.getElementById('apiKeysList');
      try {
        const res = await fetch('/api/keys');
        const data = await res.json();

        if (!data.keys || data.keys.length === 0) {
          container.innerHTML = '<div style="text-align: center; padding: 24px; color: oklch(var(--muted-foreground));">No API keys yet. Create one above.</div>';
          return;
        }

        container.innerHTML = data.keys.map(key => \`
          <div class="card" style="padding: 12px 16px; margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 500;">\${escapeHtml(key.name)}</div>
              <div style="font-size: 12px; color: oklch(var(--muted-foreground)); margin-top: 2px;">
                <code>\${escapeHtml(key.key_prefix)}...</code>
                \${key.last_used_at ? ' · Last used ' + formatRelativeTime(key.last_used_at) : ' · Never used'}
              </div>
            </div>
            <button class="btn btn-ghost btn-icon sm" onclick="deleteApiKey(\${key.id}, '\${escapeJs(key.name)}')" title="Delete key">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
              </svg>
            </button>
          </div>
        \`).join('');
      } catch (e) {
        container.innerHTML = '<div style="text-align: center; padding: 24px; color: oklch(var(--destructive));">Failed to load API keys</div>';
      }
    }

    async function createApiKey() {
      const nameInput = document.getElementById('newApiKeyName');
      const name = nameInput.value.trim();

      if (!name) {
        showToast('Please enter a name for the API key', 'error');
        return;
      }

      try {
        const res = await fetch('/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name })
        });

        const data = await res.json();

        if (data.error) {
          showToast(data.error, 'error');
          return;
        }

        // Show the new key (only shown once!)
        document.getElementById('newKeyValue').textContent = data.key;
        document.getElementById('newKeyDisplay').style.display = 'block';
        nameInput.value = '';

        // Refresh the list
        await loadApiKeys();
        showToast('API key created! Save it now - it won\\'t be shown again.', 'success');
      } catch (e) {
        showToast('Failed to create API key', 'error');
      }
    }

    function copyNewKey() {
      const key = document.getElementById('newKeyValue').textContent;
      navigator.clipboard.writeText(key).then(() => {
        showToast('API key copied to clipboard', 'success');
      }).catch(() => {
        showToast('Failed to copy to clipboard', 'error');
      });
    }

    function deleteApiKey(id, name) {
      showConfirmModal(
        'Delete API Key',
        \`Delete API key "\${name}"? This cannot be undone.\`,
        'Delete',
        async () => {
          try {
            await fetch('/api/keys/' + id, { method: 'DELETE' });
            await loadApiKeys();
            showToast('API key deleted', 'success');
          } catch (e) {
            showToast('Failed to delete API key', 'error');
          }
        }
      );
    }

    function formatRelativeTime(dateStr) {
      const date = new Date(dateStr);
      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);

      if (diffMins < 1) return 'just now';
      if (diffMins < 60) return diffMins + 'm ago';
      if (diffHours < 24) return diffHours + 'h ago';
      if (diffDays < 30) return diffDays + 'd ago';
      return date.toLocaleDateString();
    }

    // Close API keys modal on overlay click or Escape
    document.getElementById('apiKeysModal').addEventListener('click', (e) => {
      if (e.target.id === 'apiKeysModal') closeApiKeysModal();
    });

    // Close confirmation modal on overlay click
    document.getElementById('confirmModal').addEventListener('click', (e) => {
      if (e.target.id === 'confirmModal') closeConfirmModal();
    });

    async function downloadQR() {
      if (!currentQRCode) return;

      const svg = document.querySelector('#qrCodeContainer svg');
      if (!svg) return;

      // Convert SVG to PNG using canvas
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = 400;
      canvas.height = 400;

      // Create image from SVG
      const svgData = new XMLSerializer().serializeToString(svg);
      const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
      const svgUrl = URL.createObjectURL(svgBlob);

      const img = new Image();
      img.onload = () => {
        ctx.fillStyle = 'white';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 50, 50, 300, 300);
        URL.revokeObjectURL(svgUrl);

        // Download
        canvas.toBlob((blob) => {
          const link = document.createElement('a');
          link.download = 'qr-' + currentQRCode.code + '.png';
          link.href = URL.createObjectURL(blob);
          link.click();
          URL.revokeObjectURL(link.href);
        }, 'image/png');
      };
      img.src = svgUrl;

      showToast('Downloading', 'QR code is being downloaded');
    }

    // Close QR modal on escape or backdrop click
    document.getElementById('qrModal').addEventListener('click', (e) => {
      if (e.target.id === 'qrModal') closeQRModal();
    });

    // Bulk operations
    let selectedLinks = new Set();

    function toggleSelectAll() {
      const selectAll = document.getElementById('selectAll');
      const checkboxes = document.querySelectorAll('.link-checkbox');

      checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
        if (selectAll.checked) {
          selectedLinks.add(cb.value);
        } else {
          selectedLinks.delete(cb.value);
        }
      });

      updateBulkUI();
    }

    function updateBulkSelection() {
      selectedLinks.clear();
      document.querySelectorAll('.link-checkbox:checked').forEach(cb => {
        selectedLinks.add(cb.value);
      });
      updateBulkUI();
    }

    function updateBulkUI() {
      const bulkActions = document.getElementById('bulkActions');
      const bulkCount = document.getElementById('bulkCount');
      const selectAll = document.getElementById('selectAll');

      if (selectedLinks.size > 0) {
        bulkActions.classList.add('visible');
        bulkCount.textContent = selectedLinks.size;
      } else {
        bulkActions.classList.remove('visible');
      }

      // Update select all checkbox state
      const checkboxes = document.querySelectorAll('.link-checkbox');
      const checkedCount = document.querySelectorAll('.link-checkbox:checked').length;
      selectAll.checked = checkedCount > 0 && checkedCount === checkboxes.length;
      selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;

      // Update bulk move category dropdown
      const bulkMoveSelect = document.getElementById('bulkMoveCategory');
      bulkMoveSelect.innerHTML = '<option value="">Move to category...</option><option value="none">Remove category</option>' +
        allCategories.map(cat => \`<option value="\${escapeAttr(cat.id)}">\${escapeHtml(cat.name)}</option>\`).join('');
    }

    function clearSelection() {
      selectedLinks.clear();
      document.querySelectorAll('.link-checkbox').forEach(cb => cb.checked = false);
      document.getElementById('selectAll').checked = false;
      updateBulkUI();
    }

    async function bulkDelete() {
      if (selectedLinks.size === 0) return;

      if (!confirm(\`Delete \${selectedLinks.size} link(s)? This cannot be undone.\`)) return;

      const codes = Array.from(selectedLinks);
      const res = await fetch('/api/links/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ codes })
      });

      if (res.ok) {
        const data = await res.json();
        showToast('Links deleted', \`\${data.deleted} link(s) deleted successfully\`);
        clearSelection();
        await Promise.all([loadLinks(), loadStats(), loadCategories()]);
      } else {
        const data = await res.json();
        showToast('Error', data.error || 'Failed to delete links', 'error');
      }
    }

    async function bulkMove() {
      if (selectedLinks.size === 0) return;

      const categoryId = document.getElementById('bulkMoveCategory').value;
      if (!categoryId) {
        showToast('Select category', 'Please select a category to move links to', 'error');
        return;
      }

      const codes = Array.from(selectedLinks);
      const res = await fetch('/api/links/bulk-move', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ codes, category_id: categoryId === 'none' ? null : categoryId })
      });

      if (res.ok) {
        const data = await res.json();
        showToast('Links moved', \`\${data.updated} link(s) moved successfully\`);
        clearSelection();
        document.getElementById('bulkMoveCategory').value = '';
        await Promise.all([loadLinks(), loadCategories()]);
      } else {
        const data = await res.json();
        showToast('Error', data.error || 'Failed to move links', 'error');
      }
    }

    // Minimal QR Code Generator
    // Note: Custom implementation used because Cloudflare Workers doesn't natively support
    // npm packages without a bundler. This self-contained implementation handles URL encoding
    // with byte mode for versions 1-10. For production deployments requiring extensive QR
    // features, consider adding a build step with Wrangler and using a library like 'qrcode-svg'.
    // See: https://developers.cloudflare.com/workers/wrangler/bundling/
    function generateQR(text) {
      // Use a simple approach: encode as binary/byte mode
      const data = encodeData(text);
      const version = getMinVersion(data.length);
      const size = version * 4 + 17;

      // Create matrix
      const matrix = Array(size).fill(null).map(() => Array(size).fill(null));

      // Add finder patterns
      addFinderPattern(matrix, 0, 0);
      addFinderPattern(matrix, size - 7, 0);
      addFinderPattern(matrix, 0, size - 7);

      // Add alignment patterns (for version >= 2)
      if (version >= 2) {
        const alignPos = getAlignmentPositions(version);
        for (const row of alignPos) {
          for (const col of alignPos) {
            if (matrix[row]?.[col] === null) {
              addAlignmentPattern(matrix, row, col);
            }
          }
        }
      }

      // Add timing patterns
      for (let i = 8; i < size - 8; i++) {
        matrix[6][i] = i % 2 === 0;
        matrix[i][6] = i % 2 === 0;
      }

      // Dark module
      matrix[size - 8][8] = true;

      // Reserve format info areas
      for (let i = 0; i < 9; i++) {
        if (matrix[8][i] === null) matrix[8][i] = false;
        if (matrix[i][8] === null) matrix[i][8] = false;
        if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = false;
        if (matrix[size - 1 - i][8] === null) matrix[size - 1 - i][8] = false;
      }

      // Place data
      placeData(matrix, data, version);

      // Apply mask (using mask 0 for simplicity)
      applyMask(matrix);

      // Add format info
      addFormatInfo(matrix, size);

      return matrix;
    }

    function encodeData(text) {
      // Byte mode encoding (mode indicator: 0100)
      const bytes = new TextEncoder().encode(text);
      const bits = [0, 1, 0, 0]; // Mode indicator for byte

      // Character count (8 bits for version 1-9)
      const countBits = bytes.length.toString(2).padStart(8, '0').split('').map(Number);
      bits.push(...countBits);

      // Data
      for (const byte of bytes) {
        const byteBits = byte.toString(2).padStart(8, '0').split('').map(Number);
        bits.push(...byteBits);
      }

      // Terminator
      bits.push(0, 0, 0, 0);

      // Pad to byte boundary
      while (bits.length % 8 !== 0) bits.push(0);

      // Add padding codewords
      const padBytes = [236, 17];
      let padIndex = 0;
      const capacity = getDataCapacity(getMinVersion(bytes.length));
      while (bits.length < capacity * 8) {
        const padBits = padBytes[padIndex % 2].toString(2).padStart(8, '0').split('').map(Number);
        bits.push(...padBits);
        padIndex++;
      }

      return bits;
    }

    function getMinVersion(dataLength) {
      // Simplified version selection (byte mode, L error correction)
      const capacities = [17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
      for (let v = 1; v <= 10; v++) {
        if (dataLength <= capacities[v - 1]) return v;
      }
      return 10;
    }

    function getDataCapacity(version) {
      const capacities = [19, 34, 55, 80, 108, 136, 156, 194, 232, 274];
      return capacities[version - 1] || capacities[0];
    }

    function getAlignmentPositions(version) {
      if (version === 1) return [];
      const positions = [6];
      const step = Math.floor((version * 4 + 10) / (Math.floor(version / 7) + 1));
      let pos = version * 4 + 10;
      while (pos > 10) {
        positions.unshift(pos);
        pos -= step;
      }
      return positions;
    }

    function addFinderPattern(matrix, row, col) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const mr = row + r, mc = col + c;
          if (mr < 0 || mc < 0 || mr >= matrix.length || mc >= matrix.length) continue;
          if (r === -1 || r === 7 || c === -1 || c === 7) {
            matrix[mr][mc] = false; // Separator
          } else if (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
            matrix[mr][mc] = true;
          } else {
            matrix[mr][mc] = false;
          }
        }
      }
    }

    function addAlignmentPattern(matrix, row, col) {
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const mr = row + r, mc = col + c;
          if (mr < 0 || mc < 0 || mr >= matrix.length || mc >= matrix.length) continue;
          if (matrix[mr][mc] !== null) continue;
          if (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0)) {
            matrix[mr][mc] = true;
          } else {
            matrix[mr][mc] = false;
          }
        }
      }
    }

    function placeData(matrix, data, version) {
      const size = matrix.length;
      let dataIndex = 0;
      let upward = true;

      for (let col = size - 1; col >= 1; col -= 2) {
        if (col === 6) col = 5; // Skip timing pattern column

        for (let row = upward ? size - 1 : 0; upward ? row >= 0 : row < size; upward ? row-- : row++) {
          for (let c = 0; c < 2; c++) {
            const currentCol = col - c;
            if (matrix[row][currentCol] === null) {
              matrix[row][currentCol] = dataIndex < data.length ? data[dataIndex++] === 1 : false;
            }
          }
        }
        upward = !upward;
      }
    }

    function applyMask(matrix) {
      const size = matrix.length;
      for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
          if (isDataModule(matrix, row, col, size)) {
            // Mask pattern 0: (row + col) % 2 === 0
            if ((row + col) % 2 === 0) {
              matrix[row][col] = !matrix[row][col];
            }
          }
        }
      }
    }

    function isDataModule(matrix, row, col, size) {
      // Check if this is a data module (not a function pattern)
      if (row < 9 && col < 9) return false; // Top-left finder
      if (row < 9 && col >= size - 8) return false; // Top-right finder
      if (row >= size - 8 && col < 9) return false; // Bottom-left finder
      if (row === 6 || col === 6) return false; // Timing patterns
      return true;
    }

    function addFormatInfo(matrix, size) {
      // Format string for mask 0, error correction L
      const formatBits = [1,1,1,0,1,1,1,1,1,0,0,0,1,0,0];

      // Place format info
      for (let i = 0; i < 6; i++) {
        matrix[8][i] = formatBits[i] === 1;
        matrix[i][8] = formatBits[14 - i] === 1;
      }
      matrix[8][7] = formatBits[6] === 1;
      matrix[8][8] = formatBits[7] === 1;
      matrix[7][8] = formatBits[8] === 1;

      for (let i = 0; i < 7; i++) {
        matrix[8][size - 1 - i] = formatBits[14 - i] === 1;
        matrix[size - 1 - i][8] = formatBits[i] === 1;
      }
      matrix[size - 8][8] = true; // Always dark
    }

    function qrToSVG(matrix, size) {
      const moduleCount = matrix.length;
      const moduleSize = size / moduleCount;

      let svg = \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 \${size} \${size}" width="\${size}" height="\${size}">\`;
      svg += \`<rect width="\${size}" height="\${size}" fill="white"/>\`;

      for (let row = 0; row < moduleCount; row++) {
        for (let col = 0; col < moduleCount; col++) {
          if (matrix[row][col]) {
            svg += \`<rect x="\${col * moduleSize}" y="\${row * moduleSize}" width="\${moduleSize}" height="\${moduleSize}" fill="black"/>\`;
          }
        }
      }

      svg += '</svg>';
      return svg;
    }

    // Theme toggle
    function toggleTheme() {
      const html = document.documentElement;
      const isDark = html.classList.contains('dark');

      if (isDark) {
        html.classList.remove('dark');
        html.classList.add('light');
        localStorage.setItem('theme', 'light');
      } else {
        html.classList.remove('light');
        html.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
      updateThemeIcon();
    }

    function updateThemeIcon() {
      const isDark = document.documentElement.classList.contains('dark');
      document.querySelector('.theme-icon-dark').style.display = isDark ? 'block' : 'none';
      document.querySelector('.theme-icon-light').style.display = isDark ? 'none' : 'block';
    }

    // Initialize theme from localStorage
    function initTheme() {
      const savedTheme = localStorage.getItem('theme');
      if (savedTheme === 'light') {
        document.documentElement.classList.remove('dark');
        document.documentElement.classList.add('light');
      }
      updateThemeIcon();
    }
    initTheme();

    // Close mobile menu when clicking sidebar nav items
    document.getElementById('sidebar').addEventListener('click', (e) => {
      if (e.target.closest('.nav-item') && window.innerWidth <= 768) {
        closeMobileMenu();
      }
    });

    // =================================================================
    // MOBILE UI FUNCTIONS
    // =================================================================

    // Render mobile link cards
    function renderMobileLinks(links = allLinks) {
      const container = document.getElementById('mobileLinksContainer');
      if (!container) return;

      if (links.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px 20px; color: hsl(var(--muted-foreground));">No links yet. Tap + to create one!</div>';
        return;
      }

      container.innerHTML = links.map(link => {
        const safeCode = escapeHtml(link.code);
        const safeDest = escapeHtml(link.destination);
        const catName = link.category_name ? escapeHtml(link.category_name) : '';

        return \`
          <div class="link-card" data-code="\${escapeAttr(link.code)}">
            <div class="link-card-header">
              <a href="\${baseUrl}/\${encodeURIComponent(link.code)}" target="_blank" class="link-card-code">/\${safeCode}</a>
              <div class="link-card-actions">
                <button class="link-card-action" onclick="copyLink('\${escapeJs(link.code)}')" title="Copy">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
                    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                  </svg>
                </button>
                <button class="link-card-action" onclick="showQRCode('\${escapeJs(link.code)}')" title="QR Code">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/>
                    <rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/>
                    <path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/>
                    <path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>
                  </svg>
                </button>
              </div>
            </div>
            <div class="link-card-url">\${safeDest}</div>
            <div class="link-card-footer">
              <div class="link-card-meta">
                <span class="link-card-clicks">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                    <path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>
                  </svg>
                  \${link.clicks || 0}
                </span>
                \${catName ? \`<span class="link-card-category">\${catName}</span>\` : ''}
              </div>
            </div>
          </div>
        \`;
      }).join('');
    }

    // Filter mobile links
    function filterMobileLinks(query) {
      const q = query.toLowerCase().trim();
      if (!q) {
        renderMobileLinks(allLinks);
        return;
      }
      const filtered = allLinks.filter(link =>
        link.code.toLowerCase().includes(q) ||
        link.destination.toLowerCase().includes(q) ||
        (link.description && link.description.toLowerCase().includes(q))
      );
      renderMobileLinks(filtered);
    }

    // Update mobile stats
    function updateMobileStats() {
      const linksEl = document.getElementById('mobileStatLinks');
      const clicksEl = document.getElementById('mobileStatClicks');
      if (linksEl) linksEl.textContent = allLinks.length;
      if (clicksEl) clicksEl.textContent = allLinks.reduce((sum, l) => sum + (l.clicks || 0), 0);
    }

    // Switch mobile tab
    function switchMobileTab(tab) {
      document.querySelectorAll('.tab-item').forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tab);
      });

      // Update header title
      const titles = { links: 'Links', stats: 'Analytics', categories: 'Categories', settings: 'Settings' };
      const titleEl = document.querySelector('.mobile-header-title');
      if (titleEl) titleEl.textContent = titles[tab] || 'Links';
    }

    // Sheet functions
    function openCreateSheet() {
      document.getElementById('createSheet').classList.add('open');
      document.body.style.overflow = 'hidden';
      // Populate categories
      const select = document.getElementById('sheetNewCategory');
      if (select) {
        select.innerHTML = '<option value="">No category</option>' +
          allCategories.map(c => \`<option value="\${c.id}">\${escapeHtml(c.name)}</option>\`).join('');
      }
    }

    function closeCreateSheet() {
      document.getElementById('createSheet').classList.remove('open');
      document.body.style.overflow = '';
    }

    // Create link from sheet
    async function createLinkFromSheet() {
      const code = document.getElementById('sheetNewCode').value.trim();
      const destination = document.getElementById('sheetNewDestination').value.trim();
      const categoryId = document.getElementById('sheetNewCategory').value;
      const description = document.getElementById('sheetNewDescription').value.trim();

      if (!destination) {
        showToast('Error', 'Please enter a destination URL', 'error');
        return;
      }

      try {
        const res = await fetch('/api/links', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code: code || undefined,
            destination,
            category_id: categoryId || undefined,
            description: description || undefined
          })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to create link');

        showToast('Success', 'Link created!', 'success');
        closeCreateSheet();

        // Clear form
        document.getElementById('sheetNewCode').value = '';
        document.getElementById('sheetNewDestination').value = '';
        document.getElementById('sheetNewDescription').value = '';

        // Refresh links
        await loadLinks();
        renderMobileLinks();
        updateMobileStats();
      } catch (err) {
        showToast('Error', err.message, 'error');
      }
    }

    // Hook into existing functions to update mobile UI
    const originalLoadLinks = loadLinks;
    loadLinks = async function() {
      await originalLoadLinks();
      renderMobileLinks();
      updateMobileStats();
    };

    // Init
    init();

    // Register Service Worker for PWA
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    }
  </script>
</body>
</html>`;
}

// Design System Reference Page
function getDesignSystemHTML() {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>URLsToGo - Design System</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --background: 0.1430 0.0219 293.0857; --foreground: 0.9842 0.0034 247.8575; --card: 0.1831 0.0284 289.8409; --muted: 0.2352 0.0362 290.5754; --muted-foreground: 0.7000 0.0100 285.0000; --border: 0.2352 0.0362 290.5754; --primary: 0.6056 0.2189 292.7172; --primary-foreground: 1.0000 0 0; --indigo: 0.6056 0.2189 292.7172; --purple: 0.6368 0.2078 307.3313; --radius: 0.75rem; --cat-work: 0.6850 0.2190 307.0000; --cat-personal: 0.6520 0.2450 340.0000; --cat-social: 0.6000 0.1700 210.0000; --cat-marketing: 0.6800 0.2000 50.0000; --cat-docs: 0.5800 0.1500 165.0000; }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, sans-serif; background: oklch(var(--background)); color: oklch(var(--foreground)); min-height: 100vh; padding: 48px 24px; max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; }
    .subtitle { color: oklch(var(--muted-foreground)); margin-bottom: 48px; }
    h2 { font-size: 20px; font-weight: 600; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid oklch(var(--border)); }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .card { background: oklch(var(--card)); border: 1px solid oklch(var(--border)); border-radius: var(--radius); padding: 20px; }
    .color-swatch { width: 100%; height: 60px; border-radius: calc(var(--radius) - 4px); margin-bottom: 12px; }
    .color-name { font-weight: 500; margin-bottom: 4px; }
    .color-value { font-size: 12px; color: oklch(var(--muted-foreground)); font-family: monospace; }
    .btn { display: inline-flex; align-items: center; justify-content: center; height: 36px; padding: 0 16px; font-size: 14px; font-weight: 500; border-radius: var(--radius); border: none; cursor: pointer; transition: all 150ms; }
    .btn-primary { background: oklch(var(--primary)); color: oklch(var(--primary-foreground)); }
    .btn-secondary { background: oklch(var(--muted)); color: oklch(var(--foreground)); }
    .btn-indigo { background: oklch(var(--indigo)); color: white; }
    .btn-outline { background: transparent; border: 1px solid oklch(var(--border)); color: oklch(var(--foreground)); }
    .btn-ghost { background: transparent; color: oklch(var(--foreground)); }
    .btn:hover { opacity: 0.9; }
    .input { height: 40px; width: 100%; padding: 0 12px; background: oklch(var(--background)); border: 1px solid oklch(var(--border)); border-radius: var(--radius); font-size: 14px; color: oklch(var(--foreground)); }
    .input:focus { outline: none; border-color: oklch(var(--indigo)); }
    .badge { display: inline-flex; padding: 4px 10px; font-size: 12px; font-weight: 500; border-radius: var(--radius); }
    .badge-cat { display: inline-flex; align-items: center; gap: 6px; }
    .cat-dot { width: 8px; height: 8px; border-radius: 50%; }
    .flex { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
    .back-link { display: inline-flex; align-items: center; gap: 8px; color: oklch(var(--indigo)); text-decoration: none; margin-bottom: 24px; }
    .back-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <a href="/admin" class="back-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 18-6-6 6-6"/></svg> Back to Admin</a>
  <h1>Design System</h1>
  <p class="subtitle">Shadcn-style components and colors for URLsToGo</p>

  <h2>Colors</h2>
  <div class="grid">
    <div class="card"><div class="color-swatch" style="background: oklch(var(--background)); border: 1px solid oklch(var(--border));"></div><div class="color-name">Background</div><div class="color-value">--background</div></div>
    <div class="card"><div class="color-swatch" style="background: oklch(var(--foreground));"></div><div class="color-name">Foreground</div><div class="color-value">--foreground</div></div>
    <div class="card"><div class="color-swatch" style="background: oklch(var(--card)); border: 1px solid oklch(var(--border));"></div><div class="color-name">Card</div><div class="color-value">--card</div></div>
    <div class="card"><div class="color-swatch" style="background: oklch(var(--muted));"></div><div class="color-name">Muted</div><div class="color-value">--muted</div></div>
    <div class="card"><div class="color-swatch" style="background: oklch(var(--indigo));"></div><div class="color-name">Indigo</div><div class="color-value">--indigo</div></div>
    <div class="card"><div class="color-swatch" style="background: linear-gradient(135deg, oklch(var(--indigo)) 0%, oklch(var(--purple)) 100%);"></div><div class="color-name">Gradient</div><div class="color-value">indigo → purple</div></div>
  </div>

  <h2>Category Colors</h2>
  <div class="flex">
    <span class="badge badge-cat" style="background: oklch(var(--cat-work) / 0.15); color: oklch(var(--cat-work));"><span class="cat-dot" style="background: oklch(var(--cat-work));"></span> Work</span>
    <span class="badge badge-cat" style="background: oklch(var(--cat-personal) / 0.15); color: oklch(var(--cat-personal));"><span class="cat-dot" style="background: oklch(var(--cat-personal));"></span> Personal</span>
    <span class="badge badge-cat" style="background: oklch(var(--cat-social) / 0.15); color: oklch(var(--cat-social));"><span class="cat-dot" style="background: oklch(var(--cat-social));"></span> Social</span>
    <span class="badge badge-cat" style="background: oklch(var(--cat-marketing) / 0.15); color: oklch(var(--cat-marketing));"><span class="cat-dot" style="background: oklch(var(--cat-marketing));"></span> Marketing</span>
  </div>

  <h2>Buttons</h2>
  <div class="flex">
    <button class="btn btn-primary">Primary</button>
    <button class="btn btn-secondary">Secondary</button>
    <button class="btn btn-indigo">Indigo</button>
    <button class="btn btn-outline">Outline</button>
    <button class="btn btn-ghost">Ghost</button>
  </div>

  <h2>Inputs</h2>
  <div class="grid" style="grid-template-columns: 1fr 1fr;">
    <input type="text" class="input" placeholder="Text input...">
    <input type="text" class="input" value="With value">
  </div>

  <h2>Cards</h2>
  <div class="grid">
    <div class="card"><div style="font-weight: 600; margin-bottom: 8px;">Card Title</div><div style="color: oklch(var(--muted-foreground)); font-size: 14px;">Card description text goes here.</div></div>
    <div class="card"><div style="font-size: 28px; font-weight: 700;">128</div><div style="color: oklch(var(--muted-foreground)); font-size: 14px;">Total Links</div></div>
  </div>

  <h2>Typography</h2>
  <div class="card">
    <div style="font-size: 32px; font-weight: 700; margin-bottom: 8px;">Heading 1</div>
    <div style="font-size: 24px; font-weight: 600; margin-bottom: 8px;">Heading 2</div>
    <div style="font-size: 18px; font-weight: 600; margin-bottom: 8px;">Heading 3</div>
    <div style="font-size: 14px; margin-bottom: 8px;">Body text - The quick brown fox jumps over the lazy dog.</div>
    <div style="font-size: 14px; color: oklch(var(--muted-foreground));">Muted text - Secondary information displayed here.</div>
  </div>
</body>
</html>`;
}

// Mobile App Mockup Page
function getMobileMockupHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>URLsToGo - Mobile App Mockup</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%); min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 20px; }
    .header { text-align: center; color: white; margin-bottom: 32px; }
    .header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
    .header p { color: rgba(255,255,255,0.6); font-size: 14px; }
    .back-link { display: inline-flex; align-items: center; gap: 8px; color: #818cf8; text-decoration: none; margin-bottom: 24px; }
    .iphone { width: 375px; height: 812px; background: #1c1c1e; border-radius: 55px; padding: 18px; box-shadow: 0 0 0 3px #2c2c2e, 0 50px 100px -20px rgba(0,0,0,0.5); position: relative; }
    .iphone::before { content: ''; position: absolute; top: 18px; left: 50%; transform: translateX(-50%); width: 150px; height: 35px; background: #1c1c1e; border-radius: 0 0 20px 20px; z-index: 10; }
    .screen { width: 100%; height: 100%; background: #0a0a0a; border-radius: 40px; overflow: hidden; display: flex; flex-direction: column; font-size: 15px; color: #fafafa; }
    .status-bar { height: 54px; padding: 14px 28px 0; display: flex; justify-content: space-between; font-size: 15px; font-weight: 600; }
    .app-header { padding: 0 20px 16px; display: flex; justify-content: space-between; align-items: center; }
    .app-title { font-size: 32px; font-weight: 700; }
    .header-btn { width: 40px; height: 40px; background: #262626; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
    .search-bar { margin: 0 20px 16px; height: 44px; background: #262626; border-radius: 12px; display: flex; align-items: center; padding: 0 14px; gap: 10px; color: #a1a1aa; }
    .stats { display: flex; gap: 12px; padding: 0 20px; margin-bottom: 20px; }
    .stat { flex: 1; background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 14px; }
    .stat-value { font-size: 24px; font-weight: 700; }
    .stat-label { font-size: 12px; color: #a1a1aa; }
    .stat-change { font-size: 11px; color: #22c55e; margin-top: 4px; }
    .section-header { display: flex; justify-content: space-between; padding: 0 20px; margin-bottom: 12px; }
    .section-title { font-size: 18px; font-weight: 600; }
    .section-action { font-size: 14px; color: #818cf8; }
    .links-list { flex: 1; overflow-y: auto; padding: 0 20px; }
    .link-card { background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 16px; margin-bottom: 12px; }
    .link-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
    .link-code { font-family: monospace; font-size: 16px; color: #818cf8; background: rgba(129,140,248,0.15); padding: 6px 12px; border-radius: 8px; }
    .link-url { font-size: 14px; color: #a1a1aa; margin-bottom: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .link-footer { display: flex; justify-content: space-between; align-items: center; }
    .link-meta { display: flex; gap: 16px; font-size: 13px; color: #a1a1aa; }
    .link-clicks { color: #22c55e; }
    .link-cat { display: flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 12px; }
    .cat-work { background: rgba(167,139,250,0.15); color: #a78bfa; }
    .cat-social { background: rgba(34,211,238,0.15); color: #22d3ee; }
    .cat-marketing { background: rgba(251,146,60,0.15); color: #fb923c; }
    .tab-bar { height: 83px; background: rgba(23,23,23,0.95); backdrop-filter: blur(20px); border-top: 1px solid #262626; display: flex; padding: 8px 0 25px; }
    .tab { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 4px; color: #a1a1aa; font-size: 10px; }
    .tab.active { color: #818cf8; }
    .tab-add { width: 56px; height: 56px; background: linear-gradient(135deg, #6366f1 0%, #a78bfa 100%); border-radius: 16px; display: flex; align-items: center; justify-content: center; margin-top: -20px; box-shadow: 0 4px 20px rgba(99,102,241,0.4); }
    .home-indicator { position: absolute; bottom: 26px; left: 50%; transform: translateX(-50%); width: 134px; height: 5px; background: rgba(255,255,255,0.3); border-radius: 3px; }
    .nav-btns { display: flex; gap: 8px; margin-top: 16px; }
    .nav-btn { padding: 8px 16px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; color: white; font-size: 13px; cursor: pointer; }
    .nav-btn:hover { background: rgba(255,255,255,0.2); }
    .nav-btn.active { background: #6366f1; border-color: #6366f1; }
    svg { width: 20px; height: 20px; }
  </style>
</head>
<body>
  <a href="/admin" class="back-link"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 18-6-6 6-6"/></svg> Back to Admin</a>
  <div class="header"><h1>Mobile App Mockup</h1><p>iPhone companion app design preview</p></div>
  <div class="iphone">
    <div class="screen">
      <div class="status-bar"><span>9:41</span><span>100%</span></div>
      <div class="app-header">
        <div class="app-title">Links</div>
        <div class="header-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/></svg></div>
      </div>
      <div class="search-bar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg><span>Search links...</span></div>
      <div class="stats">
        <div class="stat"><div class="stat-value">128</div><div class="stat-label">Total Links</div><div class="stat-change">+12 this week</div></div>
        <div class="stat"><div class="stat-value">4.8K</div><div class="stat-label">Total Clicks</div><div class="stat-change">+523 today</div></div>
      </div>
      <div class="section-header"><div class="section-title">Recent Links</div><div class="section-action">See All</div></div>
      <div class="links-list">
        <div class="link-card">
          <div class="link-header"><span class="link-code">/portfolio</span></div>
          <div class="link-url">https://example.com/my-portfolio-2024</div>
          <div class="link-footer"><div class="link-meta"><span class="link-clicks">1,234 clicks</span><span>2d ago</span></div><span class="link-cat cat-work">Work</span></div>
        </div>
        <div class="link-card">
          <div class="link-header"><span class="link-code">/twitter</span></div>
          <div class="link-url">https://twitter.com/username</div>
          <div class="link-footer"><div class="link-meta"><span class="link-clicks">856 clicks</span><span>5d ago</span></div><span class="link-cat cat-social">Social</span></div>
        </div>
        <div class="link-card">
          <div class="link-header"><span class="link-code">/promo</span></div>
          <div class="link-url">https://producthunt.com/posts/app</div>
          <div class="link-footer"><div class="link-meta"><span class="link-clicks">2,341 clicks</span><span>1w ago</span></div><span class="link-cat cat-marketing">Marketing</span></div>
        </div>
      </div>
      <div class="tab-bar">
        <div class="tab active"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>Links</div>
        <div class="tab"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>Analytics</div>
        <div class="tab"><div class="tab-add"><svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><path d="M5 12h14"/><path d="M12 5v14"/></svg></div></div>
        <div class="tab"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg>Categories</div>
        <div class="tab"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>Settings</div>
      </div>
      <div class="home-indicator"></div>
    </div>
  </div>
</body>
</html>`;
}
