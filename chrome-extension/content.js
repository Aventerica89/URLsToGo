// Artifact Manager Content Script for Claude.ai
// Detects artifacts and adds "Save to Artifact Manager" buttons

(function() {
  'use strict';

  // Cross-browser API compatibility
  const browser = globalThis.browser || globalThis.chrome;

  const BUTTON_CLASS = 'artifact-manager-save-btn';
  const PROCESSED_ATTR = 'data-artifact-manager-processed';

  // Debounce helper
  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Create save button
  function createSaveButton() {
    const button = document.createElement('button');
    button.className = BUTTON_CLASS;
    button.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
        <polyline points="17 21 17 13 7 13 7 21"/>
        <polyline points="7 3 7 8 15 8"/>
      </svg>
      <span>Save</span>
    `;
    button.title = 'Save to Artifact Manager';
    return button;
  }

  // Check if a name is a placeholder (synced with macOS NameValidator.swift and backend)
  function isPlaceholder(name) {
    if (!name || typeof name !== 'string') return true;

    const trimmed = name.trim();
    if (trimmed === '') return true;

    const placeholderPatterns = [
      /^Saving\.{3}$/i,
      /^Loading\.{3}$/i,
      /^Downloading\.{3}$/i,
      /^Untitled( \d+)?$/i,
      /^New Artifact$/i,
      /^\s*$/
    ];

    return placeholderPatterns.some(pattern => pattern.test(trimmed));
  }

  // Enhanced artifact name extraction with multiple strategies
  function extractArtifactName(panel) {
    // Strategy 1: Look for title text in artifact header with data-testid
    const titleEl = panel.querySelector('[data-testid="artifact-title"]') ||
                    panel.querySelector('[data-testid*="title"]');
    if (titleEl?.textContent?.trim() && !isPlaceholder(titleEl.textContent.trim())) {
      return titleEl.textContent.trim();
    }

    // Strategy 2: Find title in parent conversation message
    const messageContainer = panel.closest('[class*="message"]') ||
                            panel.closest('[data-testid*="message"]');
    if (messageContainer) {
      const artifactName = messageContainer.querySelector('[class*="artifact-name"]') ||
                          messageContainer.querySelector('[class*="artifact"] [class*="title"]');
      if (artifactName?.textContent?.trim() && !isPlaceholder(artifactName.textContent.trim())) {
        return artifactName.textContent.trim();
      }
    }

    // Strategy 3: Look for heading elements near the artifact
    const headings = panel.querySelectorAll('h1, h2, h3, h4, h5, h6');
    for (const heading of headings) {
      const text = heading.textContent.trim();
      if (text && !isPlaceholder(text)) {
        return text;
      }
    }

    // Strategy 4: Find the artifact title from text content in the header area
    // The title appears as text like "Smith event options" with type "HTML" nearby
    const headerTexts = panel.querySelectorAll('div, span');
    for (const el of headerTexts) {
      const text = el.textContent.trim();
      // Skip very short or very long text, and skip known labels
      if (text.length > 2 && text.length < 100 &&
          !['Copy', 'HTML', 'Code', 'Preview', 'Download', 'Save', 'View', 'Edit', 'Remix'].includes(text) &&
          !el.querySelector('*') && // Only leaf text nodes
          !isPlaceholder(text)) {
        return text;
      }
    }

    // Strategy 5: Look for text before the artifact panel
    const prevSibling = panel.previousElementSibling;
    if (prevSibling) {
      const prevText = prevSibling.textContent.trim();
      if (prevText && !isPlaceholder(prevText) && prevText.length < 100) {
        return prevText;
      }
    }

    // Strategy 6: Extract from iframe title attribute
    const iframe = panel.querySelector('iframe');
    if (iframe?.title && !isPlaceholder(iframe.title)) {
      return iframe.title;
    }

    // Fallback: Return placeholder that will be caught by validation
    return 'Untitled Artifact';
  }

  // Extract artifact data from the panel
  function extractArtifactData(panel) {
    const data = {
      name: extractArtifactName(panel),
      description: '',
      artifact_type: 'code',
      source_type: 'downloaded',
      published_url: '',
      file_content: '',
      language: '',
      conversation_url: window.location.href
    };

    // Check if current URL contains artifact info
    const url = new URL(window.location.href);
    if (url.searchParams.has('artifactId')) {
      data.artifact_id = url.searchParams.get('artifactId');
    }

    // Look for published claude.site URL in the panel first (more accurate)
    const panelLinks = panel.querySelectorAll('a[href*="claude.site/artifacts"]');
    if (panelLinks.length > 0) {
      data.published_url = panelLinks[0].href;
      data.source_type = 'published';

      // Extract artifact ID from URL
      const match = data.published_url.match(/\/artifacts\/([a-zA-Z0-9-]+)/);
      if (match) {
        data.artifact_id = match[1];
      }
    }

    // Fallback: Check all page links
    if (!data.published_url) {
      const links = document.querySelectorAll('a[href*="claude.site"]');
      if (links.length > 0) {
        data.published_url = links[0].href;
        data.source_type = 'published';
      }
    }

    // Also check if there's a share/publish URL visible in text
    if (!data.published_url) {
      const allText = document.body.innerText;
      const claudeSiteMatch = allText.match(/https:\/\/claude\.site\/artifacts\/[a-zA-Z0-9-]+/);
      if (claudeSiteMatch) {
        data.published_url = claudeSiteMatch[0];
        data.source_type = 'published';
      }
    }

    // Detect artifact type from the panel
    const panelText = panel.textContent.toLowerCase();
    if (panelText.includes('html')) {
      data.artifact_type = 'html';
      data.language = 'HTML';
    } else if (panelText.includes('react') || panelText.includes('jsx') || panelText.includes('tsx')) {
      data.artifact_type = 'code';
      data.language = 'React';
    } else if (panelText.includes('python') || panelText.includes('.py')) {
      data.artifact_type = 'code';
      data.language = 'Python';
    } else if (panelText.includes('javascript') || panelText.includes('typescript') || panelText.includes('.js') || panelText.includes('.ts')) {
      data.artifact_type = 'code';
      data.language = 'JavaScript';
    } else if (panelText.includes('svg')) {
      data.artifact_type = 'image';
      data.language = 'SVG';
    } else if (panelText.includes('css')) {
      data.artifact_type = 'code';
      data.language = 'CSS';
    } else if (panelText.includes('markdown') || panelText.includes('.md')) {
      data.artifact_type = 'document';
      data.language = 'Markdown';
    }

    // Try to get content by clicking Copy button and reading clipboard
    // Look for the Copy button more specifically
    const copyBtn = panel.querySelector('button[aria-label*="Copy"]') ||
                    Array.from(panel.querySelectorAll('button')).find(b => b.textContent.includes('Copy'));
    if (copyBtn) {
      data._copyButton = copyBtn;
    }

    // Store panel reference for content extraction
    data._panel = panel;

    return data;
  }

  // Robust content extraction with multiple fallback methods
  async function extractContent(panel, publishedUrl) {
    // Method 1: Try clipboard (existing method - most reliable when it works)
    try {
      const copyBtn = panel.querySelector('button[aria-label*="Copy"]') ||
                      Array.from(panel.querySelectorAll('button')).find(b => b.textContent.includes('Copy'));
      if (copyBtn) {
        copyBtn.click();
        await new Promise(r => setTimeout(r, 150)); // Wait for clipboard
        const clipboardText = await navigator.clipboard.readText();
        if (clipboardText && clipboardText.length > 10) {
          console.log('Artifact Manager: Content extracted via clipboard');
          return clipboardText;
        }
      }
    } catch (e) {
      console.log('Artifact Manager: Clipboard method failed:', e.message);
    }

    // Method 2: Extract from iframe srcdoc or content
    try {
      const iframe = panel.querySelector('iframe[src*="claudeusercontent.com"]');
      if (iframe) {
        // Try to access iframe content (may fail due to CORS)
        try {
          const doc = iframe.contentDocument || iframe.contentWindow?.document;
          if (doc?.documentElement) {
            const content = doc.documentElement.outerHTML;
            if (content && content.length > 50) {
              console.log('Artifact Manager: Content extracted from iframe document');
              return content;
            }
          }
        } catch (e) {
          // Cross-origin restriction - expected
        }

        // Try srcdoc attribute
        if (iframe.srcdoc && iframe.srcdoc.length > 50) {
          console.log('Artifact Manager: Content extracted from iframe srcdoc');
          return iframe.srcdoc;
        }
      }
    } catch (e) {
      console.log('Artifact Manager: Iframe method failed:', e.message);
    }

    // Method 3: Check for code block in panel (for code artifacts)
    try {
      const codeBlock = panel.querySelector('pre code') ||
                       panel.querySelector('code') ||
                       panel.querySelector('pre');
      if (codeBlock?.textContent && codeBlock.textContent.length > 10) {
        console.log('Artifact Manager: Content extracted from code block');
        return codeBlock.textContent;
      }
    } catch (e) {
      console.log('Artifact Manager: Code block method failed:', e.message);
    }

    // Method 4: Fetch from published URL if available
    if (publishedUrl && publishedUrl.includes('claude.site/artifacts')) {
      try {
        console.log('Artifact Manager: Attempting to fetch from published URL...');
        const response = await fetch(publishedUrl);
        if (response.ok) {
          const html = await response.text();
          if (html && html.length > 50) {
            console.log('Artifact Manager: Content extracted from published URL');
            return html;
          }
        }
      } catch (e) {
        console.log('Artifact Manager: Published URL fetch failed:', e.message);
      }
    }

    // Method 5: Look for any pre-formatted text in the panel
    try {
      const textElements = panel.querySelectorAll('[class*="code"], [class*="content"], [class*="text"]');
      for (const el of textElements) {
        if (el.textContent && el.textContent.length > 50 && !el.querySelector('button')) {
          console.log('Artifact Manager: Content extracted from text element');
          return el.textContent;
        }
      }
    } catch (e) {
      console.log('Artifact Manager: Text element method failed:', e.message);
    }

    console.warn('Artifact Manager: All content extraction methods failed');
    return null;
  }

  // Validate artifact name before saving (synced with macOS NameValidator and backend)
  function validateArtifactName(name) {
    if (!name || isPlaceholder(name)) {
      return {
        valid: false,
        error: 'Artifact name appears to be a placeholder. Please wait for Claude to finish generating the artifact, or manually edit the name before saving.'
      };
    }

    return { valid: true };
  }

  // Handle save button click
  async function handleSaveClick(event, panel) {
    event.preventDefault();
    event.stopPropagation();

    const button = event.currentTarget;
    const originalContent = button.innerHTML;

    // Show loading
    button.innerHTML = `
      <svg class="artifact-manager-spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12a9 9 0 11-6.219-8.56"/>
      </svg>
      <span>Saving...</span>
    `;
    button.disabled = true;

    try {
      const artifactData = extractArtifactData(panel);

      // Validate name before proceeding (client-side validation)
      const validation = validateArtifactName(artifactData.name);
      if (!validation.valid) {
        throw new Error(validation.error);
      }

      // Extract content using robust multi-method extraction
      const publishedUrl = artifactData.published_url;

      const content = await extractContent(panel, publishedUrl);
      if (content) {
        artifactData.file_content = content;
      } else {
        console.warn('Artifact Manager: No content could be extracted, saving metadata only');
      }

      // Clean up internal properties
      delete artifactData._copyButton;
      delete artifactData._panel;

      const response = await browser.runtime.sendMessage({
        action: 'saveArtifact',
        data: artifactData
      });

      if (response.success) {
        button.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <span>Saved!</span>
        `;
        button.classList.add('artifact-manager-success');
        showNotification('Artifact saved to Artifact Manager!', 'success');
      } else {
        throw new Error(response.error || 'Failed to save');
      }
    } catch (error) {
      console.error('Artifact Manager: Save failed', error);
      button.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <span>Error</span>
      `;
      button.classList.add('artifact-manager-error');
      showNotification(error.message || 'Failed to save artifact', 'error');
    }

    setTimeout(() => {
      button.innerHTML = originalContent;
      button.classList.remove('artifact-manager-success', 'artifact-manager-error');
      button.disabled = false;
    }, 2500);
  }

  // Show notification toast
  function showNotification(message, type = 'info') {
    const existing = document.querySelector('.artifact-manager-notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `artifact-manager-notification artifact-manager-notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => notification.remove(), 8000);
  }

  // Find and process artifact panels
  function processArtifacts() {
    // Look for the artifact preview panel
    // Based on the DOM, it contains an iframe from claudeusercontent.com
    const iframes = document.querySelectorAll('iframe[src*="claudeusercontent.com"]');

    iframes.forEach(iframe => {
      // Find the panel container (go up to find the header)
      let panel = iframe.closest('div[class*="flex"]');

      // Walk up to find a suitable container with the title
      for (let i = 0; i < 10 && panel; i++) {
        if (panel.querySelector('button') && panel.offsetWidth > 200) {
          break;
        }
        panel = panel.parentElement;
      }

      if (!panel || panel.hasAttribute(PROCESSED_ATTR)) return;
      panel.setAttribute(PROCESSED_ATTR, 'true');

      // Find where to insert the button - look for the Copy button
      const copyButton = panel.querySelector('button');
      if (copyButton) {
        const buttonContainer = copyButton.parentElement;

        // Check if we already added our button
        if (buttonContainer && !buttonContainer.querySelector(`.${BUTTON_CLASS}`)) {
          const saveButton = createSaveButton();
          saveButton.addEventListener('click', (e) => handleSaveClick(e, panel));

          // Insert before the copy button
          buttonContainer.insertBefore(saveButton, copyButton);
        }
      }
    });

    // Also look for artifact mentions in the chat (the small preview cards)
    const artifactCards = document.querySelectorAll('[class*="artifact"], [data-testid*="artifact"]');
    artifactCards.forEach(card => {
      if (card.hasAttribute(PROCESSED_ATTR)) return;
      if (card.offsetHeight < 30 || card.offsetWidth < 100) return;

      card.setAttribute(PROCESSED_ATTR, 'true');

      // Check if we already added our button
      if (card.querySelector(`.${BUTTON_CLASS}`)) return;

      const saveButton = createSaveButton();
      saveButton.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleSaveClick(e, card);
      });

      // Strategy 1: Find existing button container in the card
      const existingButtonContainer = card.querySelector('div[class*="flex"][class*="gap"]') ||
                                      card.querySelector('div > button')?.parentElement;

      if (existingButtonContainer && existingButtonContainer.querySelector('button')) {
        // Insert into existing button row
        const firstButton = existingButtonContainer.querySelector('button');
        existingButtonContainer.insertBefore(saveButton, firstButton);
        return;
      }

      // Strategy 2: Find the card's action area (usually at bottom)
      const actionArea = card.querySelector('[class*="action"]') ||
                        card.querySelector('[class*="footer"]') ||
                        card.querySelector('[class*="bottom"]');

      if (actionArea) {
        actionArea.insertBefore(saveButton, actionArea.firstChild);
        return;
      }

      // Strategy 3: Create a button container at the bottom of the card
      const buttonContainer = document.createElement('div');
      buttonContainer.className = 'artifact-manager-btn-row';
      buttonContainer.appendChild(saveButton);
      card.appendChild(buttonContainer);
    });
  }

  // Setup mutation observer
  function setupObserver() {
    const debouncedProcess = debounce(processArtifacts, 300);

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          debouncedProcess();
          break;
        }
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
    return observer;
  }

  // Initialize
  function init() {
    console.log('Artifact Manager: Initializing...');

    // Initial scan
    setTimeout(processArtifacts, 1000);

    // Watch for changes
    setupObserver();

    // Re-scan periodically (Claude.ai is very dynamic)
    setInterval(processArtifacts, 3000);

    console.log('Artifact Manager: Ready');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
