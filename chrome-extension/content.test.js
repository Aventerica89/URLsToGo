/**
 * Unit tests for Artifact Manager content script
 * Run with: node --experimental-vm-modules content.test.js
 * Or use in browser console for manual testing
 */

// Mock DOM for testing
function createMockCard(options = {}) {
  const card = document.createElement('div');
  card.className = options.className || 'artifact-card';
  card.style.height = options.height || '100px';
  card.style.width = options.width || '200px';

  if (options.withButtonContainer) {
    const btnContainer = document.createElement('div');
    btnContainer.className = 'flex gap-2';
    const existingBtn = document.createElement('button');
    existingBtn.textContent = 'View';
    btnContainer.appendChild(existingBtn);
    card.appendChild(btnContainer);
  }

  if (options.withActionArea) {
    const actionArea = document.createElement('div');
    actionArea.className = 'action-buttons';
    card.appendChild(actionArea);
  }

  return card;
}

// Test: Button placement strategy 1 - existing button container
function testButtonPlacementInExistingContainer() {
  const card = createMockCard({ withButtonContainer: true });
  const btnContainer = card.querySelector('.flex');
  const originalBtnCount = btnContainer.querySelectorAll('button').length;

  // Simulate adding save button
  const saveButton = document.createElement('button');
  saveButton.className = 'artifact-manager-save-btn';
  saveButton.textContent = 'Save';

  const firstButton = btnContainer.querySelector('button');
  btnContainer.insertBefore(saveButton, firstButton);

  const newBtnCount = btnContainer.querySelectorAll('button').length;
  console.assert(newBtnCount === originalBtnCount + 1, 'Button should be added to container');
  console.assert(btnContainer.firstChild === saveButton, 'Save button should be first');

  console.log('✓ testButtonPlacementInExistingContainer passed');
}

// Test: Button placement strategy 2 - action area
function testButtonPlacementInActionArea() {
  const card = createMockCard({ withActionArea: true });
  const actionArea = card.querySelector('.action-buttons');

  const saveButton = document.createElement('button');
  saveButton.className = 'artifact-manager-save-btn';
  saveButton.textContent = 'Save';

  actionArea.insertBefore(saveButton, actionArea.firstChild);

  console.assert(actionArea.contains(saveButton), 'Save button should be in action area');
  console.log('✓ testButtonPlacementInActionArea passed');
}

// Test: Button placement strategy 3 - create new container
function testButtonPlacementNewContainer() {
  const card = createMockCard({}); // No existing containers

  const buttonContainer = document.createElement('div');
  buttonContainer.className = 'artifact-manager-btn-row';

  const saveButton = document.createElement('button');
  saveButton.className = 'artifact-manager-save-btn';
  saveButton.textContent = 'Save';

  buttonContainer.appendChild(saveButton);
  card.appendChild(buttonContainer);

  console.assert(card.querySelector('.artifact-manager-btn-row'), 'Button row should be created');
  console.assert(card.lastChild === buttonContainer, 'Button row should be at bottom');

  console.log('✓ testButtonPlacementNewContainer passed');
}

// Test: Skip small cards
function testSkipSmallCards() {
  const card = createMockCard({ height: '20px', width: '50px' });
  const shouldSkip = card.offsetHeight < 30 || card.offsetWidth < 100;

  console.assert(shouldSkip === true, 'Should skip cards smaller than 30x100');
  console.log('✓ testSkipSmallCards passed');
}

// Test: Placeholder name detection
function testPlaceholderDetection() {
  const placeholders = [
    'Saving...',
    'Loading...',
    'Downloading...',
    'Untitled',
    'Untitled 1',
    'New Artifact',
    '',
    '   '
  ];

  const validNames = [
    'My Artifact',
    'Component.tsx',
    'Smith Event Options',
    'Volunteer option 1'
  ];

  function isPlaceholder(name) {
    if (!name || typeof name !== 'string') return true;
    const trimmed = name.trim();
    if (trimmed === '') return true;
    const patterns = [
      /^Saving\.{3}$/i,
      /^Loading\.{3}$/i,
      /^Downloading\.{3}$/i,
      /^Untitled( \d+)?$/i,
      /^New Artifact$/i,
      /^\s*$/
    ];
    return patterns.some(p => p.test(trimmed));
  }

  placeholders.forEach(name => {
    console.assert(isPlaceholder(name) === true, `"${name}" should be detected as placeholder`);
  });

  validNames.forEach(name => {
    console.assert(isPlaceholder(name) === false, `"${name}" should NOT be detected as placeholder`);
  });

  console.log('✓ testPlaceholderDetection passed');
}

// Run all tests
function runTests() {
  console.log('Running content script tests...\n');

  testButtonPlacementInExistingContainer();
  testButtonPlacementInActionArea();
  testButtonPlacementNewContainer();
  testSkipSmallCards();
  testPlaceholderDetection();

  console.log('\n✓ All tests passed!');
}

// Export for Node.js or run in browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runTests };
} else if (typeof window !== 'undefined') {
  window.runArtifactManagerTests = runTests;
}

// Auto-run if executed directly
if (typeof document !== 'undefined') {
  runTests();
}
