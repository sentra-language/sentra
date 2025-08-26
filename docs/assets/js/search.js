// Sentra Documentation Search
(function() {
  'use strict';

  // Search index (in production, this would be generated from all docs)
  const searchIndex = [
    // Tutorial
    { title: 'Introduction to Sentra', url: '/tutorial/introduction/', content: 'Welcome to Sentra programming language tutorial security-focused defensive operations', category: 'Tutorial' },
    { title: 'Installation', url: '/tutorial/installation/', content: 'Install Sentra Windows macOS Linux build from source quick install package managers', category: 'Tutorial' },
    { title: 'Your First Program', url: '/tutorial/first-program/', content: 'Hello World first Sentra program variables functions log output', category: 'Tutorial' },
    { title: 'Data Types', url: '/tutorial/data-types/', content: 'Numbers strings booleans arrays maps null data types variables', category: 'Tutorial' },
    
    // Library Reference
    { title: 'Built-in Functions', url: '/library/builtin/', content: 'log str int float bool type len global functions conversions', category: 'Library' },
    { title: 'Math Module', url: '/library/math/', content: 'math PI E sin cos tan sqrt pow abs random trigonometry', category: 'Library' },
    { title: 'Security Module', url: '/library/security/', content: 'security sha256 encrypt decrypt hash_password vulnerability scanning cryptography', category: 'Library' },
    { title: 'Network Module', url: '/library/network/', content: 'network scan_ports tcp udp http port scanning network analysis', category: 'Library' },
    { title: 'Database Module', url: '/library/database/', content: 'database sql query connect security operations injection prevention', category: 'Library' },
    
    // Language Reference
    { title: 'Lexical Analysis', url: '/reference/lexical/', content: 'tokens comments identifiers keywords literals operators lexical', category: 'Reference' },
    { title: 'Data Model', url: '/reference/datamodel/', content: 'objects types numbers strings arrays maps functions null data model', category: 'Reference' },
    { title: 'Expressions', url: '/reference/expressions/', content: 'arithmetic comparison logical function calls indexing lambda expressions', category: 'Reference' },
    { title: 'Statements', url: '/reference/statements/', content: 'simple assignment control flow loops functions import statements', category: 'Reference' },
    
    // How-to Guides
    { title: 'Building a Port Scanner', url: '/guide/port-scanner/', content: 'port scanner network reconnaissance security tool TCP UDP scanning', category: 'Guide' },
    { title: 'Creating a REST API', url: '/guide/rest-api/', content: 'REST API HTTP web service JSON endpoints routing middleware', category: 'Guide' },
    { title: 'Security Scanner', url: '/guide/security-scanner/', content: 'vulnerability scanner security assessment automated testing compliance', category: 'Guide' },
    { title: 'Database Security', url: '/guide/db-security/', content: 'database security SQL injection prevention parameterized queries encryption', category: 'Guide' },
    
    // Installation
    { title: 'Windows Installation', url: '/installing/windows/', content: 'Windows 10 11 PowerShell installer download setup PATH environment', category: 'Install' },
    { title: 'macOS Installation', url: '/installing/macos/', content: 'macOS Homebrew brew install Terminal command line Xcode', category: 'Install' },
    { title: 'Linux Installation', url: '/installing/linux/', content: 'Linux Ubuntu Debian Fedora apt yum snap package manager', category: 'Install' },
    { title: 'Build from Source', url: '/installing/source/', content: 'source code Go build compile git clone make development', category: 'Install' },
  ];

  // Search configuration
  const MIN_QUERY_LENGTH = 2;
  const MAX_RESULTS = 20;
  const DEBOUNCE_DELAY = 300;

  // DOM elements
  let searchInput;
  let searchButton;
  let searchResults;
  let searchTimeout;

  // Initialize search when DOM is ready
  document.addEventListener('DOMContentLoaded', function() {
    searchInput = document.getElementById('search-input');
    searchButton = document.getElementById('search-button');
    searchResults = document.getElementById('search-results');

    if (searchInput && searchResults) {
      // Add event listeners
      searchInput.addEventListener('input', handleSearchInput);
      searchInput.addEventListener('keypress', handleKeyPress);
      
      if (searchButton) {
        searchButton.addEventListener('click', performSearch);
      }

      // Handle search from URL parameter
      const urlParams = new URLSearchParams(window.location.search);
      const query = urlParams.get('q');
      if (query) {
        searchInput.value = query;
        performSearch();
      }
    }

    // Add global search shortcut (Ctrl+K or Cmd+K)
    document.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }
    });
  });

  // Handle search input with debouncing
  function handleSearchInput() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(performSearch, DEBOUNCE_DELAY);
  }

  // Handle Enter key
  function handleKeyPress(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      clearTimeout(searchTimeout);
      performSearch();
    }
  }

  // Perform the search
  function performSearch() {
    const query = searchInput.value.trim().toLowerCase();
    
    if (query.length < MIN_QUERY_LENGTH) {
      clearResults();
      return;
    }

    const results = searchDocuments(query);
    displayResults(results, query);
  }

  // Search through documents
  function searchDocuments(query) {
    const terms = query.split(/\s+/);
    const results = [];

    for (const doc of searchIndex) {
      let score = 0;
      const titleLower = doc.title.toLowerCase();
      const contentLower = doc.content.toLowerCase();

      for (const term of terms) {
        // Exact title match gets highest score
        if (titleLower === term) {
          score += 100;
        }
        // Title contains term
        else if (titleLower.includes(term)) {
          score += 50;
        }
        // Title word starts with term
        else if (titleLower.split(/\s+/).some(word => word.startsWith(term))) {
          score += 30;
        }
        // Content contains term
        if (contentLower.includes(term)) {
          score += 10;
        }
        // URL contains term
        if (doc.url.toLowerCase().includes(term)) {
          score += 5;
        }
      }

      if (score > 0) {
        results.push({ ...doc, score });
      }
    }

    // Sort by score (highest first) and limit results
    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, MAX_RESULTS);
  }

  // Display search results
  function displayResults(results, query) {
    if (!searchResults) return;

    if (results.length === 0) {
      searchResults.innerHTML = `
        <div class="search-no-results">
          <p>No results found for "<strong>${escapeHtml(query)}</strong>"</p>
          <p>Try different keywords or check the <a href="/reference/">reference documentation</a>.</p>
        </div>
      `;
      return;
    }

    const html = `
      <div class="search-results-header">
        <strong>${results.length} result${results.length !== 1 ? 's' : ''}</strong> for "<strong>${escapeHtml(query)}</strong>"
      </div>
      <div class="search-results-list">
        ${results.map(result => `
          <div class="search-result-item">
            <div class="search-result-category">${result.category}</div>
            <h4><a href="${result.url}">${highlightTerms(result.title, query)}</a></h4>
            <p>${highlightTerms(truncateContent(result.content), query)}</p>
            <div class="search-result-url">${result.url}</div>
          </div>
        `).join('')}
      </div>
    `;

    searchResults.innerHTML = html;
  }

  // Clear search results
  function clearResults() {
    if (searchResults) {
      searchResults.innerHTML = '';
    }
  }

  // Highlight search terms in text
  function highlightTerms(text, query) {
    const terms = query.split(/\s+/);
    let highlighted = text;

    for (const term of terms) {
      const regex = new RegExp(`(${escapeRegex(term)})`, 'gi');
      highlighted = highlighted.replace(regex, '<mark>$1</mark>');
    }

    return highlighted;
  }

  // Truncate content for display
  function truncateContent(content, maxLength = 150) {
    if (content.length <= maxLength) return content;
    return content.substring(0, maxLength) + '...';
  }

  // Escape HTML special characters
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Escape regex special characters
  function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Export for use in other scripts
  window.SentraSearch = {
    search: performSearch,
    clear: clearResults
  };
})();