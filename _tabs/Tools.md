---
title: Tools
layout: page
permalink: /tools/
icon: fas fa-tools
order: 2
---

##### Here is a list of my custom tools. Use the filter and sorting options to find what you need.
Check out my GitHub repository for a complete list of my public tools: [Github](https://github.com/cyb3rtr0nian)

<!-- Tools Listing Section -->
<div class="tools-container mb-4">
    <div class="row g-3 mb-3">
      <div class="col-md-8">
        <div class="input-group">
          <input 
            id="tools-filter" 
            type="search" 
            class="form-control" 
            placeholder="Filter tools by name, language or description..." 
            aria-label="Filter tools"
          >
          <button id="clear-filter" class="btn btn-outline-secondary" type="button" aria-label="Clear filter">
            <i class="fas fa-times"></i>
          </button>
        </div>
      </div>
      <div class="col-md-4">
        <div class="input-group">
          <label class="input-group-text" for="tools-sort">Sort by:</label>
          <select id="tools-sort" class="form-select" aria-label="Sort tools">
            <option value="name-asc">Name (A-Z)</option>
            <option value="name-desc">Name (Z-A)</option>
            <option value="language">Language</option>
            <option value="category">Category</option>
          </select>
        </div>
      </div>
  </div>

  <div id="tools-list" class="row g-3">
      <!-- Tools will be loaded here dynamically -->
  </div>

  <!-- Dynamic button -->
  <div class="d-flex justify-content-center align-items-center mt-4" style="height: 100px;">
    <button id="load-more" class="btn btn-primary" style="display: none;">
      Load More
    </button>
  </div>

</div>

<div aria-live="polite" id="filter-status" class="visually-hidden"></div>

<!-- JavaScript for tools functionality (unchanged) -->
<script>
  document.addEventListener('DOMContentLoaded', function() {
    // Sample tools data - in production this would come from an API or Jekyll data file
    const tools = [
      {
        id: 1,
        name: "Nmap",
        url: "https://nmap.org",
        language: "C++",
        category: "Network",
        description: "Network discovery and security auditing tool",
        icon: "fa-network-wired"
      },
      {
        id: 2,
        name: "MSFconsole",
        url: "https://www.metasploit.com",
        language: "Ruby",
        category: "Exploitation",
        description: "Penetration testing platform for developing and executing exploits",
        icon: "fa-bug"
      },
      {
        id: 3,
        name: "Burp Suite",
        url: "https://portswigger.net/burp",
        language: "Java",
        category: "Web",
        description: "Web application security testing platform",
        icon: "fa-globe"
      },
      {
        id: 4,
        name: "John the Ripper",
        url: "https://www.openwall.com/john",
        language: "C",
        category: "Password",
        description: "Password cracking tool",
        icon: "fa-key"
      },
      {
        id: 5,
        name: "Wireshark",
        url: "https://www.wireshark.org",
        language: "C++",
        category: "Network",
        description: "Network protocol analyzer",
        icon: "fa-network-wired"
      },
      {
        id: 6,
        name: "Hashcat",
        url: "https://hashcat.net/hashcat",
        language: "C++",
        category: "Password",
        description: "Advanced password recovery tool",
        icon: "fa-lock"
      },
      {
        id: 7,
        name: "SQLmap",
        url: "https://sqlmap.org",
        language: "Python",
        category: "Database",
        description: "Automatic SQL injection and database takeover tool",
        icon: "fa-database"
      },
      {
        id: 8,
        name: "Impacket",
        url: "https://github.com/SecureAuthCorp/impacket",
        language: "Python",
        category: "Network",
        description: "Collection of Python classes for working with network protocols",
        icon: "fa-code"
      }
    ];

    // DOM elements
    const toolsList = document.getElementById('tools-list');
    const filterInput = document.getElementById('tools-filter');
    const clearFilterBtn = document.getElementById('clear-filter');
    const sortSelect = document.getElementById('tools-sort');
    const loadMoreBtn = document.getElementById('load-more');
    const filterStatus = document.getElementById('filter-status');
    
    // State
    let visibleTools = 6;
    let filteredTools = [...tools];
    
    // Initialize
    renderTools();
    
    // Event listeners
    filterInput.addEventListener('input', handleFilter);
    clearFilterBtn.addEventListener('click', clearFilters);
    sortSelect.addEventListener('change', handleSort);
    loadMoreBtn.addEventListener('click', loadMoreTools);
    
    // Functions
    function renderTools(toolsToRender = filteredTools.slice(0, visibleTools)) {
      if (toolsToRender.length === 0) {
        toolsList.innerHTML = `
          <div class="col-12 no-tools-message">
            <div class="alert alert-info">
              <i class="fas fa-info-circle me-2"></i>
              No tools match your search criteria
            </div>
          </div>
        `;
        return;
      }
      
      toolsList.innerHTML = toolsToRender.map(tool => `
        <div class="col-md-6 col-lg-4 col-xl-3">
          <div class="card tool-card">
            <div class="card-body">
              <h5 class="card-title">
                <i class="fas ${tool.icon || 'fa-tools'} me-2"></i>
                <a href="${tool.url}" target="_blank" rel="noopener noreferrer">${tool.name}</a>
                ${tool.language ? `<span class="badge bg-secondary tool-badge ms-2">${tool.language}</span>` : ''}
              </h5>
              ${tool.category ? `<span class="badge bg-primary mb-2">${tool.category}</span>` : ''}
              <p class="card-text">${tool.description}</p>
            </div>
          </div>
        </div>
      `).join('');
      
      updateFilterStatus(toolsToRender.length, filteredTools.length);
    }
    
    function handleFilter() {
      const searchTerm = filterInput.value.toLowerCase();
      
      if (!searchTerm) {
        filteredTools = [...tools];
      } else {
        filteredTools = tools.filter(tool => 
          tool.name.toLowerCase().includes(searchTerm) ||
          (tool.language && tool.language.toLowerCase().includes(searchTerm)) ||
          (tool.category && tool.category.toLowerCase().includes(searchTerm)) ||
          tool.description.toLowerCase().includes(searchTerm)
        );
      }
      
      visibleTools = 6;
      handleSort();
    }
    
    function clearFilters() {
      filterInput.value = '';
      filteredTools = [...tools];
      visibleTools = 6;
      handleSort();
      filterInput.focus();
    }
    
    function handleSort() {
      const sortValue = sortSelect.value;
      
      filteredTools.sort((a, b) => {
        switch (sortValue) {
          case 'name-asc':
            return a.name.localeCompare(b.name);
          case 'name-desc':
            return b.name.localeCompare(a.name);
          case 'language':
            return (a.language || '').localeCompare(b.language || '');
          case 'category':
            return (a.category || '').localeCompare(b.category || '');
          default:
            return 0;
        }
      });
      
      renderTools();
    }
    
    function loadMoreTools() {
      visibleTools += 6;
      renderTools();
      
      if (visibleTools >= filteredTools.length) {
        loadMoreBtn.style.display = 'none';
      }
    }
    
    function updateFilterStatus(visibleCount, totalCount) {
      if (filterInput.value) {
        filterStatus.textContent = `${visibleCount} of ${totalCount} tools matching "${filterInput.value}"`;
      } else {
        filterStatus.textContent = `Showing ${visibleCount} of ${totalCount} tools`;
      }
      
      // Show/hide load more button
      loadMoreBtn.style.display = visibleCount < filteredTools.length ? 'block' : 'none';
    }
  });
</script>

<!-- Enhanced CSS for the tools listing -->
<style>
  .tools-container {
    margin-top: 1rem;
    padding: 0;
  }

  .tool-card {
    border: 1px solid var(--bs-border-color, rgba(0, 0, 0, 0.125));
    border-radius: 0.5rem;
    overflow: hidden;
    box-shadow: var(--bs-box-shadow-sm, 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075));
    height: 200px; /* Fixed height for compact, uniform cards */
    display: flex;
    flex-direction: column;
    background-color: var(--card-bg, #fff);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
  }

  .tool-card:hover {
    transform: translateY(-5px);
    box-shadow: var(--bs-box-shadow, 0 0.5rem 1rem rgba(0, 0, 0, 0.15));
    border-color: rgba(0, 0, 0, 0.2);
  }

  .tool-card .card-body {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    flex: 1 1 auto;
    overflow: hidden;
  }

  .tool-card .card-title {
    font-size: 1rem;
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    line-height: 1.3;
    color: var(--text-color, #212529);
  }

  .tool-card .card-title a {
    color: inherit;
    text-decoration: none;
    transition: color 0.2s;
  }

  .tool-card .card-title a:hover {
    color: var(--link-color, #0d6efd);
    text-decoration: underline;
  }

  .tool-card .card-title i {
    font-size: 0.9rem;
    color: var(--text-muted-color, #6c757d);
    margin-right: 0.5rem;
  }

  .tool-card .card-text {
    color: var(--text-muted-color, #6c757d);
    font-size: 0.85rem;
    margin-top: 0.25rem;
    overflow: hidden;
    text-overflow: ellipsis;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    flex: 1 1 auto;
  }

  .tool-badge {
    font-size: 0.65rem;
    font-weight: 500;
    padding: 0.25em 0.5em;
    margin-left: 0.5rem;
  }

  .badge.bg-primary {
    background-color: var(--bs-primary, #0d6efd) !important;
  }

  .badge.bg-secondary {
    background-color: var(--bs-secondary, #6c757d) !important;
  }

  #filter-status {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .no-tools-message {
    grid-column: 1 / -1;
    text-align: center;
    padding: 1.5rem;
  }

  /* Override Chirpy theme and Bootstrap conflicts */
  .content {
    margin-top: 0.5rem !important;
    font-size: 1rem !important;
    line-height: 1.5 !important;
  }

  #tools-list {
    margin-top: 0;
  }

  #tools-list > div {
    display: flex;
    flex-direction: column;
  }

  /* Responsive adjustments */
  @media (max-width: 767.98px) {
    .tool-card {
      height: 180px;
    }

    .tool-card .card-body {
      padding: 0.5rem;
    }

    .tool-card .card-title {
      font-size: 0.9rem;
    }

    .tool-card .card-text {
      font-size: 0.8rem;
      -webkit-line-clamp: 2;
    }

    .tool-badge {
      font-size: 0.6rem;
      padding: 0.2em 0.4em;
    }
  }
</style>
