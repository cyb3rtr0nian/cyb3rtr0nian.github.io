---
title: Tools
layout: page
permalink: /tools/
icon: fas fa-tools
order: 2
---

##### Here is a list of my custom tools. Use the filter and sorting options to find what you need.
Check out my GitHub repository for a complete list of my public tools: [GitHub](https://github.com/cyb3rtr0nian)

<!-- Tools Listing Section -->
<div class="tools-container mb-4">
    <div class="row g-3 mb-3">
      <div class="col-md-8">
        <div class="input-group">
        </div>
      </div>
      <div class="col-md-4">
        <div class="input-group">
        </div>
      </div>
    </div>

  <div id="tools-list" class="row g-3">
      {% if site.data.tools %}
        {% for tool in site.data.tools limit:6 %}
          <div class="col-md-6 col-lg-4 col-xl-3">
            <div class="card tool-card">
              <div class="card-body">
                <h5 class="card-title">
                  <i class="fas {{ tool.icon | default: 'fa-tools' }} me-2"></i>
                  <a href="{{ tool.url }}" target="_blank" rel="noopener noreferrer">{{ tool.name }}</a>
                  {% if tool.language %}
                    <span class="badge bg-secondary tool-badge ms-2">{{ tool.language }}</span>
                  {% endif %}
                </h5>
                {% if tool.category %}
                  <span class="badge bg-primary mb-2">{{ tool.category }}</span>
                {% endif %}
                <p class="card-text">{{ tool.description }}</p>
              </div>
            </div>
          </div>
        {% endfor %}
      {% else %}
        <div class="col-12 no-tools-message">
          <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle me-2"></i>
            No tools data found. Please check _data/tools.yml.
          </div>
        </div>
      {% endif %}
    </div>

  <!-- Dynamic button -->

<!-- JavaScript for tools functionality -->
<script>
  document.addEventListener('DOMContentLoaded', function() {
    // Load tools data from Jekyll data file
    const tools = {{ site.data.tools | jsonify | default: '[]' }};

    // DOM elements
    
    // State
    
    // Initialize
    if (tools.length > 0) {
      renderTools();
    } else {
      toolsList.innerHTML = `
        <div class="col-12 no-tools-message">
          <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle me-2"></i>
            Failed to load tools data. Please check the console for errors.
          </div>
        </div>
      `;
    }
    
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
          (tool.name && tool.name.toLowerCase().includes(searchTerm)) ||
          (tool.language && tool.language.toLowerCase().includes(searchTerm)) ||
          (tool.category && tool.category.toLowerCase().includes(searchTerm)) ||
          (tool.description && tool.description.toLowerCase().includes(searchTerm))
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
    min-height: 200px; /* Minimum height for uniformity */
    height: 100%; /* Stretch to match row height */
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
    padding: 1rem; /* Increased padding for better spacing */
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
    flex-wrap: nowrap; /* Prevent wrapping in title for better uniformity */
    line-height: 1.3;
    color: var(--text-color, #212529);
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .tool-card .card-title a {
    color: inherit;
    text-decoration: none;
    transition: color 0.2s;
    overflow: hidden;
    text-overflow: ellipsis;
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

  /* Fix for clear-filter button alignment */
  .input-group {
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
  }

  .input-group > .form-control {
    flex: 1 1 auto;
    min-width: 0;
  }

  .input-group > .btn {
    flex: 0 0 auto;
    white-space: nowrap;
  }

  /* Responsive adjustments */
  @media (max-width: 767.98px) {
    .tool-card {
      min-height: 180px;
    }

    .tool-card .card-body {
      padding: 0.75rem;
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

    .input-group {
      flex-wrap: nowrap;
      display: flex;
      align-items: center;
    }

    .input-group > .form-control {
      flex: 1 1 auto;
      min-width: 0;
    }

    .input-group > .btn {
      flex: 0 0 auto;
      white-space: nowrap;
    }
  }
</style>