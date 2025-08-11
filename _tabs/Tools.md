---
title: Tools
layout: page
permalink: /tools/
icon: fas fa-tools
order: 2
---

# Tools

Here is the list of my custom tools. Use the filter and sorting options to find what you need.

<div id="tools-list"></div>

<!-- Filter and sort controls -->
<div class="controls-container">
  <div class="filter-container">
    <input id="filter-input" type="search" placeholder="Filter tools..." aria-label="Filter tools" />
    <button id="clear-filter" aria-label="Clear filter">&times;</button>
  </div>
  <div class="sort-container">
    <label for="sort-tools">Sort by:</label>
    <select id="sort-tools">
      <option value="name-asc">Name (A-Z)</option>
      <option value="name-desc">Name (Z-A)</option>
      <option value="language">Language</option>
    </select>
  </div>
</div>

<div id="tools-list">
  {% for tool in site.data.tools %}
    <div class="tool-card" tabindex="0" role="article" aria-labelledby="tool-{{ forloop.index }}">
      <h3 id="tool-{{ forloop.index }}">
        <a href="{{ tool.url }}" target="_blank">{{ tool.name }}</a>
        {% if tool.language %}
          <span class="language-badge">{{ tool.language }}</span>
        {% endif %}
      </h3>
      <p class="tool-description">{{ tool.description | escape }}</p>
    </div>
  {% endfor %}
</div>

<!--
<div id="load-more">Loading more tools...</div>
-->

<div aria-live="polite" id="filter-status" class="visually-hidden"></div>

<script>
// Paste your filtering, sorting, infinite scroll JS here (from your example or previous code)
</script>
