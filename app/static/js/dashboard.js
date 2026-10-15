/**
 * Dashboard & Diagnostic Scripts
 * Stage 2: Splunk REST Connectivity & Live Windows Security Event Ingestion
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const btnTestSplunk = document.getElementById("btn-test-splunk");
  const diagnosticBox = document.getElementById("connection-output");
  const statusBadge = document.getElementById("splunk-status-badge");
  const latencyBadge = document.getElementById("splunk-latency-badge");

  const btnFetchLogs = document.getElementById("btn-fetch-logs");
  const selectEventId = document.getElementById("filter-event-id");
  const selectTimeRange = document.getElementById("filter-time-range");
  const selectLimit = document.getElementById("filter-limit");

  const eventsTbody = document.getElementById("events-tbody");
  const eventCountNum = document.getElementById("event-count-num");
  const queryLatencyDisplay = document.getElementById("query-latency-display");
  const dataSourceBadge = document.getElementById("data-source-badge");
  const splQueryBox = document.getElementById("spl-query-box");
  const queryErrorBox = document.getElementById("query-error-box");
  const btnToggleSpl = document.getElementById("btn-toggle-spl");

  // Modal elements
  const modalOverlay = document.getElementById("log-detail-modal");
  const modalTitle = document.getElementById("modal-title");
  const modalRawContent = document.getElementById("modal-raw-content");
  const modalCloseBtn = document.getElementById("modal-close-btn");

  // ------------------------------------------------------------------------
  // 1. Splunk Connection Test Handler
  // ------------------------------------------------------------------------
  if (btnTestSplunk) {
    btnTestSplunk.addEventListener("click", async () => {
      btnTestSplunk.disabled = true;
      const originalText = btnTestSplunk.innerHTML;
      btnTestSplunk.innerHTML = `<span>⏳ Testing Connection...</span>`;

      if (diagnosticBox) {
        diagnosticBox.style.display = "block";
        diagnosticBox.textContent = "[...] Querying Splunk REST API (/services/server/info) at management port 8089...";
        diagnosticBox.style.borderColor = "var(--border-subtle)";
      }

      try {
        const response = await fetch("/api/splunk/test-connection", {
          method: "GET",
          headers: { "Accept": "application/json" }
        });

        const data = await response.json();
        if (diagnosticBox) {
          diagnosticBox.textContent = JSON.stringify(data, null, 2);
        }

        if (data.connected) {
          if (statusBadge) {
            statusBadge.className = "status-pill success";
            statusBadge.innerHTML = `<span class="badge-pulse" style="background:#10b981;"></span> Connected`;
          }
          if (latencyBadge) {
            latencyBadge.textContent = `${data.latency_ms} ms`;
          }
          if (diagnosticBox) {
            diagnosticBox.style.borderColor = "var(--cyber-green)";
          }
        } else {
          if (statusBadge) {
            statusBadge.className = "status-pill warning";
            statusBadge.innerHTML = `<span class="badge-pulse" style="background:#f59e0b;"></span> ${data.status || 'Failed'}`;
          }
          if (latencyBadge) {
            latencyBadge.textContent = "Offline / Error";
          }
          if (diagnosticBox) {
            diagnosticBox.style.borderColor = "var(--cyber-amber)";
          }
        }
      } catch (err) {
        if (diagnosticBox) {
          diagnosticBox.textContent = `[!] Network Error: Unable to reach /api/splunk/test-connection.\nDetails: ${err.message}`;
          diagnosticBox.style.borderColor = "var(--cyber-red)";
        }
        if (statusBadge) {
          statusBadge.className = "status-pill danger";
          statusBadge.innerHTML = `<span class="badge-pulse" style="background:#ef4444;"></span> App Error`;
        }
      } finally {
        btnTestSplunk.disabled = false;
        btnTestSplunk.innerHTML = originalText;
      }
    });
  }

  // ------------------------------------------------------------------------
  // 2. Fetch Windows Security Logs from Splunk Handler
  // ------------------------------------------------------------------------
  if (btnFetchLogs) {
    btnFetchLogs.addEventListener("click", async () => {
      const eventId = selectEventId ? selectEventId.value : "all";
      const timeRange = selectTimeRange ? selectTimeRange.value : "-24h";
      const limit = selectLimit ? selectLimit.value : "50";

      // UI Loading state
      btnFetchLogs.disabled = true;
      const originalBtnText = btnFetchLogs.innerHTML;
      btnFetchLogs.innerHTML = `<span>⏳ Querying Splunk...</span>`;

      if (queryErrorBox) {
        queryErrorBox.style.display = "none";
        queryErrorBox.textContent = "";
      }

      try {
        const queryUrl = `/api/splunk/query-windows-logs?event_id=${encodeURIComponent(eventId)}&time_range=${encodeURIComponent(timeRange)}&limit=${encodeURIComponent(limit)}`;
        const response = await fetch(queryUrl, {
          method: "GET",
          headers: { "Accept": "application/json" }
        });

        const data = await response.json();

        // Update latency display
        if (queryLatencyDisplay && data.execution_time_ms !== undefined && data.execution_time_ms !== null) {
          queryLatencyDisplay.textContent = `Latency: ${data.execution_time_ms} ms`;
        }

        // Update SPL query display
        if (splQueryBox && data.spl_query) {
          splQueryBox.textContent = `[Splunk SPL Dispatched]:\n${data.spl_query}`;
        }

        // Update mode badges
        if (dataSourceBadge) {
          if (data.mode === "DEMO") {
            dataSourceBadge.className = "status-pill warning";
            dataSourceBadge.innerHTML = `⚠️ DEMO MODE: Simulated Events Only`;
          } else {
            dataSourceBadge.className = "status-pill success";
            dataSourceBadge.innerHTML = `🟢 LIVE SPLUNK ENTERPRISE DATA`;
          }
        }

        if (data.success) {
          // Render retrieved events
          const events = data.events || [];
          if (eventCountNum) {
            eventCountNum.textContent = events.length;
          }
          renderEventRows(events);
          fetchAndReconstructTimeline(currentOrder === "desc");
          fetchAndUpdateSummary();
          updatePdfExportLink();
        } else {
          // Query or connection error - display authentic diagnostic error
          if (queryErrorBox) {
            queryErrorBox.style.display = "block";
            queryErrorBox.textContent = `[!] Splunk Query Error: ${data.error || 'Failed to retrieve logs from Splunk Enterprise.'}`;
          }
          if (eventCountNum) {
            eventCountNum.textContent = "0";
          }
          renderEmptyState(data.error || "Splunk query returned an error.");
        }
      } catch (err) {
        if (queryErrorBox) {
          queryErrorBox.style.display = "block";
          queryErrorBox.textContent = `[!] Network Communication Error: ${err.message}`;
        }
        renderEmptyState("Network communication error with Flask server.");
      } finally {
        btnFetchLogs.disabled = false;
        btnFetchLogs.innerHTML = originalBtnText;
      }
    });
  }

  // ------------------------------------------------------------------------
  // 3. Render Event Table Rows (XSS Safe)
  // ------------------------------------------------------------------------
  function renderEventRows(events) {
    if (!eventsTbody) return;
    eventsTbody.innerHTML = "";

    if (events.length === 0) {
      renderEmptyState("No matching Windows Security events found in Splunk index for this time range.");
      return;
    }

    events.forEach((ev) => {
      const tr = document.createElement("tr");

      // Timestamp
      const tdTime = document.createElement("td");
      tdTime.className = "cyber-mono";
      tdTime.textContent = ev.timestamp || "N/A";
      tr.appendChild(tdTime);

      // Event ID & Name
      const tdEvent = document.createElement("td");
      const eventCodePill = document.createElement("span");
      eventCodePill.className = `tag-event-code tag-${ev.event_id || 'default'}`;
      eventCodePill.textContent = ev.event_id || "Unknown";
      tdEvent.appendChild(eventCodePill);

      const eventNameDiv = document.createElement("div");
      eventNameDiv.style.fontSize = "0.76rem";
      eventNameDiv.style.color = "var(--text-muted)";
      eventNameDiv.style.marginTop = "2px";
      eventNameDiv.textContent = ev.event_name || "";
      tdEvent.appendChild(eventNameDiv);
      tr.appendChild(tdEvent);

      // User Account
      const tdUser = document.createElement("td");
      const userStrong = document.createElement("strong");
      userStrong.style.color = "#ffffff";
      userStrong.textContent = ev.username || "N/A";
      tdUser.appendChild(userStrong);
      tr.appendChild(tdUser);

      // Source IP / Host
      const tdSrc = document.createElement("td");
      tdSrc.className = "cyber-mono";
      tdSrc.style.fontSize = "0.8rem";
      tdSrc.textContent = ev.source_ip || "-";
      tr.appendChild(tdSrc);

      // Target Computer
      const tdDest = document.createElement("td");
      tdDest.className = "cyber-mono";
      tdDest.style.fontSize = "0.8rem";
      tdDest.style.color = "var(--text-muted)";
      tdDest.textContent = ev.computer_name || "-";
      tr.appendChild(tdDest);

      // Logon Type / MITRE
      const tdLogon = document.createElement("td");
      const mitreSpan = document.createElement("span");
      mitreSpan.className = "tag-mitre";
      mitreSpan.textContent = ev.mitre_technique || "Unclassified";
      tdLogon.appendChild(mitreSpan);

      const logonDiv = document.createElement("div");
      logonDiv.style.fontSize = "0.72rem";
      logonDiv.style.color = "var(--text-dim)";
      logonDiv.style.marginTop = "3px";
      logonDiv.textContent = ev.logon_type || "";
      tdLogon.appendChild(logonDiv);
      tr.appendChild(tdLogon);

      // Forensic Narrative
      const tdMsg = document.createElement("td");
      tdMsg.style.fontSize = "0.82rem";
      tdMsg.style.color = "var(--text-muted)";
      tdMsg.style.maxWidth = "320px";
      tdMsg.textContent = ev.message || "";
      tr.appendChild(tdMsg);

      // Action: Inspect
      const tdAction = document.createElement("td");
      const inspectBtn = document.createElement("button");
      inspectBtn.className = "btn btn-cyber-outline btn-sm btn-inspect-log";
      inspectBtn.textContent = "Inspect";
      inspectBtn.addEventListener("click", () => {
        openLogModal(
          `Event ${ev.event_id} - ${ev.event_name}`,
          ev.raw_snippet || JSON.stringify(ev, null, 2)
        );
      });
      tdAction.appendChild(inspectBtn);
      tr.appendChild(tdAction);

      eventsTbody.appendChild(tr);
    });
  }

  function renderEmptyState(message) {
    if (!eventsTbody) return;
    eventsTbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
          <div style="font-size: 2.2rem; margin-bottom: 0.8rem;">🔍</div>
          <h3 style="color: #ffffff; margin-bottom: 0.5rem;">No Events Found</h3>
          <p style="max-width: 550px; margin: 0 auto; font-size: 0.88rem;">
            ${message}
          </p>
        </td>
      </tr>
    `;
  }

  // ------------------------------------------------------------------------
  // 4. Modal Handlers
  // ------------------------------------------------------------------------
  function openLogModal(title, content) {
    if (modalTitle) modalTitle.textContent = title;
    if (modalRawContent) modalRawContent.textContent = content;
    if (modalOverlay) modalOverlay.style.display = "flex";
  }

  function closeLogModal() {
    if (modalOverlay) modalOverlay.style.display = "none";
  }

  if (modalCloseBtn) {
    modalCloseBtn.addEventListener("click", closeLogModal);
  }

  if (modalOverlay) {
    modalOverlay.addEventListener("click", (e) => {
      if (e.target === modalOverlay) {
        closeLogModal();
      }
    });
  }

  // Initial event handlers for static demo rows
  document.querySelectorAll(".btn-inspect-log").forEach((btn) => {
    btn.addEventListener("click", () => {
      const raw = btn.getAttribute("data-raw") || "No raw text available";
      const title = btn.getAttribute("data-title") || "Event Detail";
      openLogModal(title, raw);
    });
  });

  // ------------------------------------------------------------------------
  // 5. Toggle SPL Display
  // ------------------------------------------------------------------------
  if (btnToggleSpl && splQueryBox) {
    btnToggleSpl.addEventListener("click", () => {
      if (splQueryBox.style.display === "block") {
        splQueryBox.style.display = "none";
        btnToggleSpl.innerHTML = `<span>Show Generated SPL</span>`;
      } else {
        splQueryBox.style.display = "block";
        btnToggleSpl.innerHTML = `<span>Hide Generated SPL</span>`;
      }
    });
  }

  // ------------------------------------------------------------------------
  // 6. Stage 3: Attack Timeline Reconstruction
  // ------------------------------------------------------------------------
  const btnReconstructTimeline = document.getElementById("btn-reconstruct-timeline");
  const timelineTrackContainer = document.getElementById("timeline-track-container");
  const metricThreatLevel = document.getElementById("metric-threat-level");
  const metricThreatActors = document.getElementById("metric-threat-actors");
  const metricTargetedAccounts = document.getElementById("metric-targeted-accounts");
  const metricStepCount = document.getElementById("metric-step-count");
  const cardMetricThreat = document.getElementById("card-metric-threat");
  const timelineOrderTabs = document.getElementById("timeline-order-tabs");
  const timelineFilterTabs = document.getElementById("timeline-filter-tabs");

  let currentTimelineItems = [];
  let currentOrder = "asc";
  let currentSuspicionFilter = "all";

  async function fetchAndReconstructTimeline(reverse = false) {
    if (!btnReconstructTimeline) return;
    
    btnReconstructTimeline.disabled = true;
    const originalText = btnReconstructTimeline.innerHTML;
    btnReconstructTimeline.innerHTML = `<span>⏳ Correlating Events...</span>`;

    const eventId = selectEventId ? selectEventId.value : "all";
    const timeRange = selectTimeRange ? selectTimeRange.value : "-24h";
    const limit = selectLimit ? selectLimit.value : "50";

    try {
      const url = `/api/timeline/reconstruct?event_id=${encodeURIComponent(eventId)}&time_range=${encodeURIComponent(timeRange)}&limit=${encodeURIComponent(limit)}&reverse=${reverse}`;
      const response = await fetch(url, {
        method: "GET",
        headers: { "Accept": "application/json" }
      });

      const data = await response.json();
      if (data.success) {
        currentTimelineItems = data.timeline || [];
        updateTimelineMetrics(data.summary, data.count);
        renderTimelineTrack();
      }
    } catch (err) {
      console.error("Error reconstructing timeline:", err);
    } finally {
      btnReconstructTimeline.disabled = false;
      btnReconstructTimeline.innerHTML = originalText;
    }
  }

  function updateTimelineMetrics(summary, count) {
    if (!summary) return;

    if (metricThreatLevel) {
      metricThreatLevel.textContent = summary.threat_level || "Unknown";
    }
    if (cardMetricThreat) {
      cardMetricThreat.className = "timeline-metric-card";
      if (summary.threat_level && summary.threat_level.includes("Critical")) {
        cardMetricThreat.classList.add("critical");
      } else if (summary.threat_level && (summary.threat_level.includes("High") || summary.threat_level.includes("Suspicious"))) {
        cardMetricThreat.classList.add("warning");
      } else {
        cardMetricThreat.classList.add("success");
      }
    }
    if (metricThreatActors) {
      metricThreatActors.textContent = summary.unique_actors && summary.unique_actors.length > 0 
        ? summary.unique_actors.join(", ") 
        : "None Isolated";
    }
    if (metricTargetedAccounts) {
      metricTargetedAccounts.textContent = summary.targeted_accounts && summary.targeted_accounts.length > 0
        ? summary.targeted_accounts.join(", ")
        : "None";
    }
    if (metricStepCount) {
      metricStepCount.textContent = `${count || 0} Steps`;
    }
  }

  function renderTimelineTrack() {
    if (!timelineTrackContainer) return;

    let itemsToRender = [...currentTimelineItems];

    // Apply suspicion filter
    if (currentSuspicionFilter === "threats") {
      itemsToRender = itemsToRender.filter(item => item.suspicion_level !== "Informational / Baseline");
    } else if (currentSuspicionFilter === "baseline") {
      itemsToRender = itemsToRender.filter(item => item.suspicion_level === "Informational / Baseline");
    }

    if (itemsToRender.length === 0) {
      timelineTrackContainer.innerHTML = `
        <div style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
          <div style="font-size: 2.2rem; margin-bottom: 0.8rem;">🔍</div>
          <h3 style="color: #ffffff; margin-bottom: 0.5rem;">No Steps Match Filter</h3>
          <p style="max-width: 500px; margin: 0 auto; font-size: 0.88rem;">
            No timeline steps match the current suspicion filter. Try selecting "All Steps" above.
          </p>
        </div>
      `;
      return;
    }

    timelineTrackContainer.innerHTML = "";

    itemsToRender.forEach((item, idx) => {
      const stepDiv = document.createElement("div");
      
      let stepClass = "baseline";
      let pillClass = "baseline";
      let hypoClass = "baseline";

      if (item.suspicion_level === "Critical") {
        stepClass = "critical";
        pillClass = "critical";
        hypoClass = "critical";
      } else if (item.suspicion_level === "High") {
        stepClass = "high";
        pillClass = "high";
      } else if (item.suspicion_level === "Suspicious") {
        stepClass = "high";
        pillClass = "suspicious";
      }

      stepDiv.className = `timeline-step ${stepClass}`;
      stepDiv.setAttribute("data-suspicion", item.suspicion_level);

      const nodeDiv = document.createElement("div");
      nodeDiv.className = "timeline-node";
      nodeDiv.textContent = item.display_index || (idx + 1);
      stepDiv.appendChild(nodeDiv);

      const cardDiv = document.createElement("div");
      cardDiv.className = "timeline-card";

      // Card Header
      const headerDiv = document.createElement("div");
      headerDiv.className = "timeline-card-header";
      headerDiv.innerHTML = `
        <div class="timeline-tags-left">
          <span class="cyber-mono" style="font-size: 0.84rem; color: #ffffff; font-weight: 600;">
            ${escapeHtml(item.timestamp)}
          </span>
          <span class="tag-event-code tag-${escapeHtml(item.event_id)}">${escapeHtml(item.event_id)}</span>
          <span style="font-size: 0.82rem; font-weight: 600; color: #ffffff;">${escapeHtml(item.event_name)}</span>
          <span class="tag-mitre">${escapeHtml(item.kill_chain_phase)}</span>
        </div>
        <div>
          <span class="pill-level ${pillClass}">${escapeHtml(item.suspicion_level)}</span>
        </div>
      `;
      cardDiv.appendChild(headerDiv);

      // Actor Flow Pill
      const actorFlowDiv = document.createElement("div");
      actorFlowDiv.className = "actor-flow-pill";
      actorFlowDiv.innerHTML = `
        <span style="color: var(--text-muted);">Source / Actor:</span>
        <strong style="color: var(--cyber-cyan);">${escapeHtml(item.actor)}</strong>
        <span class="flow-arrow">&rarr;</span>
        <span style="color: var(--text-muted);">Target:</span>
        <strong style="color: #ffffff;">${escapeHtml(item.target_user)}</strong>
        <span style="color: var(--text-dim);">@ ${escapeHtml(item.target_host)}</span>
      `;
      cardDiv.appendChild(actorFlowDiv);

      // Forensic Split Blocks
      const forensicGrid = document.createElement("div");
      forensicGrid.className = "forensic-blocks-grid";
      forensicGrid.innerHTML = `
        <div class="forensic-block block-confirmed">
          <div class="forensic-block-title">
            <span>🛡️ Confirmed Forensic Evidence (Log Truth)</span>
          </div>
          <p>${escapeHtml(item.confirmed_facts)}</p>
        </div>
        <div class="forensic-block block-hypothesis ${hypoClass}">
          <div class="forensic-block-title">
            <span>🔍 Correlation Rationale &amp; Threat Hypothesis</span>
          </div>
          <p>${escapeHtml(item.correlation_reason)}</p>
        </div>
      `;
      cardDiv.appendChild(forensicGrid);

      // Guidance Checklist
      if (item.investigation_guidance) {
        const guidanceDiv = document.createElement("div");
        guidanceDiv.className = "investigation-guidance-box";
        guidanceDiv.innerHTML = `
          <div class="guidance-header">
            <span>📋 Investigator Action Guidance</span>
          </div>
          <div class="guidance-content">${escapeHtml(item.investigation_guidance)}</div>
        `;
        cardDiv.appendChild(guidanceDiv);
      }

      stepDiv.appendChild(cardDiv);
      timelineTrackContainer.appendChild(stepDiv);
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Attach Timeline Reconstruct button listener
  if (btnReconstructTimeline) {
    btnReconstructTimeline.addEventListener("click", () => {
      fetchAndReconstructTimeline(currentOrder === "desc");
      fetchAndUpdateSummary();
      updatePdfExportLink();
    });
  }

  // Order Tabs listener
  if (timelineOrderTabs) {
    timelineOrderTabs.querySelectorAll(".btn-tab").forEach(tab => {
      tab.addEventListener("click", () => {
        timelineOrderTabs.querySelectorAll(".btn-tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        currentOrder = tab.getAttribute("data-order") || "asc";
        
        // Reverse current array and re-index
        if (currentTimelineItems.length > 0) {
          currentTimelineItems.reverse();
          currentTimelineItems.forEach((item, i) => {
            item.display_index = i + 1;
          });
          renderTimelineTrack();
        } else {
          fetchAndReconstructTimeline(currentOrder === "desc");
        }
      });
    });
  }

  // Filter Tabs listener
  if (timelineFilterTabs) {
    timelineFilterTabs.querySelectorAll(".btn-tab").forEach(tab => {
      tab.addEventListener("click", () => {
        timelineFilterTabs.querySelectorAll(".btn-tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        currentSuspicionFilter = tab.getAttribute("data-filter") || "all";
        renderTimelineTrack();
      });
    });
  }

  // ------------------------------------------------------------------------
  // 7. Stage 4: Dynamic PDF Export & Investigation Summary Sync
  // ------------------------------------------------------------------------
  function updatePdfExportLink() {
    const btnExportPdf = document.getElementById("btn-export-pdf");
    if (!btnExportPdf) return;
    const eventId = selectEventId ? selectEventId.value : "all";
    const timeRange = selectTimeRange ? selectTimeRange.value : "-24h";
    const limit = selectLimit ? selectLimit.value : "50";
    btnExportPdf.href = `/api/report/export-pdf?event_id=${encodeURIComponent(eventId)}&time_range=${encodeURIComponent(timeRange)}&limit=${encodeURIComponent(limit)}`;
  }

  async function fetchAndUpdateSummary() {
    const execText = document.getElementById("summary-exec-text");
    const findingsCount = document.getElementById("summary-findings-count");
    const findingsList = document.getElementById("summary-findings-list");
    const recsList = document.getElementById("summary-recs-list");
    if (!execText) return;

    const eventId = selectEventId ? selectEventId.value : "all";
    const timeRange = selectTimeRange ? selectTimeRange.value : "-24h";
    const limit = selectLimit ? selectLimit.value : "50";

    try {
      const url = `/api/report/summary?event_id=${encodeURIComponent(eventId)}&time_range=${encodeURIComponent(timeRange)}&limit=${encodeURIComponent(limit)}`;
      const response = await fetch(url, {
        headers: { "Accept": "application/json" }
      });
      const data = await response.json();
      if (data.success && data.summary) {
        const s = data.summary;
        if (execText) execText.textContent = s.executive_summary || "No events analyzed.";
        if (findingsCount) findingsCount.textContent = `${(s.key_findings || []).length} Suspicious Steps`;
        
        if (findingsList) {
          if (!s.key_findings || s.key_findings.length === 0) {
            findingsList.innerHTML = `<p style="color: var(--text-muted);">No suspicious attack sequences detected in current filtered events.</p>`;
          } else {
            findingsList.innerHTML = s.key_findings.map(f => `
              <div style="padding: 0.6rem 0.8rem; background: rgba(0,0,0,0.25); border-left: 3px solid ${f.suspicion === 'Critical' ? 'var(--cyber-red)' : 'var(--cyber-amber)'}; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.2rem;">
                  <span class="cyber-mono" style="font-size: 0.75rem; color: var(--text-muted);">Step ${escapeHtml(f.step)} &bull; ${escapeHtml(f.timestamp)}</span>
                  <span class="pill-level ${f.suspicion === 'Critical' ? 'critical' : 'high'}" style="font-size: 0.68rem; padding: 0.1rem 0.4rem;">${escapeHtml(f.suspicion)}</span>
                </div>
                <strong style="color: #ffffff;">${escapeHtml(f.event_id)} - ${escapeHtml(f.event_name)}</strong>
                <p style="color: var(--text-muted); font-size: 0.8rem; margin-top: 3px;">${escapeHtml(f.description)}</p>
              </div>
            `).join("");
          }
        }

        if (recsList) {
          if (!s.recommendations || s.recommendations.length === 0) {
            recsList.innerHTML = `<p style="color: var(--text-muted);">No remediation actions required for baseline operations.</p>`;
          } else {
            recsList.innerHTML = s.recommendations.map(r => `
              <div style="padding: 0.6rem 0.8rem; background: rgba(0,0,0,0.25); border-left: 3px solid var(--cyber-green); border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.2rem;">
                  <strong style="color: var(--cyber-green);">${escapeHtml(r.action)}</strong>
                  <span class="status-pill danger" style="font-size: 0.66rem; padding: 0.1rem 0.4rem;">${escapeHtml(r.priority)}</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.8rem; line-height: 1.5;">${escapeHtml(r.details)}</p>
              </div>
            `).join("");
          }
        }
      }
    } catch (err) {
      console.error("Error updating forensic summary:", err);
    }
  }

  // Bind filter change events to update PDF export link
  [selectEventId, selectTimeRange, selectLimit].forEach(select => {
    if (select) {
      select.addEventListener("change", () => {
        updatePdfExportLink();
      });
    }
  });

  // Initialize PDF link with current default filter values
  updatePdfExportLink();
});


