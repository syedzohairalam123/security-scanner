(() => {
  "use strict";

  /* ---------------- Theme toggle ---------------- */
  const THEME_KEY = "perimeter-theme";
  const root = document.documentElement;
  const savedTheme = localStorage.getItem(THEME_KEY);
  if (savedTheme) root.setAttribute("data-theme", savedTheme);

  const themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      localStorage.setItem(THEME_KEY, next);
    });
  }

  /* ---------------- CSRF helper ---------------- */
  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }

  async function apiFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers, { "X-CSRFToken": csrfToken() });
    return fetch(url, Object.assign({}, options, { headers }));
  }
  window.__apiFetch = apiFetch;

  /* ---------------- Homepage: live scan console ---------------- */
  const scanForm = document.getElementById("scan-form");
  if (scanForm) {
    const urlInput = document.getElementById("target-url");
    const consentInput = document.getElementById("consent-checkbox");
    const submitBtn = document.getElementById("scan-submit");
    const errorEl = document.getElementById("scan-form-error");

    const consoleEl = document.getElementById("scan-console");
    const consoleBar = document.getElementById("console-target-label");
    const statusEl = document.getElementById("console-status");
    const placeholder = document.getElementById("console-placeholder");
    const moduleList = document.getElementById("console-modules");
    const ctaEl = document.getElementById("console-cta");

    const moduleRows = {};
    if (moduleList) {
      moduleList.querySelectorAll(".console-module").forEach((row) => {
        moduleRows[row.dataset.label] = row;
      });
    }

    function resetConsole() {
      Object.values(moduleRows).forEach((row) => {
        row.classList.remove("is-active", "is-done");
        const count = row.querySelector(".count");
        if (count) count.textContent = "";
      });
      consoleEl.classList.remove("is-scanning", "is-complete", "is-error");
      if (ctaEl) ctaEl.innerHTML = "";
    }

    function setStatus(text, kind) {
      statusEl.textContent = text;
      statusEl.className = "console-status" + (kind ? " is-" + kind : "");
    }

    scanForm.addEventListener("submit", (event) => {
      event.preventDefault();
      errorEl.textContent = "";

      const targetUrl = urlInput.value.trim();
      if (!targetUrl) {
        errorEl.textContent = "Enter a target URL first.";
        return;
      }
      if (!consentInput.checked) {
        errorEl.textContent = "Confirm you own or are authorized to test this target.";
        return;
      }

      resetConsole();
      placeholder.style.display = "none";
      moduleList.style.display = "flex";
      consoleBar.textContent = targetUrl;
      consoleEl.classList.add("is-scanning");
      setStatus("Scanning\u2026", "active");
      submitBtn.disabled = true;
      submitBtn.textContent = "Scanning\u2026";

      const params = new URLSearchParams({ target_url: targetUrl, consent: "1" });
      const source = new EventSource("/api/scan/stream?" + params.toString());
      let settled = false;

      source.onmessage = (event) => {
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (e) {
          return;
        }

        if (data.type === "progress") {
          if (data.done !== undefined && data.total !== undefined) {
            setStatus(`Scanning\u2026 (${data.done}/${data.total})`, "active");
          }
          const label = (data.message || "").split(":")[0].trim();
          const row = moduleRows[label];
          if (row) {
            row.classList.add("is-done");
            const detail = data.message.includes(":") ? data.message.split(":").slice(1).join(":").trim() : "";
            const count = row.querySelector(".count");
            if (count) count.textContent = detail;
          }
        } else if (data.type === "complete") {
          settled = true;
          source.close();
          consoleEl.classList.remove("is-scanning");
          consoleEl.classList.add("is-complete");
          setStatus(`Done \u2014 risk ${Math.round(data.risk_score)}/100 (${data.risk_level})`, "done");
          submitBtn.disabled = false;
          submitBtn.textContent = "Scan another target";
          ctaEl.innerHTML = `<a class="btn btn-primary" href="/dashboard/${data.scan_id}">View full report</a>`;
          setTimeout(() => { window.location.href = "/dashboard/" + data.scan_id; }, 1100);
        } else if (data.type === "error") {
          settled = true;
          source.close();
          consoleEl.classList.remove("is-scanning");
          consoleEl.classList.add("is-error");
          setStatus("Error", "error");
          errorEl.textContent = data.message || "Scan failed.";
          submitBtn.disabled = false;
          submitBtn.textContent = "Scan target";
        }
      };

      source.onerror = () => {
        if (settled) return;
        settled = true;
        source.close();
        consoleEl.classList.remove("is-scanning");
        consoleEl.classList.add("is-error");
        setStatus("Connection lost", "error");
        errorEl.textContent = "Lost connection to the scan. Check the URL and try again.";
        submitBtn.disabled = false;
        submitBtn.textContent = "Scan target";
      };
    });
  }

  /* ---------------- Dashboard: AI assistant ---------------- */
  const aiForm = document.getElementById("ai-ask-form");
  if (aiForm) {
    const scanId = aiForm.dataset.scanId;
    const input = document.getElementById("ai-question");
    const messages = document.getElementById("ai-messages");
    const askBtn = document.getElementById("ai-ask-btn");

    function appendMessage(who, text) {
      const wrap = document.createElement("div");
      wrap.className = "ai-message from-" + who;
      const whoEl = document.createElement("div");
      whoEl.className = "who";
      whoEl.textContent = who === "user" ? "You" : "Assistant";
      const bodyEl = document.createElement("div");
      bodyEl.textContent = text;
      wrap.appendChild(whoEl);
      wrap.appendChild(bodyEl);
      messages.appendChild(wrap);
      messages.scrollTop = messages.scrollHeight;
    }

    aiForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const question = input.value.trim();
      if (!question) return;

      appendMessage("user", question);
      input.value = "";
      askBtn.disabled = true;
      askBtn.textContent = "Thinking\u2026";

      try {
        const res = await apiFetch(`/api/scan/${scanId}/ask`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question }),
        });
        const data = await res.json();
        appendMessage("assistant", res.ok ? data.answer : (data.error || "Something went wrong."));
      } catch (e) {
        appendMessage("assistant", "Request failed - check your connection and try again.");
      } finally {
        askBtn.disabled = false;
        askBtn.textContent = "Ask";
      }
    });
  }

  /* ---------------- History page: scheduled scans ---------------- */
  const scheduleForm = document.getElementById("schedule-form");
  if (scheduleForm) {
    scheduleForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const formData = new FormData(scheduleForm);
      const payload = {
        target_url: formData.get("target_url"),
        frequency: formData.get("frequency"),
        notify_email: formData.get("notify_email") === "on",
      };
      const errorEl = document.getElementById("schedule-form-error");
      errorEl.textContent = "";

      const res = await apiFetch("/api/schedule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        window.location.reload();
      } else {
        const data = await res.json().catch(() => ({}));
        errorEl.textContent = data.error || "Could not save that schedule.";
      }
    });
  }

  document.querySelectorAll(".delete-schedule-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Remove this scheduled scan?")) return;
      const res = await apiFetch(`/api/schedule/${btn.dataset.scheduleId}`, { method: "DELETE" });
      if (res.ok) btn.closest(".list-row").remove();
    });
  });
})();
