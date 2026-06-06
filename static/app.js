function formatRemaining(totalSeconds) {
  const safe = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(safe / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const seconds = safe % 60;
  if (hours > 0) {
    return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  }
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

const SOUND_STORAGE_KEY = "ctf_sound_enabled";
let audioContext = null;

function soundEnabled() {
  return localStorage.getItem(SOUND_STORAGE_KEY) === "1";
}

function getAudioContext() {
  if (!audioContext) {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) return null;
    audioContext = new Context();
  }
  return audioContext;
}

function scheduleTone(context, start, frequency, duration, volume) {
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(frequency, start);
  gain.gain.setValueAtTime(0.0001, start);
  gain.gain.exponentialRampToValueAtTime(volume, start + 0.015);
  gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);
  oscillator.connect(gain);
  gain.connect(context.destination);
  oscillator.start(start);
  oscillator.stop(start + duration + 0.03);
}

async function playSound(kind) {
  if (!soundEnabled()) return;
  const context = getAudioContext();
  if (!context) return;
  try {
    if (context.state === "suspended") {
      await context.resume();
    }
    const now = context.currentTime;
    if (kind === "challenge") {
      scheduleTone(context, now, 523.25, 0.1, 0.08);
      scheduleTone(context, now + 0.11, 659.25, 0.1, 0.08);
      scheduleTone(context, now + 0.22, 987.77, 0.16, 0.075);
    } else {
      scheduleTone(context, now, 880, 0.08, 0.065);
      scheduleTone(context, now + 0.09, 1174.66, 0.12, 0.06);
    }
  } catch (_error) {
    return;
  }
}

function refreshSoundToggles() {
  document.querySelectorAll("[data-sound-toggle]").forEach((button) => {
    const enabled = soundEnabled();
    button.classList.toggle("enabled", enabled);
    button.setAttribute("aria-pressed", enabled ? "true" : "false");
    button.title = enabled ? "Notification sounds on" : "Notification sounds off";
    button.innerHTML = enabled
      ? '<i class="fa-solid fa-volume-high" aria-hidden="true"></i>'
      : '<i class="fa-solid fa-volume-xmark" aria-hidden="true"></i>';
  });
}

function reloadAfterChallengeSound() {
  if (!soundEnabled()) {
    window.location.reload();
    return;
  }
  playSound("challenge");
  window.setTimeout(() => window.location.reload(), 420);
}

function tickCountdowns() {
  document.querySelectorAll("[data-countdown]").forEach((node) => {
    const deadline = Date.parse(node.dataset.deadline);
    if (Number.isNaN(deadline)) return;
    const remaining = Math.floor((deadline - serverNow()) / 1000);
    node.textContent = formatRemaining(remaining);
    node.classList.toggle("warning", remaining > 0 && remaining <= 60);
    node.classList.toggle("expired", remaining <= 0);
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function userProfileLink(username) {
  const safe = encodeURIComponent(String(username));
  return `<a href="/users/${safe}">${escapeHtml(username)}</a>`;
}

function localTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString("zh-TW", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function renderScoreboard(payload) {
  const board = document.querySelector("[data-scoreboard-body]");
  if (!board || !Array.isArray(payload.scoreboard)) return;
  if (payload.scoreboard.length === 0) {
    board.innerHTML = '<tr><td colspan="5" class="muted">No solves yet.</td></tr>';
  } else {
    board.innerHTML = payload.scoreboard.map((row, index) => (
      `<tr><td>${index + 1}</td><td>${userProfileLink(row.username)}</td><td>${row.score}</td><td>${row.solved_count}</td><td>${localTime(row.last_solve)}</td></tr>`
    )).join("");
  }
  const total = Number(payload.scoreboard_total ?? payload.scoreboard.length);
  const limit = Number(payload.scoreboard_limit ?? payload.scoreboard.length);
  const shown = Math.min(payload.scoreboard.length, limit, total);
  const summary = document.querySelector("[data-scoreboard-summary]");
  if (summary) {
    summary.textContent = total > 0 ? `Showing top ${shown} of ${total} players.` : "No solves yet.";
  }
  const fullLink = document.querySelector("[data-scoreboard-full-link]");
  if (fullLink) {
    fullLink.hidden = total <= shown;
  }
}

async function pollLiveState(root) {
  const url = root.dataset.stateUrl;
  if (!url) return;
  try {
    const response = await fetch(url, { credentials: "same-origin" });
    if (!response.ok) return;
    const payload = await response.json();
    const nextId = payload.active ? String(payload.active.id) : "";
    const currentId = root.dataset.currentChallengeId || "";
    if (nextId !== currentId) {
      reloadAfterChallengeSound();
      return;
    }
    if (payload.active) {
      const title = root.querySelector("[data-live-title]");
      const countdown = root.querySelector("[data-countdown]");
      if (title) title.textContent = payload.active.title;
      if (countdown) countdown.dataset.deadline = payload.active.closes_at;
    }
    renderScoreboard(payload);
  } catch (_error) {
    return;
  }
}

let clockOffsetMs = 0;

function serverNow() {
  return Date.now() + clockOffsetMs;
}

function applyClockSync(payload) {
  const serverMs = Date.parse(payload.server_time);
  if (Number.isNaN(serverMs)) return;
  const receivedAt = Date.now();
  const sentAt = Number(payload.client_sent_at);
  const estimatedClientAtServer = Number.isFinite(sentAt) && sentAt <= receivedAt
    ? (sentAt + receivedAt) / 2
    : receivedAt;
  const nextOffset = serverMs - estimatedClientAtServer;
  clockOffsetMs = clockOffsetMs === 0 ? nextOffset : (clockOffsetMs * 0.7) + (nextOffset * 0.3);
}

function applyStatePayload(root, payload) {
  applyClockSync(payload);
  const nextId = payload.active ? String(payload.active.id) : "";
  const currentId = root.dataset.currentChallengeId || "";
  if (nextId !== currentId) {
    reloadAfterChallengeSound();
    return;
  }
  if (payload.active) {
    const title = root.querySelector("[data-live-title]");
    const countdown = root.querySelector("[data-countdown]");
    if (title) title.textContent = payload.active.title;
    if (countdown) countdown.dataset.deadline = payload.active.closes_at;
  }
  renderScoreboard(payload);
}

function websocketUrl(path) {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}${path}`;
}

function connectLiveState(root) {
  if (!("WebSocket" in window) || !root.dataset.wsUrl) {
    return false;
  }
  let socket;
  let syncTimer;
  let closedByBrowser = false;

  const sendSync = () => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "sync", client_sent_at: Date.now() }));
    }
  };

  try {
    socket = new WebSocket(websocketUrl(root.dataset.wsUrl));
  } catch (_error) {
    return false;
  }

  socket.addEventListener("open", () => {
    sendSync();
    syncTimer = window.setInterval(sendSync, 10000);
  });

  socket.addEventListener("message", (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch (_error) {
      return;
    }
    if (payload.type === "sync") {
      applyClockSync(payload);
      return;
    }
    if (payload.type === "hello" || payload.type === "tick" || payload.type === "round_changed") {
      applyStatePayload(root, payload);
    }
  });

  socket.addEventListener("close", () => {
    window.clearInterval(syncTimer);
    if (!closedByBrowser) {
      window.setTimeout(() => {
        if (!connectLiveState(root)) {
          window.setInterval(() => pollLiveState(root), 8000);
        }
      }, 1500);
    }
  });

  window.addEventListener("beforeunload", () => {
    closedByBrowser = true;
    socket.close();
  });

  return true;
}

function previewItems(root) {
  return Array.from(root.children).filter((child) => !child.matches("script, style"));
}

function applyListPreview(root) {
  if (!root || root.dataset.previewApplied === "1") return;
  const limit = Number(root.dataset.previewLimit || "10");
  if (!Number.isFinite(limit) || limit <= 0) return;
  const items = previewItems(root);
  const anchor = root.closest(".table-wrap") || root;
  if (anchor.nextElementSibling?.classList.contains("preview-more-row")) {
    anchor.nextElementSibling.remove();
  }
  if (items.length <= limit) return;
  root.dataset.previewApplied = "1";
  items.slice(limit).forEach((item) => {
    item.hidden = true;
    item.dataset.previewHidden = "1";
  });
  const button = document.createElement("button");
  button.className = "button small preview-more";
  button.type = "button";
  button.textContent = `SHOW MORE ${limit}/${items.length}`;
  button.addEventListener("click", () => {
    const expanded = root.dataset.previewExpanded === "1";
    root.dataset.previewExpanded = expanded ? "0" : "1";
    items.slice(limit).forEach((item) => {
      item.hidden = !expanded;
    });
    button.textContent = expanded ? `SHOW MORE ${limit}/${items.length}` : `SHOW LESS ${items.length}/${items.length}`;
  });
  const row = document.createElement("div");
  row.className = "preview-more-row";
  row.appendChild(button);
  anchor.insertAdjacentElement("afterend", row);
}

tickCountdowns();
setInterval(tickCountdowns, 1000);

refreshSoundToggles();

document.querySelectorAll("[data-sound-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    localStorage.setItem(SOUND_STORAGE_KEY, soundEnabled() ? "0" : "1");
    refreshSoundToggles();
    playSound("notification");
  });
});

if (document.querySelector(".flash")) {
  window.setTimeout(() => playSound("notification"), 250);
}

document.querySelectorAll("[data-preview-list]").forEach((root) => applyListPreview(root));

document.querySelectorAll("[data-live-state]").forEach((root) => {
  if (!connectLiveState(root)) {
    setInterval(() => pollLiveState(root), 8000);
  }
});

document.querySelectorAll("[data-flag-mode]").forEach((select) => {
  const form = select.closest("form");
  const sync = () => {
    form.querySelectorAll("[data-flag-group]").forEach((group) => {
      group.hidden = group.dataset.flagGroup !== select.value;
    });
  };
  select.addEventListener("change", sync);
  sync();
});

document.querySelectorAll("[data-copy-button]").forEach((button) => {
  button.addEventListener("click", async () => {
    const raw = button.dataset.copyValue || "";
    const value = raw.startsWith("http") ? raw : `${window.location.origin}${raw}`;
    try {
      await navigator.clipboard.writeText(value);
      button.classList.add("copied");
      playSound("notification");
      window.setTimeout(() => button.classList.remove("copied"), 1200);
    } catch (_error) {
      const field = button.closest("tr")?.querySelector("[data-copy-value]");
      if (field) {
        field.focus();
        field.select();
      }
    }
  });
});

document.querySelectorAll("[data-sortable-challenges]").forEach((tbody) => {
  let dragged = null;

  const rows = () => Array.from(tbody.querySelectorAll("tr[data-challenge-id]"));
  const cleanup = () => {
    rows().forEach((row) => row.classList.remove("dragging", "drop-target"));
  };
  const saveOrder = async () => {
    const order = rows().map((row) => row.dataset.challengeId).join(",");
    const body = new URLSearchParams({ _csrf: tbody.dataset.csrf || "", order });
    const response = await fetch(tbody.dataset.reorderUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (response.ok) {
      window.location.reload();
    }
  };

  tbody.addEventListener("dragstart", (event) => {
    const row = event.target.closest("tr[data-challenge-id]");
    if (!row) return;
    dragged = row;
    row.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", row.dataset.challengeId);
  });

  tbody.addEventListener("dragover", (event) => {
    if (!dragged) return;
    const target = event.target.closest("tr[data-challenge-id]");
    if (!target || target === dragged) return;
    event.preventDefault();
    cleanup();
    dragged.classList.add("dragging");
    target.classList.add("drop-target");
    const rect = target.getBoundingClientRect();
    const after = event.clientY > rect.top + rect.height / 2;
    tbody.insertBefore(dragged, after ? target.nextSibling : target);
  });

  tbody.addEventListener("drop", async (event) => {
    if (!dragged) return;
    event.preventDefault();
    cleanup();
    dragged = null;
    await saveOrder();
  });

  tbody.addEventListener("dragend", () => {
    cleanup();
    dragged = null;
  });
});
