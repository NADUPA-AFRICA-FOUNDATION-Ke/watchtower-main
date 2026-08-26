/* Watchtower frontend. No framework, no build step — open the page and it works.
   The sweep arrives over SSE, so sources fill their lane as each one lands
   rather than everything appearing at once after a minute of nothing. */

const $ = (s) => document.querySelector(s);
const el = (t, cls, txt) => {
  const n = document.createElement(t);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};

const BAND_COLOUR = {
  HIGH: "var(--high)", MED: "var(--med)", LOW: "var(--low)", WEAK: "var(--weak)",
};
const BAND_SEGMENTS = { HIGH: 5, MED: 4, LOW: 2, WEAK: 1 };

let selected = new Set();
let hours = 72;
let stream = null;
let capabilities = {};

/* ------------------------------------------------------------ bootstrap */

async function init() {
  let data;
  try {
    data = await (await fetch("/api/sources")).json();
  } catch {
    $("#ai-status").textContent = "server unreachable";
    return;
  }
  capabilities = data;

  const unavailable = data.sources.filter((s) => s.available === false);
  const statusDetails = $("#status-details");
  statusDetails.replaceChildren(
    el("li", null, `${data.sources.length - unavailable.length} of ${data.sources.length} sources available`),
    el("li", null, data.ai_available
      ? `Model scoring available (${data.ai_provider})` : "Model scoring unavailable — keyword ranking only"),
    el("li", null, data.ephemeral_storage
      ? "Temporary storage — saving and analyst verdicts are disabled" : "Durable local storage available"),
    ...unavailable.map((s) => el("li", null, `${s.name}: unavailable (${s.key_name || "configuration required"})`)),
  );
  $("#system-status-summary").textContent = data.ephemeral_storage
    ? `${unavailable.length} source${unavailable.length === 1 ? "" : "s"} unavailable · temporary storage`
    : `${unavailable.length} source${unavailable.length === 1 ? "" : "s"} unavailable · storage ready`;

  const box = $("#sources");
  const sanctionsBox = $("#sanctions-source");
  const sanctionsNote = $("#sanctions-note");
  data.sources.forEach((s) => {
    const isSanctions = s.name === "opensanctions";
    const chip = el("button", "chip", isSanctions ? "OpenSanctions" : s.name);
    chip.type = "button";
    chip.dataset.source = s.name;
    // Gate on the key actually being present, not on whether the source is a
    // default. opensanctions is both, so the old `needs_key && !default` guard
    // never fired and it shipped selected but dead.
    const usable = s.available !== false;
    const on = s.default && usable;
    chip.setAttribute("aria-pressed", String(on));
    if (on) { chip.classList.add("is-on"); selected.add(s.name); }
    if (!usable) {
      chip.disabled = true;
      chip.title = `Set ${s.key_name || "the API key"} to enable`;
      if (isSanctions) {
        sanctionsNote.textContent =
          `Set ${s.key_name || "OPENSANCTIONS_API_KEY"} to search sanctions, PEP and watchlist records.`;
      }
    } else if (isSanctions) {
      sanctionsNote.textContent =
        "Ready — include OpenSanctions in this sweep for sanctions, PEP and watchlist matches.";
    }
    chip.onclick = () => {
      chip.classList.toggle("is-on");
      const on = chip.classList.contains("is-on");
      chip.setAttribute("aria-pressed", String(on));
      on ? selected.add(s.name) : selected.delete(s.name);
    };
    (isSanctions ? sanctionsBox : box).append(chip);
  });

  // On a serverless host the archive lives in /tmp and does not survive between
  // requests. Saying nothing would let someone tick "Keep results", see it
  // succeed, and find an empty Archive tab later — a silent data loss.
  if (data.ephemeral_storage) {
    const keep = $("#keep");
    keep.checked = false;
    keep.disabled = true;
    keep.closest(".toggle").title =
      "This deployment has no persistent disk — saved results are lost between requests.";
    const note = el("p", "hint warn-note",
      "Storage on this host is temporary: anything you keep is lost between requests.");
    $("#sweep-form").append(note);
  }

  // Name the provider actually in use. The label said "Score with Claude" long
  // after a Gemini key would drive it, which is the kind of drift that makes
  // someone doubt what the rest of the page is telling them.
  const provider = { gemini: "Gemini", anthropic: "Claude" }[data.ai_provider];
  if (!data.ai_available) {
    $("#use-ai").checked = false;
    $("#use-ai").disabled = true;
    $("#use-ai").closest(".toggle").title =
      "Set GEMINI_API_KEY (free tier) or ANTHROPIC_API_KEY to enable scoring";
    $("#ai-label").textContent = "Score with a model";
    $("#ai-status").textContent = "keyword ranking";
  } else {
    $("#ai-label").textContent = `Score with ${provider || "a model"}`;
    $("#ai-status").textContent = provider
      ? `scoring ready — ${provider}` : "scoring ready";
  }
}

$("#status-toggle").onclick = () => {
  const details = $("#status-details");
  details.hidden = !details.hidden;
  $("#status-toggle").setAttribute("aria-expanded", String(!details.hidden));
};

/* -------------------------------------------------------------- controls */

$("#window").onclick = (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  $("#window").querySelectorAll("button").forEach((x) => {
    x.classList.remove("is-on");
    x.setAttribute("aria-checked", "false");
  });
  b.classList.add("is-on");
  b.setAttribute("aria-checked", "true");
  hours = Number(b.dataset.h);
};

function radioKeys(group, apply) {
  group.addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(e.key)) return;
    const buttons = [...group.querySelectorAll('[role="radio"]:not([disabled])')];
    const current = buttons.indexOf(document.activeElement);
    let next = current < 0 ? 0 : current;
    if (["ArrowRight", "ArrowDown"].includes(e.key)) next = (next + 1) % buttons.length;
    if (["ArrowLeft", "ArrowUp"].includes(e.key)) next = (next - 1 + buttons.length) % buttons.length;
    if (e.key === "Home") next = 0;
    if (e.key === "End") next = buttons.length - 1;
    e.preventDefault();
    buttons[next].click();
    buttons[next].focus();
    if (apply) apply(buttons[next]);
  });
}
radioKeys($("#window"));

/* Two tools, one front door. The views are independent — nothing on the
   scamscan side reads watchtower's store and vice versa — so switching sides
   is only ever showing and hiding, never a state handover. */
const VIEWS = ["sweep", "archive", "discover", "queue", "score"];

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.remove("is-on");
      t.removeAttribute("aria-current");
    });
    tab.classList.add("is-on");
    tab.setAttribute("aria-current", "page");
    VIEWS.forEach((v) => {
      const section = document.getElementById(`view-${v}`);
      if (section) section.hidden = tab.dataset.view !== v;
    });
    $("#rail-name").textContent = (tab.dataset.side || "watchtower").toUpperCase();
    if (location.hash !== `#${tab.dataset.view}`) location.hash = tab.dataset.view;
    const heading = document.querySelector(`#view-${tab.dataset.view} .view-head`);
    if (heading) heading.focus();
    if (tab.dataset.view === "queue") loadQueue();
  };
});

function openHashView() {
  const view = location.hash.slice(1);
  const tab = document.querySelector(`.tab[data-view="${view}"]`);
  if (tab && !tab.classList.contains("is-on")) tab.click();
}
window.addEventListener("hashchange", openHashView);

/* ----------------------------------------------------------------- sweep */

$("#sweep-form").onsubmit = (e) => {
  e.preventDefault();
  const q = $("#q").value.trim();
  if (q.length < 2) return;
  if (!selected.size) return showEmpty("Pick a source", "Nothing is selected to search.");
  startSweep(q);
};

function startSweep(q) {
  if (stream) stream.close();

  $("#go").disabled = true;
  $("#go").textContent = "Monitoring";
  $("#results").hidden = true;
  $("#empty").hidden = true;
  $("#trace").hidden = false;
  $("#trace-title").textContent = `Monitoring "${q}"`;
  $("#trace-stage").textContent = "";

  const lanes = $("#lanes");
  lanes.replaceChildren();
  const laneOf = {};
  [...selected].forEach((name) => {
    const lane = el("div", "lane pending");
    lane.append(el("span", "lane-name", name));
    const bar = el("div", "lane-bar");
    bar.append(el("div", "lane-fill"));
    lane.append(bar, el("span", "lane-count", "·"));
    lanes.append(lane);
    laneOf[name] = lane;
  });

  const params = new URLSearchParams({
    q, hours,
    sources: [...selected].join(","),
    use_ai: $("#use-ai").checked,
    fetch_bodies: $("#fetch-bodies").checked,
    // Off by default, same as the API. The Archive tab is empty until this is
    // ticked, so it's the only way to populate it from the browser.
    save: $("#keep").checked,
  });

  stream = new EventSource(`/api/sweep?${params}`);

  stream.addEventListener("source", (ev) => {
    const d = JSON.parse(ev.data);
    const lane = laneOf[d.name];
    if (!lane) return;
    lane.classList.remove("pending");
    lane.classList.add("done");
    if (d.error) lane.classList.add("failed");
    if (d.skipped) lane.classList.add("skipped");
    if (!d.count) lane.classList.add("zero");
    // Bars are relative to 20 hits, capped — absolute scale would make a
    // 3-hit source look like a failure next to a 60-hit one.
    lane.style.setProperty("--w", `${Math.min(100, (d.count / 20) * 100) || 4}%`);
    // A failed or unsearched lane must never read as "0". Zero is a finding.
    lane.querySelector(".lane-count").textContent =
      d.error ? "failed" : d.skipped ? "off" : d.count;
    if (d.reason || d.skipped) lane.title = d.reason || d.skipped;
  });

  stream.addEventListener("stage", (ev) => {
    const d = JSON.parse(ev.data);
    const label = {
      dedupe: `deduped ${d.before} → ${d.after}`,
      fetch: `reading ${d.count} article${d.count === 1 ? "" : "s"}`,
      score: `scoring ${d.count}`,
    }[d.stage];
    if (label) $("#trace-stage").textContent = label;
  });

  stream.addEventListener("scored", (ev) => {
    const d = JSON.parse(ev.data);
    $("#trace-stage").textContent = `scored [${d.relevance}] ${d.title}`;
  });

  stream.addEventListener("done", (ev) => {
    finish();
    render(JSON.parse(ev.data));
  });

  stream.addEventListener("failed", (ev) => {
    finish();
    showEmpty("The sweep stopped", JSON.parse(ev.data).message);
  });

  stream.onerror = () => {
    if (!$("#go").disabled) return;   // already finished cleanly
    finish();
    showEmpty("Lost the connection", "The server closed the stream. Check its log and try again.");
  };
}

function finish() {
  if (stream) { stream.close(); stream = null; }
  $("#go").disabled = false;
  $("#go").textContent = "Monitor";
  $("#trace-stage").textContent = "";
  $("#trace-title").textContent = "Sources";
}

$("#cancel-sweep").onclick = () => {
  if (!stream) return;
  stream.close();
  stream = null;
  finish();
  showEmpty("Updates stopped", "The browser stopped listening. Requests already sent to providers may still finish or incur cost.");
};

/* --------------------------------------------------------------- render */

function gauge(band) {
  const g = el("span", "gauge");
  const on = BAND_SEGMENTS[band] || 1;
  for (let i = 0; i < 5; i++) g.append(el("i", i < on ? "on" : ""));
  return g;
}

function card(item) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[item.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(item.band), el("span", "score", item.relevance));
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || "(untitled)");
  a.href = item.url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  // How many independent domains carried this story. The cheapest strong
  // signal that something is real, and it would otherwise be thrown away by
  // dedupe — so it gets its own badge rather than hiding in the metadata line.
  const corroboration = item.raw_meta?.corroboration || 1;
  if (corroboration > 1) {
    const c = el("span", "corrob", `${corroboration} sources`);
    c.title = (item.raw_meta.corroborating_domains || []).join("\n");
    top.append(c);
  }
  if (item.raw_meta?.headline_only) {
    const h = el("span", "flag", "headline only");
    h.title = "No article body was read — scored on the headline alone.";
    top.append(h);
  }

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.source));
  if (item.published_at) meta.append(el("span", null, item.published_at.slice(0, 16)));
  if (item.author) meta.append(el("span", null, item.author));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  c.append(meta);

  const body = item.summary || item.text;
  if (body) c.append(el("p", "body", body.slice(0, 320)));

  if (item.categories?.length) {
    const tags = el("div", "tags");
    item.categories.forEach((t) => tags.append(el("span", "tag", t)));
    c.append(tags);
  }
  return c;
}

/* Why a count can't be trusted, in the user's words rather than a stack trace. */
function coverageNotes(d) {
  return [
    ...Object.entries(d.failed || {}).map(([k, v]) => `${k} failed — ${v}`),
    ...Object.entries(d.skipped || {}).map(([k, v]) => `${k} was not searched — ${v}`),
  ];
}

function render(d) {
  const notes = coverageNotes(d);

  if (!d.items.length) {
    // "Nothing came back" is a claim about the world. Only make it when every
    // source actually answered; otherwise this is an absence of evidence that
    // someone could mistake for evidence of absence.
    return d.complete === false
      ? showEmpty(
          "Incomplete sweep — no results",
          "This is not a clean result. Some sources could not be searched, so " +
          "nothing here rules anything out.",
          notes)
      : showEmpty(
          "Nothing came back",
          "Every source was searched and none returned a match. Try a longer " +
          "window, fewer words, or looser terms.",
          notes);
  }

  const strong = d.items.filter((i) => i.relevance >= 60).length;
  const sum = $("#summary");
  sum.replaceChildren();
  // Results arrived, but not from everywhere. Say so next to the count, or the
  // count reads as the whole picture.
  if (d.complete === false) {
    const w = el("span", "warn",
      `partial coverage — ${notes.length} source${notes.length === 1 ? "" : "s"} unavailable`);
    w.title = notes.join("\n");
    sum.append(w);
  }
  const n = el("span");
  n.innerHTML = `<strong>${d.items.length}</strong> result${d.items.length === 1 ? "" : "s"}`;
  sum.append(n);
  if (d.enriched) {
    const s = el("span");
    s.innerHTML = `<strong>${strong}</strong> scored 60+`;
    sum.append(s);
  } else {
    sum.append(el("span", null,
      `keyword ranking — ${d.scoring_error || "no API key"}`));
  }
  if (d.report) {
    const link = el("a", null, "Download report");
    link.href = `/api/report/${encodeURIComponent(d.report)}`;
    sum.append(link);
  }

  $("#findings").replaceChildren(...d.items.map(card));

  const side = $("#side");
  side.replaceChildren();

  if (d.entities.length) {
    const p = el("div", "panel");
    p.append(el("h4", null, "Recurring names"));
    const ul = el("ul");
    d.entities.slice(0, 12).forEach((e) => {
      const li = el("li");
      li.append(el("span", null, e.name), el("span", null, e.count));
      ul.append(li);
    });
    p.append(ul);
    side.append(p);
  }

  const p2 = el("div", "panel");
  p2.append(el("h4", null, "Source yield"));
  const ul2 = el("ul");
  Object.entries(d.per_source).forEach(([k, v]) => {
    const li = el("li");
    li.append(el("span", null, k), el("span", null, v));
    ul2.append(li);
  });
  p2.append(ul2);
  side.append(p2);

  if (d.errors.length) {
    const p3 = el("div", "panel");
    p3.append(el("h4", null, "Problems"));
    d.errors.slice(0, 6).forEach((e) => p3.append(el("p", "errs", e)));
    side.append(p3);
  }

  $("#results").hidden = false;
  $("#empty").hidden = true;
}

function showEmpty(title, msg, errors) {
  const box = $("#empty");
  box.replaceChildren(el("h3", null, title), el("p", null, msg));
  // A zero-result sweep is more often a broken source than an absent story.
  // The Problems panel lives in #results, which this hides — so without this
  // the reason a source failed is only ever in the server log.
  if (errors && errors.length) {
    const box2 = el("div", "empty-errs");
    box2.append(el("h4", null, "What went wrong"));
    errors.slice(0, 6).forEach((e) => box2.append(el("p", "errs", e)));
    box.append(box2);
  }
  box.hidden = false;
  $("#results").hidden = true;
}

/* --------------------------------------------------------------- archive */

$("#archive-form").onsubmit = async (e) => {
  e.preventDefault();
  const q = $("#aq").value.trim();
  if (!q) return;
  const out = $("#archive-results");
  out.replaceChildren(el("p", "hint", "Searching…"));
  try {
    const r = await fetch(`/api/archive?q=${encodeURIComponent(q)}`);
    if (!r.ok) {
      const err = await r.json();
      out.replaceChildren(el("p", "errs", err.detail || "Search failed"));
      return;
    }
    const d = await r.json();
    out.replaceChildren(
      ...(d.items.length
        ? d.items.map(card)
        : [el("p", "hint", "Nothing saved matches that. Turn on “Keep results” in Monitor to start filling saved results.")])
    );
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
};

/* ======================================================================
   scamscan — the other side. Separate store, separate config, separate
   failure modes: here an empty queue reads as "this brand is clean", so a
   query that never ran must never look like a query that found nothing.
   ====================================================================== */

let scam = {};
let minScore = 45;
let disposition = "new";
let huntStream = null;

async function initScamscan() {
  let d;
  try {
    d = await (await fetch("/api/scamscan/status")).json();
  } catch {
    return;
  }
  if (d.detail) return;               // not configured; leave the tab inert
  scam = d;
  $("#brand-name").textContent = d.brand;

  const perTopic = (d.queries_per_topic || 0) * (d.max_uses_per_query || 0);
  const notes = [
    `Up to ${perTopic} searches per topic (about $${(perTopic * 0.01).toFixed(2)}) ` +
    `plus tokens, on ${d.model} with ${d.search_tool}.`,
  ];
  if (!d.api_available) {
    $("#hunt-go").disabled = true;
    $("#hunt-go").title = "Set ANTHROPIC_API_KEY to run a hunt";
    notes.push("No ANTHROPIC_API_KEY is set, so a hunt cannot run. Scoring on the Score tab still works — it makes no API calls.");
  }
  // A review queue on ephemeral storage is worse than no queue: the analyst
  // verdicts are the whole point and they are what gets lost.
  if (d.ephemeral_storage) {
    notes.push("Storage on this host is temporary — findings and the verdicts you record on them are lost between requests.");
    $("#hunt-go").disabled = true;
    $("#hunt-go").title = "Hunts require durable storage so findings and verdicts are not lost";
  }
  $("#hunt-cost").textContent = notes.join(" ");
  $("#hunt-cost").hidden = false;
}

/* --------------------------------------------------------- queue filters */

function segmented(id, attr, apply) {
  $(id).onclick = (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    $(id).querySelectorAll("button").forEach((x) => {
      x.classList.remove("is-on");
      x.setAttribute("aria-checked", "false");
    });
    b.classList.add("is-on");
    b.setAttribute("aria-checked", "true");
    apply(b.dataset[attr]);
    loadQueue();
  };
  radioKeys($(id));
}
segmented("#min-score", "s", (v) => { minScore = Number(v); });
segmented("#disposition", "d", (v) => { disposition = v; });

$("#queue-form").onsubmit = (e) => { e.preventDefault(); loadQueue(); };

async function loadQueue() {
  const out = $("#queue-results");
  out.replaceChildren(el("p", "hint", "Loading…"));
  try {
    const r = await fetch(
      `/api/scamscan/queue?min_score=${minScore}&disposition=${disposition}`);
    if (!r.ok) {
      const err = await r.json();
      out.replaceChildren(el("p", "errs", err.detail || "Could not read the queue."));
      return;
    }
    const d = await r.json();
    if (!d.items.length) {
      // Never let this read as "the brand is clean". It means this database is
      // empty, which is a fact about the tool, not about the world.
      const box = el("div", "empty-inline");
      box.append(
        el("h3", null, "Nothing in the queue"),
        el("p", null,
          `No stored finding scores ${minScore}+ with disposition "${disposition}". ` +
          "That is a statement about this database, not about the brand — run a " +
          "hunt above, or widen the filters."));
      out.replaceChildren(box);
      return;
    }
    out.replaceChildren(...d.items.map(queueCard));
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
}

/* ---------------------------------------------------------- queue render */

/* Every family that reported, as a bar. Absent families are omitted rather
   than drawn at zero — an absent model_confidence is not a low one, and the
   chart has to say the same thing the scorer does. */
function familyBars(b) {
  const box = el("div", "fams");
  const rows = [
    ["lexicon", b.lexicon_score], ["artifact", b.artifact_score],
    ["impersonation", b.impersonation_score], ["model", b.model_score],
  ];
  rows.forEach(([name, value]) => {
    const row = el("div", "fam");
    row.append(el("span", "fam-name", name));
    const bar = el("div", "fam-bar");
    if (value == null) {
      // No fill element at all. A .fam-fill with no width set is a block that
      // fills its track, which drew an absent family as a full bar — the one
      // reading this must never produce.
      row.classList.add("absent");
      row.append(bar, el("span", "fam-val", "absent"));
    } else {
      const fill = el("div", "fam-fill");
      fill.style.width = `${Math.max(2, Math.min(100, value))}%`;
      bar.append(fill);
      row.append(bar, el("span", "fam-val", String(Math.round(value))));
    }
    box.append(row);
  });
  return box;
}

/* Each hit with the source it came from. A score you cannot trace is a score
   you cannot defend, so the provenance is on the card, not in a log. */
function hitList(hits) {
  const box = el("div", "hits");
  (hits || []).slice(0, 14).forEach((h) => {
    const m = /^(.*?)\s*\[(.+)\]$/.exec(h);
    const chip = el("span", h.startsWith("counter:") ? "hit is-counter" : "hit");
    chip.append(el("span", "hit-term", m ? m[1] : h));
    if (m) chip.append(el("span", "hit-src", m[2]));
    box.append(chip);
  });
  return box;
}

/* ------------------------------------------------------------- discover */

$("#discover-form").onsubmit = async (e) => {
  e.preventDefault();
  const brand = $("#discover-brand").value.trim();
  const limit = Math.max(1, Math.min(20, Number($("#discover-limit").value) || 10));
  const button = $("#discover-go");
  const trace = $("#discover-trace");
  const stage = $("#discover-stage");
  const out = $("#discover-results");

  button.disabled = true;
  button.textContent = "Searching";
  trace.hidden = false;
  stage.textContent = `looking for ${brand}`;
  $("#discover-summary").replaceChildren();
  out.replaceChildren();

  try {
    const r = await fetch("/api/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ brand, limit }),
    });
    const d = await r.json();
    if (!r.ok) {
      out.replaceChildren(el("p", "errs", d.detail || "Discovery could not run."));
      stage.textContent = "incomplete";
      return;
    }

    stage.textContent = `${d.count} candidate${d.count === 1 ? "" : "s"}`;
    const summary = $("#discover-summary");
    summary.append(el("span", null,
      `${d.count} ranked candidate${d.count === 1 ? "" : "s"}`));
    summary.append(el("span", "warn", "review before acting"));
    if (!d.results.length) {
      const empty = el("div", "empty-inline");
      empty.append(el("h3", null, "No candidates returned"),
        el("p", null, "This only describes this search run; it does not establish that the brand is clean."));
      out.replaceChildren(empty);
    } else {
      out.replaceChildren(...d.results.map(discoveryCard));
    }
  } catch {
    stage.textContent = "incomplete";
    out.replaceChildren(el("p", "errs", "Could not reach the discovery service."));
  } finally {
    button.disabled = false;
    button.textContent = "Find sites";
  }
};

function discoveryCard(item) {
  const c = el("article", "card");
  const band = item.score >= 80 ? "HIGH" : item.score >= 45 ? "MED"
    : item.score >= 20 ? "LOW" : "WEAK";
  c.style.setProperty("--band", BAND_COLOUR[band]);

  const top = el("div", "card-top");
  top.append(gauge(band), el("span", "score", Math.round(item.score || 0)),
    el("span", "flag", item.classification || "candidate"));
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || item.url || "(untitled candidate)");
  a.href = item.url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.brand || "brand"),
    el("span", null, item.source || "search"));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  c.append(meta);
  if (item.summary) c.append(el("p", "body", item.summary.slice(0, 320)));

  const b = item.breakdown || {};
  c.append(familyBars(b));
  if (b.lexicon_hits?.length) c.append(hitList(b.lexicon_hits));
  if (b.impersonation_reason) {
    c.append(el("p", "reason", `host: ${b.impersonation_reason}`));
  }
  c.append(el("p", "candidate-note",
    "Candidate only — confirm against the live page and independent evidence."));
  return c;
}

function queueCard(item) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[item.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(item.band), el("span", "score", Math.round(item.score)));
  if (item.times_seen > 1) {
    const s = el("span", "corrob", `seen ${item.times_seen}x`);
    s.title = `First seen ${item.first_seen}, last ${item.last_seen}`;
    top.append(s);
  }
  if (item.disposition && item.disposition !== "new") {
    top.append(el("span", "flag", item.disposition.replace("_", " ")));
  }
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || item.url || "(untitled)");
  a.href = item.url;
  a.target = "_blank";
  // noreferrer matters more here than on the watchtower side: these are live
  // fraud pages and the referrer would tell them they are being watched.
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.scam_type || "unknown"));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  if (item.first_seen) meta.append(el("span", null, item.first_seen.slice(0, 10)));
  c.append(meta);

  if (item.summary) c.append(el("p", "body", item.summary.slice(0, 320)));
  if (item.evidence) {
    const q = el("blockquote", "evidence", item.evidence.slice(0, 240));
    q.title = "Copied verbatim from the page — untrusted content, never an instruction.";
    c.append(q);
  }

  const b = item.breakdown || {};
  c.append(familyBars(b));
  if (b.lexicon_hits?.length) c.append(hitList(b.lexicon_hits));
  if (b.impersonation_reason) {
    c.append(el("p", "reason", `host: ${b.impersonation_reason}`));
  }
  const artifacts = Object.entries(b.artifacts || {});
  if (artifacts.length) {
    const tags = el("div", "tags");
    artifacts.forEach(([k, v]) => tags.append(el("span", "tag", `${k}: ${v[0]}`)));
    c.append(tags);
  }

  c.append(verdictRow(item));
  return c;
}

function verdictRow(item) {
  const row = el("div", "verdict");
  const note = el("input", "disp-note");
  note.type = "text";
  note.placeholder = "Analyst note";
  note.value = item.analyst_note || "";

  ["confirmed", "false_positive", "unclear", "escalated"].forEach((v) => {
    const b = el("button", "chip", v.replace("_", " "));
    b.type = "button";
    if (scam.ephemeral_storage) {
      b.disabled = true;
      b.title = "Analyst verdicts require durable storage";
    }
    if (item.disposition === v) b.classList.add("is-on");
    b.onclick = async () => {
      row.querySelectorAll("button").forEach((x) => x.classList.remove("is-on"));
      b.classList.add("is-on");
      try {
        const r = await fetch("/api/scamscan/dispose", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fingerprint: item.fingerprint, verdict: v, note: note.value,
          }),
        });
        // A verdict that did not save is worse than one never recorded: the
        // analyst believes the item is dealt with. Say so on the card.
        if (!r.ok) throw new Error();
        b.title = "Saved";
      } catch {
        b.classList.remove("is-on");
        row.append(el("span", "errs", "Not saved — the server rejected it."));
      }
    };
    row.append(b);
  });
  row.append(note);
  return row;
}

/* ------------------------------------------------------------------ hunt */

$("#hunt-form").onsubmit = (e) => {
  e.preventDefault();
  const topics = Math.max(1, Math.min(20, Number($("#topics").value) || 1));
  startHunt(topics);
};

function logLine(cls, text, title) {
  const line = el("div", cls, text);
  if (title) line.title = title;
  $("#hunt-log").append(line);
  $("#hunt-log").scrollTop = $("#hunt-log").scrollHeight;
}

function startHunt(topics) {
  if (huntStream) huntStream.close();
  $("#hunt-go").disabled = true;
  $("#hunt-go").textContent = "Hunting";
  $("#hunt-trace").hidden = false;
  $("#hunt-title").textContent = `Hunting ${topics} topic${topics === 1 ? "" : "s"}`;
  $("#hunt-stage").textContent = "";
  $("#hunt-log").replaceChildren();

  huntStream = new EventSource(`/api/scamscan/hunt?topics=${topics}`);

  huntStream.addEventListener("start", (ev) => {
    const d = JSON.parse(ev.data);
    $("#hunt-stage").textContent =
      `${d.model} · ${d.tool} · structured ${d.structured ? "on" : "off"}`;
  });
  huntStream.addEventListener("topic", (ev) => {
    logLine("log-topic", JSON.parse(ev.data).topic);
  });
  huntStream.addEventListener("query", (ev) => {
    logLine("log-query", JSON.parse(ev.data).query);
  });
  huntStream.addEventListener("finding", (ev) => {
    const d = JSON.parse(ev.data);
    logLine("log-find",
      `${d.new ? "NEW" : "dup"} ${Math.round(d.score)}  ${d.url.slice(0, 68)}`,
      d.title);
  });
  huntStream.addEventListener("note", (ev) => {
    logLine("log-note", JSON.parse(ev.data).message);
  });
  // A query that could not be searched is not a query that found nothing.
  // It gets its own colour so it can never be read as a clean result.
  huntStream.addEventListener("unsearched", (ev) => {
    const d = JSON.parse(ev.data);
    logLine("log-fail", `NOT SEARCHED: ${d.query || d.topic} — ${d.reason}`);
  });
  huntStream.addEventListener("done", (ev) => {
    finishHunt();
    huntSummary(JSON.parse(ev.data));
    loadQueue();
  });
  huntStream.addEventListener("failed", (ev) => {
    finishHunt();
    logLine("log-fail", `The hunt stopped: ${JSON.parse(ev.data).message}`);
  });
  huntStream.onerror = () => {
    if (!$("#hunt-go").disabled) return;
    finishHunt();
    logLine("log-fail", "Lost the connection to the server.");
  };
}

$("#cancel-hunt").onclick = () => {
  if (!huntStream) return;
  huntStream.close();
  huntStream = null;
  finishHunt();
  logLine("log-fail", "UPDATES STOPPED — provider requests already sent may still finish or incur cost.");
};

function finishHunt() {
  if (huntStream) { huntStream.close(); huntStream = null; }
  $("#hunt-go").disabled = !scam.api_available ? true : false;
  $("#hunt-go").textContent = "Run hunt";
}

function huntSummary(d) {
  const n = d.seen || 0;
  $("#hunt-stage").textContent =
    `${n} finding${n === 1 ? "" : "s"}, ${d.new || 0} new, ${d.escalated || 0} at escalate`;
  if (d.structured_disabled) {
    logLine("log-note",
      "Structured outputs were rejected — this run parsed model text instead.",
      d.structured_disabled);
  }
  const failures = d.failures || [];
  if (failures.length) {
    logLine("log-fail",
      `INCOMPLETE RUN — ${failures.length} of ${(d.queries_run || 0) + failures.length} queries did not search`);
    failures.slice(0, 8).forEach((f) => logLine("log-fail", f));
    if (!n) {
      logLine("log-fail", "Zero findings here does NOT mean the brand is clean.");
    }
  } else if (!d.queries_run) {
    logLine("log-fail", "No queries ran at all — check the config and API key.");
  }
}

/* ----------------------------------------------------------------- score */

$("#score-form").onsubmit = async (e) => {
  e.preventDefault();
  const out = $("#score-out");
  out.replaceChildren(el("p", "hint", "Scoring…"));
  try {
    const r = await fetch("/api/scamscan/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: $("#score-text").value, url: $("#score-url").value.trim(),
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      out.replaceChildren(el("p", "errs", d.detail || "Could not score that."));
      return;
    }
    out.replaceChildren(scoreCard(d));
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
};

function scoreCard(d) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[d.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(d.band), el("span", "score", Math.round(d.score)));
  const verdict =
    d.score >= d.escalate_threshold ? "escalate now"
    : d.score >= d.review_threshold ? "needs review"
    : "below the review threshold";
  top.append(el("span", "flag", verdict));
  c.append(top);

  c.append(familyBars(d));
  // Which families the average was taken over. The whole absent-vs-zero
  // argument is invisible unless the page says which ones reported.
  c.append(el("p", "reason",
    `averaged over: ${(d.scored_on || []).join(", ") || "nothing"}`));

  if (d.lexicon_hits?.length) c.append(hitList(d.lexicon_hits));
  else c.append(el("p", "hint", "No lexicon terms matched."));

  if (d.impersonation_reason) {
    c.append(el("p", "reason", `host: ${d.impersonation_reason}`));
  }
  const artifacts = Object.entries(d.artifacts || {});
  if (artifacts.length) {
    const tags = el("div", "tags");
    artifacts.forEach(([k, v]) => tags.append(el("span", "tag", `${k}: ${v.join(", ")}`)));
    c.append(tags);
  }
  return c;
}

init();
initScamscan();
openHashView();
