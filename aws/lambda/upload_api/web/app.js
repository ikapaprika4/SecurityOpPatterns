"use strict";

// The upload page: ask the API for a pre-signed upload, send the file straight
// to S3, then ask about the job until it is done or has failed.
//
// Everything the server sends is put on the page as text, never as HTML: a
// report quotes whatever was in the uploaded log.

const POLL_MS = 3000;
const START_TIMEOUT_MS = 6 * 60 * 1000;     // no status by then: the task never started
const TOTAL_TIMEOUT_MS = 25 * 60 * 1000;    // the task itself gives up after 15 minutes
const MAX_MISSED_POLLS = 5;
const EXTENSIONS = [".evtx", ".xml", ".json", ".jsonl", ".ndjson", ".txt", ".log"];
const STEPS = ["upload", "start", "analyse"];

const $ = (id) => document.getElementById(id);
const els = {
  form: $("form"), code: $("code"), file: $("file"), drop: $("drop"),
  dropTitle: $("dropTitle"), dropHint: $("dropHint"), submit: $("submit"),
  progress: $("progress"), bar: $("bar"), status: $("status"),
  steps: [$("stepUpload"), $("stepStart"), $("stepAnalyse")],
  error: $("error"), retry: $("retry"),
  result: $("result"), verdict: $("verdict"), summary: $("summary"), report: $("report"),
  download: $("download"), again: $("again"),
};
const defaults = {title: els.dropTitle.textContent, hint: els.dropHint.textContent};

let chosen = null;      // the File to upload
let job = null;         // the job in progress: {id, uploadedAt, misses, timer}
let finished = null;    // the id of the job whose report is on the page

function problem(message, status) {
  return Object.assign(new Error(message), {status: status});
}

function readable(bytes) {
  if (bytes < 1024) return bytes + " bytes";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function showError(message) {
  els.error.textContent = message;
  els.error.hidden = false;
}

function hideError() {
  els.error.hidden = true;
  els.retry.hidden = true;
}

function ready() {
  els.submit.disabled = Boolean(job) || !chosen || !els.code.value.trim();
}

function lock(on) {
  els.code.disabled = on;
  els.file.disabled = on;
}

function choose(file) {
  if (job || !file) return;
  hideError();
  const dot = file.name.lastIndexOf(".");
  const extension = dot < 0 ? "" : file.name.slice(dot).toLowerCase();
  chosen = null;
  if (!EXTENSIONS.includes(extension)) {
    showError("That is not a Windows event log this service can read. Choose one of: " + EXTENSIONS.join(", ") + ".");
  } else if (file.size === 0) {
    showError("That file is empty.");
  } else {
    chosen = file;
  }
  els.drop.classList.toggle("has-file", Boolean(chosen));
  els.dropTitle.textContent = chosen ? chosen.name : defaults.title;
  els.dropHint.textContent = chosen ? readable(chosen.size) + ". Choose or drop another file to replace it." : defaults.hint;
  ready();
}

function step(name, text, fraction) {
  const at = STEPS.indexOf(name);
  els.steps.forEach((el, i) => {
    el.classList.toggle("done", i < at);
    el.classList.toggle("now", i === at);
  });
  if (fraction === undefined) els.bar.removeAttribute("value");      // no value: "busy"
  else els.bar.value = Math.round(fraction * 100);
  els.status.textContent = text;
}

async function api(method, path, body) {
  const code = els.code.value.trim();
  if (!/^[\x21-\x7e]+$/.test(code)) throw problem("The access code is missing or wrong.", 401);
  const options = {method: method, headers: {"X-Access-Code": code}, cache: "no-store"};
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (err) {
    throw problem("The server could not be reached. Check your connection and try again.", 0);
  }
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }
  if (!response.ok) {
    const said = data && typeof data.error === "string" ? data.error : "";
    throw problem(said || "The server answered with an error (" + response.status + ").", response.status);
  }
  if (!data) throw problem("The server sent an answer this page does not understand.", response.status);
  return data;
}

function uploadError(xhr) {
  const code = (/<Code>([^<]+)<\/Code>/.exec(xhr.responseText || "") || [])[1] || "";
  if (code === "EntityTooLarge") return "The file is too large.";
  if (code === "EntityTooSmall") return "The file is empty.";
  if (xhr.status === 403) return "The upload was refused, most likely because it took too long to start. Try again.";
  return "The upload failed (" + xhr.status + (code ? ", " + code : "") + "). Try again.";
}

function upload(url, fields, file, onProgress) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    Object.keys(fields).forEach((name) => form.append(name, fields[name]));
    form.append("file", file);              // last: S3 ignores every field after the file
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(problem(uploadError(xhr), xhr.status));
    });
    xhr.addEventListener("error", () => {
      reject(problem("The upload did not go through. Check your connection and try again.", 0));
    });
    xhr.addEventListener("abort", () => reject(problem("The upload was cancelled.", 0)));
    xhr.send(form);
  });
}

function fail(message) {
  if (job && job.timer) window.clearTimeout(job.timer);
  job = null;
  els.progress.hidden = true;
  lock(false);
  showError(message);
  els.retry.hidden = !chosen;
  ready();
}

function finish(view) {
  const findings = Boolean(view.high_or_critical_findings);
  finished = job.id;
  job = null;
  els.progress.hidden = true;
  els.verdict.textContent = findings ? "High or critical findings" : "No high or critical findings";
  els.verdict.classList.toggle("findings", findings);
  els.summary.textContent =
    (findings
      ? "The log contains activity that needs attention."
      : "Nothing rated high or critical was found. Lower-rated findings, if there are any, are in the report.") +
    (view.report ? " The full report is below." : " The report is too large to show here; download it instead.");
  els.report.textContent = view.report || "";
  els.report.hidden = !view.report;
  els.result.hidden = false;
  lock(false);
  ready();
}

function schedule() {
  job.timer = window.setTimeout(poll, POLL_MS);
}

async function poll() {
  const mine = job;                         // the page can move on while an answer is on its way
  let view;
  try {
    view = await api("GET", "api/jobs/" + mine.id);
  } catch (err) {
    if (job !== mine) return;
    const worthAsking = err.status === 0 || err.status === 429 || err.status >= 500;
    mine.misses += 1;
    if (!worthAsking || mine.misses > MAX_MISSED_POLLS) fail(err.message);
    else schedule();
    return;
  }
  if (job !== mine) return;
  mine.misses = 0;
  const waited = Date.now() - mine.uploadedAt;
  if (view.state === "done") {
    finish(view);
  } else if (view.state === "failed") {
    fail(view.error || "The analysis failed.");
  } else if (view.state === "queued" && waited > START_TIMEOUT_MS) {
    fail("The analysis did not start. Please try again in a few minutes.");
  } else if (waited > TOTAL_TIMEOUT_MS) {
    fail("The analysis took too long and was given up on. Please try again.");
  } else {
    if (view.state === "running") step("analyse", "Analysing the log…");
    schedule();
  }
}

async function run() {
  if (job || !chosen) return;
  const file = chosen;
  hideError();
  els.result.hidden = true;
  finished = null;
  job = {id: null, uploadedAt: 0, misses: 0, timer: 0};
  const mine = job;
  lock(true);
  ready();
  els.progress.hidden = false;
  step("upload", "Preparing the upload…", 0);
  try {
    const made = await api("POST", "api/uploads", {filename: file.name, size: file.size});
    mine.id = made.job_id;
    await upload(made.upload.url, made.upload.fields, file, (part) => {
      step("upload", "Uploading " + file.name + ": " + Math.round(part * 100) + "%", part);
    });
  } catch (err) {
    fail(err.message);
    return;
  }
  mine.uploadedAt = Date.now();
  step("start", "Uploaded. Waiting for the analysis to start, which usually takes about a minute.");
  schedule();
}

async function download() {
  if (!finished) return;
  els.download.disabled = true;
  try {
    // A download link is only valid for a few minutes, so ask for a fresh one.
    const view = await api("GET", "api/jobs/" + finished);
    if (!view.download_url) throw problem("The report is no longer available.", 0);
    window.location.assign(view.download_url);
  } catch (err) {
    showError(err.message);
  } finally {
    els.download.disabled = false;
  }
}

function reset() {
  finished = null;
  chosen = null;
  els.file.value = "";
  els.result.hidden = true;
  els.report.textContent = "";
  els.drop.classList.remove("has-file");
  els.dropTitle.textContent = defaults.title;
  els.dropHint.textContent = defaults.hint;
  hideError();
  ready();
  els.file.focus();
}

function codeFromLink() {
  // A link can carry the access code after "#". That part of an address is
  // never sent to a server; take it out of the address bar once it is read.
  const inLink = /(?:^#|&)code=([^&]+)/.exec(window.location.hash);
  if (!inLink || job) return;
  try {
    els.code.value = decodeURIComponent(inLink[1]);
  } catch (err) {
    els.code.value = "";
  }
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
  ready();
}

function init() {
  codeFromLink();
  window.addEventListener("hashchange", codeFromLink);    // the link opened in a tab that already shows the page

  els.code.addEventListener("input", ready);
  els.file.addEventListener("change", () => choose(els.file.files[0]));
  ["dragenter", "dragover"].forEach((type) => els.drop.addEventListener(type, (event) => {
    event.preventDefault();
    els.drop.classList.add("over");
  }));
  ["dragleave", "drop"].forEach((type) => els.drop.addEventListener(type, () => els.drop.classList.remove("over")));
  els.drop.addEventListener("drop", (event) => {
    event.preventDefault();
    choose(event.dataTransfer && event.dataTransfer.files[0]);
  });
  // A file dropped beside the box must not make the browser open it.
  ["dragover", "drop"].forEach((type) => window.addEventListener(type, (event) => event.preventDefault()));

  els.form.addEventListener("submit", (event) => {
    event.preventDefault();
    run();
  });
  els.retry.addEventListener("click", run);
  els.again.addEventListener("click", reset);
  els.download.addEventListener("click", download);
  ready();
}

init();
