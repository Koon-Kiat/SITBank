import assert from "node:assert/strict";
import fs from "node:fs";
import inspector from "node:inspector";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const browserScripts = [
  "app/static/js/account.js",
  "app/static/js/dashboard.js",
  "app/static/js/payees.js",
  "app/static/js/session-timeout.js",
  "app/static/js/theme.js",
];

class MockClassList {
  constructor(...names) {
    this.names = new Set(names);
  }

  add(name) {
    this.names.add(name);
  }

  remove(name) {
    this.names.delete(name);
  }

  contains(name) {
    return this.names.has(name);
  }

  toggle(name, force) {
    const enabled = force === undefined ? !this.names.has(name) : Boolean(force);
    if (enabled) this.names.add(name);
    else this.names.delete(name);
    return enabled;
  }
}

class MockElement {
  constructor({ id = "", attributes = {}, classes = [] } = {}) {
    this.id = id;
    this.attributes = new Map(Object.entries(attributes));
    this.classList = new MockClassList(...classes);
    this.dataset = {};
    this.listeners = new Map();
    this.selectorMap = new Map();
    this.selectorAllMap = new Map();
    this.style = {};
    this.children = [];
    this.hidden = false;
    this.open = false;
    this.disabled = false;
    this.removed = false;
    this.textContent = "";
    this.value = "";
    this.type = "";
    this.tagName = "DIV";
    for (const [name, value] of this.attributes) {
      if (name.startsWith("data-")) this.dataset[toDatasetKey(name)] = value;
    }
  }

  addEventListener(type, callback) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(callback);
    this.listeners.set(type, listeners);
  }

  async emit(type, event = {}) {
    const normalized = {
      key: "",
      preventDefault() {
        this.defaultPrevented = true;
      },
      target: this,
      ...event,
    };
    for (const callback of this.listeners.get(type) || []) {
      await callback(normalized);
    }
    return normalized;
  }

  setAttribute(name, value) {
    const text = String(value);
    this.attributes.set(name, text);
    if (name.startsWith("data-")) this.dataset[toDatasetKey(name)] = text;
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  querySelector(selector) {
    return this.selectorMap.get(selector) ?? null;
  }

  querySelectorAll(selector) {
    return this.selectorAllMap.get(selector) ?? [];
  }

  closest(selector) {
    if (selector === ".alert") return this.alert ?? null;
    if (selector === "[data-account-menu]") return this.accountMenu ?? null;
    if (selector === "a" && this.tagName === "A") return this;
    return null;
  }

  appendChild(child) {
    this.children.push(child);
    child.parentNode = this;
    return child;
  }

  remove() {
    this.removed = true;
  }

  showModal() {
    this.open = true;
  }

  close() {
    this.open = false;
  }

  click() {
    return this.emit("click");
  }

  focus() {
    this.focused = true;
  }

  select() {
    this.selected = true;
  }
}

class MockDocument extends MockElement {
  constructor() {
    super();
    this.documentElement = new MockElement();
    this.body = new MockElement();
    this.idMap = new Map();
    this.activeElement = null;
  }

  getElementById(id) {
    return this.idMap.get(id) ?? null;
  }

  createElement(tagName) {
    const element = new MockElement();
    element.tagName = tagName.toUpperCase();
    return element;
  }

  execCommand(command) {
    return command === "copy";
  }
}

function toDatasetKey(name) {
  return name
    .slice(5)
    .replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

function createBrowserContext(document) {
  const domReadyListeners = [];
  const timeoutCallbacks = [];
  const intervalCallbacks = [];
  let timerId = 0;
  const context = {
    Array,
    Blob: class MockBlob {
      constructor(parts, options) {
        this.parts = parts;
        this.type = options?.type || "";
      }
    },
    Date,
    Error,
    JSON,
    Math,
    Number,
    Object,
    Promise,
    String,
    URL: {
      createObjectURL() {
        return "blob:test";
      },
      revokeObjectURL() {},
    },
    clearInterval() {},
    clearTimeout() {},
    console,
    document,
    fetch: async () => ({
      ok: true,
      async json() {
        return { timeout_seconds: 180 };
      },
    }),
    location: {
      href: "",
      reloadCount: 0,
      reload() {
        this.reloadCount += 1;
      },
    },
    localStorage: {
      values: new Map(),
      getItem(key) {
        return this.values.get(key) ?? null;
      },
      setItem(key, value) {
        this.values.set(key, value);
      },
    },
    matchMedia() {
      return { matches: true };
    },
    navigator: {
      clipboard: {
        async writeText(text) {
          context.copiedText = text;
        },
      },
    },
    setInterval(callback) {
      intervalCallbacks.push(callback);
      timerId += 1;
      return timerId;
    },
    setTimeout(callback) {
      timeoutCallbacks.push(callback);
      timerId += 1;
      return timerId;
    },
    addEventListener(type, callback) {
      if (type === "DOMContentLoaded") domReadyListeners.push(callback);
    },
  };
  context.globalThis = context;
  context.window = context;
  context.__domReadyListeners = domReadyListeners;
  context.__timeoutCallbacks = timeoutCallbacks;
  context.__intervalCallbacks = intervalCallbacks;
  return vm.createContext(context);
}

function runScript(relativePath, context) {
  const absolutePath = path.join(repositoryRoot, relativePath);
  const source = fs.readFileSync(absolutePath, "utf8");
  vm.runInContext(source, context, { filename: absolutePath });
}

async function exerciseAccount() {
  const document = new MockDocument();
  const alert = new MockElement({ classes: ["alert", "alert-success"] });
  const dismiss = new MockElement();
  dismiss.alert = alert;
  const passwordInput = new MockElement({ id: "password" });
  passwordInput.type = "password";
  const passwordToggle = new MockElement({
    attributes: { "data-password-toggle": "password" },
  });
  const missingPasswordToggle = new MockElement({
    attributes: { "data-password-toggle": "missing-password" },
  });
  const strengthInput = new MockElement({
    attributes: { "data-password-strength-input": "primary" },
  });
  const missingStrengthInput = new MockElement({
    attributes: { "data-password-strength-input": "missing" },
  });
  strengthInput.value = "LongPasswordValue123!";
  const strengthMeter = new MockElement();
  const recoveryList = new MockElement();
  const recoveryCode = new MockElement();
  recoveryCode.textContent = "abcd-efgh";
  recoveryList.selectorAllMap.set("[data-recovery-code]", [recoveryCode]);
  const recoveryStatus = new MockElement();
  const copyButton = new MockElement();
  const downloadButton = new MockElement();

  document.idMap.set("password", passwordInput);
  document.selectorAllMap.set("[data-alert-dismiss]", [dismiss]);
  document.selectorAllMap.set(
    "[data-password-toggle]",
    [passwordToggle, missingPasswordToggle],
  );
  document.selectorAllMap.set(
    "[data-password-strength-input]",
    [strengthInput, missingStrengthInput],
  );
  document.selectorAllMap.set("[data-recovery-code-list]", [recoveryList]);
  document.selectorMap.set('[data-password-strength="primary"]', strengthMeter);
  document.selectorMap.set("[data-recovery-code-status]", recoveryStatus);
  document.selectorMap.set("[data-copy-recovery-codes]", copyButton);
  document.selectorMap.set("[data-download-recovery-codes]", downloadButton);

  const context = createBrowserContext(document);
  runScript("app/static/js/account.js", context);
  for (const callback of context.__domReadyListeners) callback();
  await dismiss.emit("click");
  for (const callback of context.__timeoutCallbacks) callback();
  await passwordToggle.emit("click");
  await missingPasswordToggle.emit("click");
  for (const value of ["", "short", "LongPassword123", "LongPasswordValue123!"]) {
    strengthInput.value = value;
    await strengthInput.emit("input");
  }
  await copyButton.emit("click");
  await Promise.resolve();
  await Promise.resolve();
  context.navigator.clipboard.writeText = async () => {
    throw new Error("clipboard denied");
  };
  await copyButton.emit("click");
  await Promise.resolve();
  await Promise.resolve();
  context.navigator.clipboard = null;
  await copyButton.emit("click");
  recoveryCode.textContent = "";
  await copyButton.emit("click");
  await downloadButton.emit("click");
  recoveryCode.textContent = "abcd-efgh";
  await downloadButton.emit("click");

  assert.equal(passwordInput.type, "text");
  assert.match(strengthMeter.textContent, /Password strength:/);
  assert.equal(context.copiedText, "abcd-efgh");
  assert.equal(downloadButton.listeners.has("click"), true);
}

async function exerciseDashboard() {
  const document = new MockDocument();
  for (const id of ["button", "masked", "full", "icon"]) {
    document.idMap.set(id, new MockElement({ id }));
  }
  document.idMap.get("full").hidden = true;
  const context = createBrowserContext(document);
  const sourcePath = "app/static/js/dashboard.js";
  const source = fs
    .readFileSync(path.join(repositoryRoot, sourcePath), "utf8")
    .replace(
      "makeToggle('bal-eye-btn',  'card-balance-masked', 'card-balance-full', 'bal-eye-icon'",
      "makeToggle('button', 'masked', 'full', 'icon'",
    )
    .replace(
      "makeToggle('acct-eye-btn', 'card-acct-masked',   'card-acct-full',   'acct-eye-icon'",
      "makeToggle('missing', 'missing', 'missing', 'missing'",
    );
  vm.runInContext(source, context, {
    filename: path.join(repositoryRoot, sourcePath),
  });
  await document.idMap.get("button").emit("click");
  assert.equal(document.idMap.get("full").hidden, false);
}

async function exercisePayees() {
  const document = new MockDocument();
  const badge = new MockElement();
  badge.dataset.cooldownExpires = new Date(Date.now() + 120_000).toISOString();
  document.selectorAllMap.set("[data-cooldown-expires]", [badge]);
  const context = createBrowserContext(document);
  runScript("app/static/js/payees.js", context);
  badge.dataset.cooldownExpires = new Date(Date.now() - 1_000).toISOString();
  for (const callback of context.__intervalCallbacks) callback();
  document.selectorAllMap.set("[data-cooldown-expires]", []);
  for (const callback of context.__intervalCallbacks) callback();
  assert.match(badge.textContent, /Available in/);
  assert.equal(context.location.reloadCount, 1);
}

async function exerciseSessionTimeout() {
  const document = new MockDocument();
  const meta = new MockElement({ attributes: { content: "120" } });
  const csrf = new MockElement({ attributes: { content: "csrf-value" } });
  const overlay = new MockElement({ id: "session-timeout-overlay" });
  const countdown = new MockElement({ id: "session-timeout-countdown" });
  const continueButton = new MockElement({ id: "session-continue-btn" });
  const timer = new MockElement({ id: "session-timer" });
  const timerValue = new MockElement({ id: "session-timer-value" });
  document.selectorMap.set('meta[name="session-timeout"]', meta);
  document.selectorMap.set('meta[name="csrf-token"]', csrf);
  for (const element of [overlay, countdown, continueButton, timer, timerValue]) {
    document.idMap.set(element.id, element);
  }
  const context = createBrowserContext(document);
  runScript("app/static/js/session-timeout.js", context);
  for (const callback of context.__timeoutCallbacks) callback();
  for (const callback of [...context.__intervalCallbacks]) callback();
  for (let index = 0; index < 65; index += 1) {
    for (const callback of [...context.__intervalCallbacks]) callback();
  }
  await continueButton.emit("click");
  await new Promise((resolve) => setTimeout(resolve, 0));
  context.fetch = async () => ({ ok: false });
  await continueButton.emit("click");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(continueButton.disabled, false);
  assert.match(timerValue.textContent, /^\d+:\d{2}$/);
}

async function exerciseTheme() {
  const document = new MockDocument();
  const toggle = new MockElement();
  const label = new MockElement();
  const icon = new MockElement();
  const iconUse = new MockElement();
  icon.selectorMap.set("use", iconUse);
  const navToggle = new MockElement();
  const navMenu = new MockElement();
  const accountMenu = new MockElement();
  const accountTrigger = new MockElement();
  const accountPanel = new MockElement();
  const accountItemOne = new MockElement();
  const accountItemTwo = new MockElement();
  accountPanel.selectorAllMap.set("a, button", [accountItemOne, accountItemTwo]);
  const selectorElements = {
    "[data-theme-toggle]": toggle,
    "[data-theme-toggle-label]": label,
    "[data-theme-toggle-icon]": icon,
    "[data-nav-toggle]": navToggle,
    "[data-nav-menu]": navMenu,
    "[data-account-menu]": accountMenu,
    "[data-account-trigger]": accountTrigger,
    "[data-account-panel]": accountPanel,
  };
  for (const [selector, element] of Object.entries(selectorElements)) {
    document.selectorMap.set(selector, element);
  }

  const context = createBrowserContext(document);
  runScript("app/static/js/theme.js", context);
  for (const callback of context.__domReadyListeners) callback();
  await toggle.emit("click");
  await navToggle.emit("click");
  await navMenu.emit("click", { target: Object.assign(new MockElement(), { tagName: "A" }) });
  await accountTrigger.emit("click");
  for (const key of ["Enter", " ", "ArrowDown"]) {
    await accountTrigger.emit("keydown", { key });
  }
  for (const key of ["Escape", "ArrowDown", "ArrowUp", "Home", "End"]) {
    document.activeElement = accountItemOne;
    await accountPanel.emit("keydown", { key });
  }
  const link = Object.assign(new MockElement(), { tagName: "A" });
  await accountPanel.emit("click", { target: link });
  await accountPanel.emit("click", { target: {} });
  accountPanel.selectorAllMap.set("a, button", []);
  await accountTrigger.emit("keydown", { key: "ArrowDown" });
  await document.emit("click", { target: new MockElement() });
  await document.emit("keydown", { key: "Escape" });

  assert.equal(document.documentElement.dataset.theme, "light");
  assert.equal(label.textContent, "Switch to dark mode");

  const noToggleDocument = new MockDocument();
  const noToggleContext = createBrowserContext(noToggleDocument);
  runScript("app/static/js/theme.js", noToggleContext);
  for (const callback of noToggleContext.__domReadyListeners) callback();

  const incompleteMenuDocument = new MockDocument();
  const incompleteToggle = new MockElement();
  const incompleteTrigger = new MockElement();
  const incompletePanel = new MockElement();
  incompleteMenuDocument.selectorMap.set("[data-theme-toggle]", incompleteToggle);
  incompleteMenuDocument.selectorMap.set("[data-account-trigger]", incompleteTrigger);
  incompleteMenuDocument.selectorMap.set("[data-account-panel]", incompletePanel);
  const incompleteContext = createBrowserContext(incompleteMenuDocument);
  incompleteContext.localStorage.setItem("sitbank-theme", "light");
  runScript("app/static/js/theme.js", incompleteContext);
  for (const callback of incompleteContext.__domReadyListeners) callback();
  await incompleteTrigger.emit("keydown", { key: "ArrowDown" });
}

function post(session, method, params = {}) {
  return new Promise((resolve, reject) => {
    session.post(method, params, (error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}

function lineOffsets(source) {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") offsets.push(index + 1);
  }
  return offsets;
}

function coverageForScript(source, entries) {
  const ranges = entries.flatMap((entry) =>
    entry.functions.flatMap((func) => func.ranges),
  );
  const offsets = lineOffsets(source);
  const coverage = new Map();
  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const content = lines[index];
    const firstToken = content.search(/\S/);
    if (firstToken < 0 || content.trim().startsWith("//")) continue;
    const offset = offsets[index] + firstToken;
    const candidates = ranges.filter(
      (range) => range.startOffset <= offset && offset < range.endOffset,
    );
    if (!candidates.length) continue;
    candidates.sort(
      (left, right) =>
        left.endOffset - left.startOffset - (right.endOffset - right.startOffset),
    );
    coverage.set(index + 1, candidates[0].count);
  }
  return coverage;
}

function writeLcov(coverageEntries) {
  const byPath = new Map();
  for (const entry of coverageEntries) {
    const entryPath = entry.url.startsWith("file:") ? fileURLToPath(entry.url) : entry.url;
    const normalizedUrl = path.normalize(entryPath);
    const relativePath = browserScripts.find(
      (candidate) =>
        normalizedUrl === path.normalize(path.join(repositoryRoot, candidate)),
    );
    if (!relativePath) continue;
    const source = fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8");
    const current = byPath.get(relativePath) || new Map();
    for (const [line, count] of coverageForScript(source, [entry])) {
      current.set(line, Math.max(current.get(line) || 0, count));
    }
    byPath.set(relativePath, current);
  }

  const output = [];
  let covered = 0;
  let total = 0;
  for (const relativePath of browserScripts) {
    const lines = byPath.get(relativePath);
    assert.ok(
      lines,
      `No V8 coverage collected for ${relativePath}; collected URLs: ${coverageEntries
        .map((entry) => entry.url)
        .filter(Boolean)
        .join(", ")}`,
    );
    output.push("TN:", `SF:${relativePath.replaceAll("\\", "/")}`);
    for (const [line, count] of [...lines].sort(([left], [right]) => left - right)) {
      output.push(`DA:${line},${count}`);
      covered += Number(count > 0);
      total += 1;
    }
    output.push("end_of_record");
  }
  const outputDirectory = path.join(repositoryRoot, "coverage");
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(path.join(outputDirectory, "lcov.info"), `${output.join("\n")}\n`);
  const percentage = total ? (covered / total) * 100 : 0;
  assert.ok(
    percentage >= 80,
    `Browser script line coverage ${percentage.toFixed(1)}% is below 80%`,
  );
  console.log(`Browser script line coverage: ${percentage.toFixed(1)}% (${covered}/${total})`);
}

const session = new inspector.Session();
session.connect();
await post(session, "Profiler.enable");
await post(session, "Profiler.startPreciseCoverage", {
  callCount: true,
  detailed: true,
});

await exerciseAccount();
await exerciseDashboard();
await exercisePayees();
await exerciseSessionTimeout();
await exerciseTheme();

const { result } = await post(session, "Profiler.takePreciseCoverage");
await post(session, "Profiler.stopPreciseCoverage");
session.disconnect();
writeLcov(result);
