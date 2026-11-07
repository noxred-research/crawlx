//! Scripts run in the isolated world `crawlx` (never in the page's main world).
//! None of them needs `Runtime.enable`: they run through `Runtime.evaluate { contextId }`
//! and `Runtime.callFunctionOn { objectId }`.

/// Name of the isolated world.
pub const WORLD_NAME: &str = "crawlx";

/// Installs the `MutationObserver`; idempotent per document. Counters are cumulative.
///
/// Records are attributed to a target element (a text node counts for its parent). A target is
/// *volatile* when it sits inside an `aria-live` region or `timer`/`log`/`status`/
/// `marquee` role, or when it mutated at least three times with a near-regular interval
/// (coefficient of variation of the last eight inter-mutation gaps below 0.3). Mutations on
/// volatile targets are counted apart (`volatile`) and never move the `stable` clock the settle
/// loop reads, so a ticker cannot keep a page from going idle.
pub const OBSERVER: &str = r#"(() => {
  if (window.__crawlx) { return 1; }
  const RECENT_MS = 2000, KEEP = 8, MAX_VOLATILE = 256;
  const c = { records: 0, added: 0, removed: 0, attrs: 0, text: 0, stable: 0, volatile: 0 };
  const states = new WeakMap();
  const volatileStates = [];
  let lastStable = -1;
  const LIVE_ROLES = '[role=timer],[role=log],[role=status],[role=marquee]';
  const isLive = (el) => {
    const live = el.closest('[aria-live]');
    if (live) { const v = (live.getAttribute('aria-live') || '').trim().toLowerCase(); if (v && v !== 'off') { return true; } }
    return !!el.closest(LIVE_ROLES);
  };
  const isPeriodic = (ts) => {
    if (ts.length < 3) { return false; }
    const gaps = [];
    for (let i = 1; i < ts.length; i++) { gaps.push(ts[i] - ts[i - 1]); }
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (!(mean > 0)) { return false; }
    const variance = gaps.reduce((a, g) => a + (g - mean) * (g - mean), 0) / gaps.length;
    return Math.sqrt(variance) / mean < 0.3;
  };
  const elementOf = (n) => {
    if (!n) { return null; }
    if (n.nodeType === 1) { return n; }
    return n.parentElement || (n.parentNode && n.parentNode.host) || null;
  };
  const tick = (el, now) => {
    let st = states.get(el);
    if (!st) { st = { ts: [], volAt: -1, listed: false }; states.set(el, st); }
    st.ts.push(now);
    if (st.ts.length > KEEP) { st.ts.shift(); }
    const vol = isLive(el) || isPeriodic(st.ts);
    if (vol) {
      st.volAt = now;
      if (!st.listed) {
        st.listed = true;
        volatileStates.push(st);
        if (volatileStates.length > MAX_VOLATILE) { volatileStates.shift().listed = false; }
      }
    }
    return vol;
  };
  const take = (list) => {
    const now = performance.now();
    const verdicts = new Map();
    for (const r of list) {
      c.records++;
      if (r.type === 'childList') { c.added += r.addedNodes.length; c.removed += r.removedNodes.length; }
      else if (r.type === 'attributes') { c.attrs++; }
      else { c.text++; }
      const el = elementOf(r.target);
      let vol = false;
      if (el) {
        if (verdicts.has(el)) { vol = verdicts.get(el); }
        else { vol = tick(el, now); verdicts.set(el, vol); }
      }
      if (vol) { c.volatile++; } else { c.stable++; lastStable = now; }
    }
  };
  const mo = new MutationObserver(take);
  mo.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  const read = () => {
    take(mo.takeRecords());
    const now = performance.now();
    let recent = 0;
    for (const st of volatileStates) { if (now - st.volAt <= RECENT_MS) { recent++; } }
    return {
      records: c.records, added: c.added, removed: c.removed, attrs: c.attrs, text: c.text,
      stable: c.stable, volatile: c.volatile, volatile_recent: recent,
      stable_age_ms: lastStable < 0 ? null : Math.round(now - lastStable),
    };
  };
  Object.defineProperty(window, '__crawlx', {
    value: { c, read }, enumerable: false,
  });
  return 1;
})()"#;

/// Flushes pending records and returns the cumulative counters (`null` if not installed):
/// the record totals, the split into `stable` and `volatile` records, how many volatile targets
/// mutated in the last two seconds (`volatile_recent`) and the milliseconds since the last
/// stable mutation (`stable_age_ms`, `null` before the first one).
pub const READ_COUNTERS: &str = r#"(() => {
  const w = window.__crawlx;
  return w ? w.read() : null;
})()"#;

/// `this` = element. The next scroll the element needs, working outermost scroller first:
/// each scrollable ancestor must show the box of the scroller nested in
/// it (the element itself for the innermost one). Returns the first scroller that does not, as
/// the centre of its client box in main-frame viewport coordinates plus the wheel delta that
/// moves what it must show to that centre; `null` when no scrollable ancestor clips the element.
/// The page scroller (`<html>`/`<body>`) is not an ancestor here: the viewport wheel handles it.
pub const CLIPPING_SCROLLER: &str = r#"function () {
  const scrolls = (v) => v === 'auto' || v === 'scroll' || v === 'overlay';
  let ox = 0, oy = 0;
  try {
    let w = window;
    while (w !== w.top && w.frameElement) {
      const fe = w.frameElement, fr = fe.getBoundingClientRect();
      ox += fr.left + fe.clientLeft; oy += fr.top + fe.clientTop;
      w = w.parent;
    }
  } catch (e) { /* cross-origin parent: offsets stay as far as they were readable */ }
  const step = (n) => n.assignedSlot || n.parentElement || (n.parentNode && n.parentNode.host) || null;
  const scrollers = [], subjects = [];
  let subject = this.getBoundingClientRect();
  for (let n = step(this); n && n !== document.body && n !== document.documentElement; n = step(n)) {
    const cs = getComputedStyle(n);
    const sy = scrolls(cs.overflowY) && n.scrollHeight > n.clientHeight + 1;
    const sx = scrolls(cs.overflowX) && n.scrollWidth > n.clientWidth + 1;
    if (!sx && !sy) { continue; }
    scrollers.push({ n, sx, sy });
    subjects.push(subject);
    subject = n.getBoundingClientRect();
  }
  for (let i = scrollers.length - 1; i >= 0; i--) {
    const { n, sx, sy } = scrollers[i], er = subjects[i];
    const ex = er.left + er.width / 2, ey = er.top + er.height / 2;
    const r = n.getBoundingClientRect();
    const left = r.left + n.clientLeft, top = r.top + n.clientTop, w = n.clientWidth, h = n.clientHeight;
    const fitsX = er.width > w ? (ex >= left && ex <= left + w) : (er.left >= left - 0.5 && er.right <= left + w + 0.5);
    const fitsY = er.height > h ? (ey >= top && ey <= top + h) : (er.top >= top - 0.5 && er.bottom <= top + h + 0.5);
    if ((fitsX || !sx) && (fitsY || !sy)) { continue; }
    const cx = left + w / 2, cy = top + h / 2;
    return { x: ox + cx, y: oy + cy, dx: sx && !fitsX ? ex - cx : 0, dy: sy && !fitsY ? ey - cy : 0 };
  }
  return null;
}"#;

/// `this` = element. Centre it in every scroller (forced scroll; `DOM.scrollIntoViewIfNeeded`
/// leaves it flush against a viewport edge, where fixed bars and unrendered window margins hide it).
pub const CENTER_IN_VIEW: &str = r#"function () {
  this.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
  return true;
}"#;

/// `this` = element. Facts for revalidation plus the rect before and after two animation
/// frames (stability). Resolves after at most ~400 ms even if frames do not run.
pub const ELEMENT_FACTS: &str = r#"function () {
  const el = this;
  const rect = () => { const r = el.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; };
  const cs = getComputedStyle(el);
  const tag = el.localName;
  const attr = (n) => el.getAttribute(n);
  const formEl = tag === 'form' ? el : (el.form || null);
  const submitLike = tag === 'button' ? (attr('type') || 'submit').toLowerCase() === 'submit'
    : (tag === 'input' && ['submit', 'image'].includes((attr('type') || '').toLowerCase()));
  const attrs = {};
  for (const k of ['aria-expanded', 'aria-haspopup', 'aria-pressed']) {
    const v = attr(k); if (v !== null) { attrs[k] = v.toLowerCase(); }
  }
  if (tag === 'input' || tag === 'button') { attrs['type'] = (attr('type') || (tag === 'input' ? 'text' : 'submit')).toLowerCase(); }
  const formField = ['input', 'select', 'textarea'].includes(tag)
    && !['button', 'reset'].includes((attr('type') || '').toLowerCase());
  if (formEl && (submitLike || formField || tag === 'form')) {
    attrs['form-method'] = ((submitLike && attr('formmethod') !== null ? el.formMethod : formEl.method) || 'get').toLowerCase();
    attrs['form-action'] = submitLike && attr('formaction') !== null ? el.formAction : formEl.action;
  }
  // descendant text the way the DOM snapshot collapses it (whitespace-collapsed, 200 chars),
  // the name fallback of a node without an accessible name
  const text = Array.from((el.textContent || '').split(/\s+/).filter(Boolean).join(' ')).slice(0, 200).join('');
  // `href` as written, trimmed: the shape of the observed descriptor (`LiveTargetFacts::href`).
  // The kernel compares the two byte for byte, so the resolved `el.href` would make every
  // relative link look changed (`confirm.identity_changed`).
  const href = (tag === 'a' || tag === 'area') ? (attr('href') || '').trim() : '';
  const facts = {
    connected: el.isConnected,
    tag,
    text,
    visible: el.getClientRects().length > 0 && cs.visibility !== 'hidden' && cs.visibility !== 'collapse',
    pointerEvents: cs.pointerEvents,
    cursor: cs.cursor,
    disabled: !!el.disabled || attr('aria-disabled') === 'true' || (!!el.closest && !!el.closest('fieldset[disabled]') && 'disabled' in el),
    href: href || null,
    attrs,
  };
  const r1 = rect();
  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (done) { return; } done = true; facts.rect1 = r1; facts.rect2 = rect(); resolve(facts); };
    requestAnimationFrame(() => requestAnimationFrame(finish));
    setTimeout(finish, 400);
  });
}"#;

/// `this` = candidate target, argument = hit element: is the hit the target, a descendant
/// (through slots and shadow hosts), or the target's label/control pair?
pub const IS_WITHIN: &str = r#"function (hit) {
  let n = hit, guard = 0;
  while (n && guard++ < 500) {
    if (n === this) { return true; }
    n = n.assignedSlot || n.parentNode || n.host;
  }
  if (this.labels && Array.prototype.includes.call(this.labels, hit)) { return true; }
  if (hit.control === this) { return true; }
  const l = hit.closest && hit.closest('label');
  return !!(l && l.control === this);
}"#;

/// `this` = element. Current checked/selected state for checkbox-like controls.
pub const CHECKED_STATE: &str = r#"function () {
  if (typeof this.checked === 'boolean') { return this.checked; }
  const a = this.getAttribute('aria-checked');
  return a === 'true';
}"#;

/// `this` = range-like element. Value, bounds and step.
pub const RANGE_STATE: &str = r#"function () {
  const num = (v, d) => { const n = parseFloat(v); return Number.isFinite(n) ? n : d; };
  const aria = this.getAttribute('aria-valuenow') !== null;
  if (aria) {
    return { value: num(this.getAttribute('aria-valuenow'), 0), min: num(this.getAttribute('aria-valuemin'), 0),
             max: num(this.getAttribute('aria-valuemax'), 100), step: 1 };
  }
  return { value: num(this.value, 0), min: num(this.min, 0), max: num(this.max, 100), step: num(this.step, 1) || 1 };
}"#;

/// `this` = `<select>`. Index of the option matching `{value|label|index}`, else -1.
pub const SELECT_INDEX: &str = r#"function (key) {
  const opts = Array.from(this.options || []);
  if ('index' in key) { return key.index >= 0 && key.index < opts.length ? key.index : -1; }
  if ('value' in key) { return opts.findIndex((o) => o.value === key.value); }
  const norm = (s) => (s || '').replace(/\s+/g, ' ').trim();
  return opts.findIndex((o) => norm(o.label || o.textContent) === norm(key.label));
}"#;

/// `this` = `<select>`: selected index and whether it is a multi-select.
pub const SELECT_STATE: &str = r#"function () {
  return { selected: this.selectedIndex, multiple: !!this.multiple, isSelect: this.localName === 'select' };
}"#;

/// Find a visible `[role=option]` (custom listbox) matching `{value|label|index}`; returns the element.
pub const FIND_ROLE_OPTION: &str = r#"function (key) {
  const visible = (e) => e.getClientRects().length > 0;
  const opts = Array.from(document.querySelectorAll('[role="option"], [role="menuitemradio"], [role="menuitem"]')).filter(visible);
  const norm = (s) => (s || '').replace(/\s+/g, ' ').trim();
  if ('index' in key) { return opts[key.index] || null; }
  if ('value' in key) {
    return opts.find((o) => o.getAttribute('data-value') === key.value || o.getAttribute('value') === key.value || o.id === key.value) || null;
  }
  return opts.find((o) => norm(o.textContent) === norm(key.label)) || null;
}"#;

/// localStorage/sessionStorage of the current origin as `[[k, v], ...]` pairs.
pub const READ_STORAGE: &str = r#"(() => {
  const dump = (s) => { const out = []; try { for (let i = 0; i < s.length; i++) { const k = s.key(i); out.push([k, s.getItem(k)]); } } catch (e) {} return out; };
  return { origin: location.origin, local: dump(window.localStorage), session: dump(window.sessionStorage) };
})()"#;

/// Scroll position of the page in whole CSS pixels: `{ top, height, viewport }` (offset of the
/// viewport top, document height, viewport height). Used by the lazy-content scroll.
pub const SCROLL_METRICS: &str = r#"(() => {
  const root = document.scrollingElement || document.documentElement;
  const body = document.body ? document.body.scrollHeight : 0;
  const whole = (n) => Math.max(0, Math.round(n || 0));
  return {
    top: whole(window.scrollY || root.scrollTop),
    height: whole(Math.max(root.scrollHeight || 0, body)),
    viewport: whole(window.innerHeight || root.clientHeight),
  };
})()"#;

/// Scroll the page back to the top.
pub const SCROLL_TOP: &str = "(() => { window.scrollTo(0, 0); })()";

/// `this` = element, arguments = `include` and `exclude` selector lists: is the element an
/// interaction candidate? It must match one of `include` (when that is non-empty) and neither it
/// nor an ancestor may match one of `exclude`. An invalid selector matches nothing.
pub const CSS_ADMITS: &str = r#"function (include, exclude) {
  const matches = (sel) => { try { return this.matches(sel); } catch (e) { return false; } };
  const within = (sel) => { try { return this.closest(sel) !== null; } catch (e) { return false; } };
  if (include.length > 0 && !include.some((sel) => matches(sel))) { return false; }
  return !exclude.some((sel) => within(sel));
}"#;

/// Build a script that restores storage for `origin` when the document's origin matches.
#[must_use]
pub fn write_storage_script(origin: &str, local: &serde_json::Value, session: &serde_json::Value) -> String {
    let origin = serde_json::Value::String(origin.to_owned());
    format!(
        r#"(() => {{
  if (location.origin !== {origin}) {{ return 0; }}
  const put = (s, pairs) => {{ try {{ for (const [k, v] of pairs) {{ if (s.getItem(k) === null) {{ s.setItem(k, v); }} }} }} catch (e) {{}} }};
  put(window.localStorage, {local});
  put(window.sessionStorage, {session});
  return 1;
}})()"#
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn storage_script_embeds_json_safely() {
        let s = write_storage_script(
            "http://a.test",
            &serde_json::json!([["k", "v\"</script>"]]),
            &serde_json::json!([]),
        );
        assert!(s.contains(r#"location.origin !== "http://a.test""#));
        assert!(s.contains(r#"[["k","v\"</script>"]]"#));
    }
}
