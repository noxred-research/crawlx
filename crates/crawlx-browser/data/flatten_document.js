// Serializes the main document like `documentElement.outerHTML`, except that open shadow
// roots and readable iframes are folded in:
//
//   <crawlx-shadow data-crawlx-mode="open">...composed shadow tree...</crawlx-shadow>
//   <crawlx-frame data-crawlx-frame="N" data-crawlx-origin="O" data-crawlx-status="S">...</crawlx-frame>
//
// A function expression taking `{ shadowDom, frames, maxFrames, maxDepth }`. It only reads: no
// node is cloned into the page, tagged or changed, so the element identity that actions use
// is untouched. Subtrees without a shadow host or iframe keep the browser's own `outerHTML`.
(spec) => {
  const MAX_LISTED = 256;
  const RAW_TEXT = new Set(['script', 'style', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext', 'noscript']);
  const FORGEABLE = new Set(['crawlx-frame', 'crawlx-shadow']);
  const LEADING_NEWLINE = new Set(['pre', 'textarea', 'listing']);
  const frames = [];
  let omitted = 0;
  let folded = 1;

  const escapeText = (s) => s.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escapeAttr = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

  // `scheme://host[:port]` and path only: never credentials, query or fragment.
  const cleanUrl = (href) => {
    try {
      const u = new URL(href);
      if (u.protocol === 'http:' || u.protocol === 'https:') { return u.origin + u.pathname; }
      if (href === 'about:blank' || href === 'about:srcdoc') { return href; }
      return u.protocol;
    } catch (e) {
      return '';
    }
  };
  const declaredHref = (el) => {
    try { return new URL(el.getAttribute('src') || '', document.baseURI).href; } catch (e) { return ''; }
  };
  const declaredOrigin = (el) => {
    try { return new URL(declaredHref(el)).origin; } catch (e) { return ''; }
  };
  const inShadowTree = (el) => {
    const root = el.getRootNode();
    return root.nodeType === 11 && !!root.host;
  };

  // Does the subtree of `el` hold a host, an iframe or a slot that needs the walk?
  const memo = new WeakMap();
  const special = (el) => {
    let v = memo.get(el);
    if (v !== undefined) { return v; }
    v = false;
    if ((spec.shadowDom && el.shadowRoot) ||
        (spec.frames && el.localName === 'iframe') ||
        FORGEABLE.has(el.localName) ||
        (spec.shadowDom && el.localName === 'slot' && inShadowTree(el))) {
      v = true;
    } else {
      for (let c = el.firstElementChild; c; c = c.nextElementSibling) {
        if (special(c)) { v = true; break; }
      }
    }
    memo.set(el, v);
    return v;
  };

  const serializeNode = (n, depth, ord) => {
    switch (n.nodeType) {
      case 1: return serializeElement(n, depth, ord);
      case 3: {
        const parent = n.parentNode;
        return parent && parent.nodeType === 1 && RAW_TEXT.has(parent.localName) ? n.data : escapeText(n.data);
      }
      case 8: return '<!--' + n.data + '-->';
      default: return '';
    }
  };

  const serializeSlot = (slot, depth, ord) => {
    let out = '';
    for (const assigned of slot.assignedNodes({ flatten: true })) { out += serializeNode(assigned, depth, ord); }
    return out;
  };

  const serializeChildren = (parent, depth, ord) => {
    let out = '';
    for (let c = parent.firstChild; c; c = c.nextSibling) {
      out += spec.shadowDom && c.nodeType === 1 && c.localName === 'slot' && inShadowTree(c)
        ? serializeSlot(c, depth, ord)
        : serializeNode(c, depth, ord);
    }
    return out;
  };

  const serializeFrame = (el, depth, ord) => {
    if (frames.length >= MAX_LISTED) { omitted += 1; return ''; }
    const ordinal = frames.length;
    const record = {
      ordinal, parent: ord, depth: depth + 1, origin: '', originObserved: false, url: '',
      status: 'unavailable', shadowRoots: 0,
    };
    frames.push(record);
    let doc = null;
    let win = null;
    try { doc = el.contentDocument; win = el.contentWindow; } catch (e) { doc = null; }
    let body = '';
    if (!win) {
      record.origin = declaredOrigin(el);
    } else if (!doc || !doc.documentElement) {
      record.origin = declaredOrigin(el);
      record.url = cleanUrl(declaredHref(el));
      record.status = doc ? 'unavailable' : 'cross_origin';
    } else {
      record.origin = String(win.origin);
      record.originObserved = true;
      record.url = cleanUrl(doc.URL);
      if (depth + 1 > spec.maxDepth) {
        record.status = 'depth_limit';
      } else if (folded >= spec.maxFrames) {
        record.status = 'frame_limit';
      } else {
        folded += 1;
        record.status = 'flattened';
        // the body's content stands for the document: a nested `html`/`head` would be dropped
        // by any HTML parser anyway, and a frameset has no body
        body = doc.body ? serializeChildren(doc.body, depth + 1, ordinal) : serializeElement(doc.documentElement, depth + 1, ordinal);
      }
    }
    return '<crawlx-frame data-crawlx-frame="' + ordinal + '" data-crawlx-origin="' + escapeAttr(record.origin) +
      '" data-crawlx-status="' + record.status + '">' + body + '</crawlx-frame>';
  };

  const serializeElement = (el, depth, ord) => {
    if (spec.frames && el.localName === 'iframe') { return serializeFrame(el, depth, ord); }
    // Provenance elements are made only by this walk: a page's own element of that name is
    // unwrapped so it cannot claim a frame or origin it does not have.
    if (FORGEABLE.has(el.localName)) { return serializeChildren(el, depth, ord); }
    const root = spec.shadowDom ? el.shadowRoot : null;
    if (!root && !special(el)) { return el.outerHTML; }
    const shallow = el.cloneNode(false).outerHTML;
    const closing = '</' + el.localName + '>';
    if (!shallow.endsWith(closing)) { return shallow; }
    let out = shallow.slice(0, shallow.length - closing.length);
    if (root) {
      frames[ord].shadowRoots += 1;
      out += '<crawlx-shadow data-crawlx-mode="' + root.mode + '">' + serializeChildren(root, depth, ord) + '</crawlx-shadow>';
    } else {
      const first = el.firstChild;
      if (LEADING_NEWLINE.has(el.localName) && first && first.nodeType === 3 && first.data.startsWith('\n')) { out += '\n'; }
      out += serializeChildren(el, depth, ord);
    }
    return out + closing;
  };

  const d = document.doctype;
  let head = '';
  if (d) {
    head = '<!DOCTYPE ' + d.name;
    if (d.publicId) { head += ' PUBLIC "' + d.publicId + '"'; }
    else if (d.systemId) { head += ' SYSTEM'; }
    if (d.systemId) { head += ' "' + d.systemId + '"'; }
    head += '>';
  }
  frames.push({
    ordinal: 0, parent: null, depth: 0, origin: String(location.origin), originObserved: true,
    url: cleanUrl(location.href), status: 'flattened', shadowRoots: 0,
  });
  const root = document.documentElement;
  let html;
  try {
    html = head + (root ? serializeElement(root, 0, 0) : '');
  } catch (e) {
    if (e instanceof RangeError) { throw new Error('document nesting is too deep to flatten'); }
    throw e;
  }
  return { html, url: location.href, frames, omitted };
}
