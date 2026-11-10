// Explicit opt-in only. Tokens stay in live widget state, never in this discovery record.
(() => {
  if (window.__crawlxCaptcha) return;
  const records = [];
  const elements = new WeakMap();
  let delivering = 0;
  const record = (element, options, kind, widget) => {
    if (typeof element === 'string') element = document.getElementById(element) || document.querySelector(element);
    if (!element || typeof element !== 'object') return null;
    let item = elements.get(element);
    if (!item) {
      item = {id: records.length, element, options: {}, kind, solved: false, attempted: false};
      records.push(item); elements.set(element, item);
    }
    item.options = {...item.options, ...options}; item.kind = kind; item.widget = widget;
    return item;
  };
  const intercept = (api, name, wrap) => {
    const descriptor = Object.getOwnPropertyDescriptor(api, name);
    if (descriptor && !descriptor.configurable) return;
    let value = api[name];
    let wrapped = typeof value === 'function' ? wrap(value) : value;
    Object.defineProperty(api, name, {configurable: true, enumerable: true,
      get: () => wrapped,
      set: next => {value = next; wrapped = typeof value === 'function' ? wrap(value) : value;}
    });
  };
  const install = (api, kind, enterprise = false) => {
    if (!api || typeof api !== 'object' || api.__crawlxWrapped) return api;
    Object.defineProperty(api, '__crawlxWrapped', {value: true});
    intercept(api, 'render', render => function(element, options = {}, ...rest) {
      const item = record(element, options, kind);
      const id = render.call(this, element, options, ...rest);
      if (item) item.widget = id;
      return id;
    });
    intercept(api, 'getResponse', getResponse => function(widget, ...rest) {
      const candidates = records.filter(item => item.kind === kind && (widget === undefined || item.widget === widget));
      if (candidates.length === 1 && candidates[0].token) return candidates[0].token;
      return getResponse.call(this, widget, ...rest);
    });
    if (kind.startsWith('checkbox')) intercept(api, 'execute', execute => function(key, options = {}) {
      const renderedV2 = records.some(item => item.kind === kind && String(item.widget) === String(key));
      if (typeof key !== 'string' || renderedV2) return execute.call(this, key, options);
      return new Promise(resolve => {
        let element = document.querySelector(`[data-sitekey="${CSS.escape(key)}"]`);
        if (!element) { element = document.createElement('div'); element.hidden = true; element.dataset.sitekey = key; document.documentElement.appendChild(element); }
        const item = record(element, {...options, sitekey: key, callback: resolve}, enterprise ? 'score_v3_enterprise' : 'score_v3');
        item.solved = false;
      });
    });
    const descriptor = Object.getOwnPropertyDescriptor(api, 'enterprise');
    if (!descriptor || descriptor.configurable) {
      let value = install(api.enterprise, 'checkbox_v2_enterprise', true);
      Object.defineProperty(api, 'enterprise', {configurable: true, enumerable: true,
        get: () => value, set: next => {value = install(next, 'checkbox_v2_enterprise', true);}
      });
    }
    return api;
  };
  for (const [name, kind] of [['grecaptcha', 'checkbox_v2'], ['hcaptcha', 'widget_h'], ['turnstile', 'widget_t']]) { // wire-compat: page-global widget API names
    let value = window[name]; install(value, kind);
    const descriptor = Object.getOwnPropertyDescriptor(window, name);
    if (!descriptor || descriptor.configurable) Object.defineProperty(window, name, {
      configurable: true, enumerable: true,
      get: () => value,
      set: next => {value = install(next, kind);}
    });
  }
  // A callback may verify a challenge, but solving never grants permission to submit a form.
  const formPrototype = HTMLFormElement.prototype;
  for (const name of ['submit', 'requestSubmit']) {
    const original = formPrototype[name];
    if (original) formPrototype[name] = function(...args) {
      if (delivering) throw new Error('captcha form submission requires a separate admitted action');
      return original.apply(this, args);
    };
  }
  document.addEventListener('submit', event => {if (delivering) {event.preventDefault(); event.stopImmediatePropagation();}}, true);
  document.addEventListener('click', event => {
    if (delivering && event.target.closest('button:not([type]),button[type=submit],input[type=submit],input[type=image]')) {
      event.preventDefault(); event.stopImmediatePropagation();
    }
  }, true);
  const scan = () => {
    for (const element of document.querySelectorAll('.g-recaptcha,.h-captcha,.cf-turnstile')) { // wire-compat: widget DOM markers
      if (elements.has(element)) continue;
      const enterprise = [...document.scripts].some(script => script.src.includes('/recaptcha/enterprise.js')); // wire-compat: widget script URL
      const kind = element.classList.contains('h-captcha') ? 'widget_h' : element.classList.contains('cf-turnstile') ? 'widget_t' : enterprise ? 'checkbox_v2_enterprise' : 'checkbox_v2'; // wire-compat: widget DOM markers
      record(element, {sitekey: element.dataset.sitekey, action: element.dataset.action, callback: element.dataset.callback,
        cData: element.dataset.cdata, chlPageData: element.dataset.chlPageData}, kind);
    }
    return records.filter(item => !item.solved && item.element.isConnected).map(item => ({
      id: item.id, kind: item.kind, siteKey: item.options.sitekey,
      action: item.options.action || null, data: item.options.cData || null,
      enterprisePayload: item.options.enterprisePayload || (item.options.s || item.element.dataset.s ? {s: item.options.s || item.element.dataset.s} : null),
      pagedata: item.options.chlPageData || null, websiteUrl: location.href
    }));
  };
  const claim = id => {
    const item = records[id];
    if (!item || item.attempted || item.solved || !item.element.isConnected) return false;
    item.attempted = true;
    return true;
  };
  const deliver = async (id, token, writeValue) => {
    const item = records[id];
    if (!item || item.solved || !item.element.isConnected || !token || typeof writeValue !== 'function') return false;
    const names = item.kind === 'widget_t' ? ['cf-turnstile-response'] : item.kind === 'widget_h' ? ['h-captcha-response', 'g-recaptcha-response'] : ['g-recaptcha-response']; // wire-compat: widget response field names
    let callback = item.options.callback;
    if (typeof callback === 'string') {
      let owner = window;
      for (const part of callback.split('.')) {if (!part || !owner) return false; owner = owner[part];}
      callback = owner;
    }
    if (callback !== undefined && callback !== null && typeof callback !== 'function') return false;
    delivering++;
    try {
      item.token = token;
      for (const name of names) {
        const scope = item.element;
        let fields = [...scope.querySelectorAll(`[name="${name}"]`)];
        if (!fields.length) {const field = document.createElement('textarea'); field.name = name; field.hidden = true; item.element.appendChild(field); fields = [field];}
        for (const field of fields) writeValue(field, token);
      }
      if (typeof callback === 'function') await callback(token);
      item.solved = true;
      return true;
    } catch (_) { return false; }
    finally {delivering--;}
  };
  Object.defineProperty(window, '__crawlxCaptcha', {value: Object.freeze({scan, claim, deliver})});
})();
