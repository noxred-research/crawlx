/* CrawlerGym client library, inlined into every fixture page by the gym server.
 * Deterministic: all randomness derives from the seed the server injects. */
(function () {
  'use strict';
  var SEED = {{SEED}} >>> 0;
  var FIXTURE = '{{FIXTURE}}';

  // mulberry32: tiny seeded PRNG, identical on every run for the same seed.
  function mulberry32(a) {
    return function () {
      a = (a + 0x6d2b79f5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function hashString(s) {
    var h = 2166136261 >>> 0;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h >>> 0;
  }

  var gym = {
    fixture: FIXTURE,
    seed: SEED,
    /** DOM-level handler invocations: { id, trusted, n }. Client-side oracle. */
    hits: [],
    /** Seeded generator for `label`; same (seed, label) gives the same stream. */
    rngFor: function (label) {
      return mulberry32((SEED ^ hashString(String(label))) >>> 0);
    },
    probes: {}
  };
  gym.rng = gym.rngFor('default');
  gym.pick = function (arr, rng) {
    return arr[Math.floor((rng || gym.rng)() * arr.length)];
  };
  gym.shuffle = function (arr, rng) {
    var r = rng || gym.rng;
    var a = arr.slice();
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(r() * (i + 1));
      var t = a[i];
      a[i] = a[j];
      a[j] = t;
    }
    return a;
  };

  function beacon(path, params) {
    var q = Object.keys(params)
      .map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
      })
      .join('&');
    try {
      return fetch('/__gym/' + path + '?' + q, { method: 'POST', keepalive: true }).catch(function () {});
    } catch (e) {
      return null;
    }
  }

  /** Record that the handler of ground-truth control `id` ran. `ev` supplies isTrusted. */
  gym.hit = function (id, ev) {
    var trusted = !!(ev && ev.isTrusted);
    gym.hits.push({ id: id, trusted: trusted, n: gym.hits.length });
    return beacon('click', { fixture: FIXTURE, control: id, trusted: trusted ? 1 : 0 });
  };

  /** Report a named client-side probe result to the server ledger. */
  gym.probe = function (name, value) {
    gym.probes[name] = String(value);
    return beacon('probe', { fixture: FIXTURE, name: name, value: String(value) });
  };

  /** Call the fixture's backend: `gym.api('DELETE', 'projects/1')` hits `/<fixture>/api/projects/1`. */
  gym.api = function (method, path, body) {
    var init = { method: method, headers: {} };
    if (body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return fetch('/' + FIXTURE + '/api/' + path, init).then(function (r) {
      return r.json().catch(function () {
        return { ok: r.ok };
      });
    });
  };

  /** Submit `fields` (object or <form>) as form `formId`; the server ledger records the fields. */
  gym.form = function (formId, source) {
    var fields = {};
    if (source && source.elements) {
      Array.prototype.forEach.call(source.elements, function (el) {
        if (el.name && el.type !== 'file' && el.type !== 'submit' && el.type !== 'button') {
          if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) return;
          fields[el.name] = el.value;
        }
      });
    } else {
      fields = source || {};
    }
    var body = Object.keys(fields)
      .map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(fields[k]);
      })
      .join('&');
    return fetch('/' + FIXTURE + '/api/form/' + encodeURIComponent(formId), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body
    }).then(function (r) {
      return r.json().catch(function () {
        return { ok: r.ok };
      });
    });
  };

  window.__gym = gym;
})();
