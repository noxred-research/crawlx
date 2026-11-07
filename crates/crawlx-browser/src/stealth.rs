//! Opt-in stealth patches (`dynamic.stealthPatches`): own-authored
//! equivalents of go-rod's `stealth.js` (katana applies that script unconditionally).
//!
//! Under the `Stealth` launch profile the flags already remove `--enable-automation` and the
//! `Runtime.enable` / `Console.enable` traces. This script adds what flags cannot reach, in the
//! page's main world through `Page.addScriptToEvaluateOnNewDocument` (no isolated world: the
//! objects it patches are per-world, so an isolated-world copy would change nothing the page
//! sees):
//!
//! * `navigator.webdriver` reads `false`;
//! * `navigator.languages` follows the context locale (`en-US` gives `["en-US", "en"]`);
//! * `navigator.plugins` / `mimeTypes` get the five PDF viewer entries current Chrome reports
//!   when the build exposes none;
//! * `window.chrome` exists with `app`, `csi`, `loadTimes` and `runtime`;
//! * the notifications permission query agrees with
//!   `Notification.permission` instead of answering `prompt` next to a `denied` permission;
//! * WebGL `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` report an Intel GPU instead of
//!   the software renderer;
//! * every patched function keeps a native-looking `Function.prototype.toString`.
//!
//! The flag is off by default and gated like the profile it needs: a crawler aimed at a
//! third-party site that lowers its automation fingerprint is evading access controls, so only
//! `test_environment` / `authorized_security_test` runs may use it.

/// WebGL vendor reported while the patches are on.
pub const WEBGL_VENDOR: &str = "Intel Inc.";
/// WebGL renderer reported while the patches are on.
pub const WEBGL_RENDERER: &str = "Intel Iris OpenGL Engine";

/// Template of the init script; `__CRAWLX_STEALTH_CONFIG__` is replaced by the JSON config.
const SCRIPT_TEMPLATE: &str = r#"(function crawlxStealth(cfg) {
  var nativeToString = Function.prototype.toString;
  var masked = new WeakMap();
  function mask(fn, label) {
    masked.set(fn, 'function ' + label + '() { [native code] }');
    return fn;
  }
  var toStringProxy = new Proxy(nativeToString, {
    apply: function (target, thisArg, args) {
      if (masked.has(thisArg)) { return masked.get(thisArg); }
      return Reflect.apply(target, thisArg, args);
    }
  });
  masked.set(toStringProxy, 'function toString() { [native code] }');
  try {
    Object.defineProperty(Function.prototype, 'toString', { value: toStringProxy, writable: true, configurable: true });
  } catch (_) {}
  function replaceMethod(proto, name, make) {
    try {
      var original = proto[name];
      if (typeof original !== 'function') { return; }
      var patched = mask(make(original), name);
      Object.defineProperty(proto, name, { value: patched, writable: true, configurable: true, enumerable: true });
    } catch (_) {}
  }
  function replaceGetter(proto, name, value) {
    try {
      var current = Object.getOwnPropertyDescriptor(proto, name);
      var getter = mask(function () { return value; }, 'get ' + name);
      Object.defineProperty(proto, name, {
        get: getter,
        set: current ? current.set : undefined,
        enumerable: current ? current.enumerable : true,
        configurable: true
      });
    } catch (_) {}
  }

  replaceGetter(Navigator.prototype, 'webdriver', false);
  replaceGetter(Navigator.prototype, 'languages', Object.freeze(cfg.languages.slice()));

  try {
    if (navigator.plugins.length === 0 && window.Plugin && window.PluginArray && window.MimeType && window.MimeTypeArray) {
      var mimeInfo = [
        { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
        { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' }
      ];
      var pluginNames = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];
      var mimes = mimeInfo.map(function (m) {
        var mime = Object.create(MimeType.prototype);
        Object.defineProperties(mime, {
          type: { value: m.type, enumerable: true },
          suffixes: { value: m.suffixes, enumerable: true },
          description: { value: m.description, enumerable: true }
        });
        return mime;
      });
      var plugins = pluginNames.map(function (name) {
        var plugin = Object.create(Plugin.prototype);
        Object.defineProperties(plugin, {
          name: { value: name, enumerable: true },
          filename: { value: 'internal-pdf-viewer', enumerable: true },
          description: { value: 'Portable Document Format', enumerable: true },
          length: { value: mimes.length, enumerable: true }
        });
        mimes.forEach(function (mime, i) { Object.defineProperty(plugin, i, { value: mime, enumerable: true }); });
        Object.defineProperty(plugin, 'item', { value: mask(function item(i) { return mimes[i] || null; }, 'item') });
        Object.defineProperty(plugin, 'namedItem', { value: mask(function namedItem(n) { return mimes.filter(function (m) { return m.type === n; })[0] || null; }, 'namedItem') });
        return plugin;
      });
      Object.keys(mimes).forEach(function (i) {
        Object.defineProperty(mimes[i], 'enabledPlugin', { value: plugins[0], enumerable: true });
      });
      var pluginArray = Object.create(PluginArray.prototype);
      plugins.forEach(function (plugin, i) { Object.defineProperty(pluginArray, i, { value: plugin, enumerable: true }); });
      Object.defineProperties(pluginArray, {
        length: { value: plugins.length, enumerable: true },
        item: { value: mask(function item(i) { return plugins[i] || null; }, 'item') },
        namedItem: { value: mask(function namedItem(n) { return plugins.filter(function (p) { return p.name === n; })[0] || null; }, 'namedItem') },
        refresh: { value: mask(function refresh() {}, 'refresh') }
      });
      var mimeArray = Object.create(MimeTypeArray.prototype);
      mimes.forEach(function (mime, i) { Object.defineProperty(mimeArray, i, { value: mime, enumerable: true }); });
      Object.defineProperties(mimeArray, {
        length: { value: mimes.length, enumerable: true },
        item: { value: mask(function item(i) { return mimes[i] || null; }, 'item') },
        namedItem: { value: mask(function namedItem(n) { return mimes.filter(function (m) { return m.type === n; })[0] || null; }, 'namedItem') }
      });
      replaceGetter(Navigator.prototype, 'plugins', pluginArray);
      replaceGetter(Navigator.prototype, 'mimeTypes', mimeArray);
    }
  } catch (_) {}

  try {
    if (!window.chrome) {
      var noop = function () {};
      Object.defineProperty(window, 'chrome', {
        value: {
          app: {
            isInstalled: false,
            InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
            RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
            getDetails: mask(noop, 'getDetails'),
            getIsInstalled: mask(noop, 'getIsInstalled'),
            runningState: mask(function runningState() { return 'cannot_run'; }, 'runningState')
          },
          csi: mask(function csi() { return { onloadT: Date.now(), startE: Date.now(), pageT: performance.now(), tran: 15 }; }, 'csi'),
          loadTimes: mask(function loadTimes() { return {}; }, 'loadTimes'),
          runtime: {}
        },
        writable: true, configurable: true, enumerable: true
      });
    }
  } catch (_) {}

  if (window.Permissions && window.PermissionStatus && window.Notification) {
    replaceMethod(Object.getPrototypeOf(navigator.permissions), 'query', function (original) {
      return function query(parameters) {
        if (parameters && parameters.name === 'notifications') {
          var permission = Notification.permission;
          var status = Object.create(PermissionStatus.prototype);
          Object.defineProperties(status, {
            state: { value: permission === 'default' ? 'prompt' : permission, enumerable: true },
            onchange: { value: null, writable: true, enumerable: true }
          });
          return Promise.resolve(status);
        }
        return original.apply(this, arguments);
      };
    });
  }

  [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach(function (ctor) {
    if (!ctor) { return; }
    replaceMethod(ctor.prototype, 'getParameter', function (original) {
      return function getParameter(parameter) {
        if (parameter === 37445) { return cfg.vendor; }
        if (parameter === 37446) { return cfg.renderer; }
        return original.apply(this, arguments);
      };
    });
  });
})(__CRAWLX_STEALTH_CONFIG__);"#;

/// `Accept-Language`-style list for `locale`: the locale itself, then its bare language
/// (`en-US` gives `["en-US", "en"]`, `de` gives `["de"]`).
#[must_use]
pub fn languages_for(locale: &str) -> Vec<String> {
    let locale = locale.trim();
    let locale = if locale.is_empty() { "en-US" } else { locale };
    let mut out = vec![locale.to_owned()];
    if let Some((language, _)) = locale.split_once(['-', '_']) {
        out.push(language.to_owned());
    }
    out
}

/// The init script for a context whose locale is `locale`.
#[must_use]
pub fn script(locale: &str) -> String {
    let config = serde_json::json!({
        "languages": languages_for(locale),
        "vendor": WEBGL_VENDOR,
        "renderer": WEBGL_RENDERER,
    });
    SCRIPT_TEMPLATE.replace("__CRAWLX_STEALTH_CONFIG__", &config.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn languages_follow_the_locale() {
        assert_eq!(languages_for("en-US"), ["en-US", "en"]);
        assert_eq!(languages_for("de"), ["de"]);
        assert_eq!(languages_for("fr_CA"), ["fr_CA", "fr"]);
        assert_eq!(languages_for(" "), ["en-US", "en"]);
    }

    #[test]
    fn the_script_patches_every_documented_surface_and_carries_its_config() {
        let s = script("en-US");
        for surface in [
            "'webdriver'",
            "'languages'",
            "'plugins'",
            "'mimeTypes'",
            "window.chrome",
            "getPrototypeOf(navigator.permissions)",
            "'getParameter'",
            "37445",
            "37446",
        ] {
            assert!(s.contains(surface), "{surface}");
        }
        assert!(s.contains(r#""languages":["en-US","en"]"#), "{s}");
        assert!(s.contains(WEBGL_VENDOR) && s.contains(WEBGL_RENDERER));
        assert!(!s.contains("__CRAWLX_STEALTH_CONFIG__"));
        // main world, no console output, no events
        assert!(!s.contains("console.") && !s.contains("dispatchEvent"));
    }
}
