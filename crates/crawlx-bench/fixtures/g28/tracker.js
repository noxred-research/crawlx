/* g28 third-party tracker: loaded from the other loopback origin, reports to its own endpoint. */
(function () {
  try {
    var img = new Image();
    img.src = (document.currentScript && document.currentScript.src ? document.currentScript.src.replace(/\/tracker\.js.*$/, '') : '') +
      '/api/tracker/event?e=pageview';
  } catch (e) {}
})();
