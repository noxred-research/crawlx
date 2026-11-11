// Reports what the page itself sees of its device. A function expression taking one flag:
// whether to also read `navigator.geolocation` (waits at most three seconds).
(probeGeolocation) => (async () => {
  const out = {
    width: innerWidth,
    height: innerHeight,
    screenWidth: screen.width,
    screenHeight: screen.height,
    pixelRatioMilli: Math.round(devicePixelRatio * 1000),
    userAgent: navigator.userAgent,
    language: navigator.language,
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    maxTouchPoints: navigator.maxTouchPoints,
    pointerCoarse: matchMedia('(pointer: coarse)').matches,
    geo: null,
    geoError: null,
  };
  if (probeGeolocation) {
    if (!window.isSecureContext || !navigator.geolocation) {
      out.geoError = 'insecure_context';
    } else {
      // a permission prompt that is never answered neither succeeds nor fails by itself, so
      // the wait is bounded here as well
      await new Promise((resolve) => {
        const timer = setTimeout(() => { out.geoError = 'timeout'; resolve(); }, 3500);
        const done = () => { clearTimeout(timer); resolve(); };
        navigator.geolocation.getCurrentPosition(
          (position) => {
            out.geo = {
              latitudeE6: Math.round(position.coords.latitude * 1e6),
              longitudeE6: Math.round(position.coords.longitude * 1e6),
              accuracyM: Math.ceil(position.coords.accuracy),
            };
            done();
          },
          (error) => {
            out.geoError = error.code === 1 ? 'denied' : error.code === 2 ? 'unavailable' : 'timeout';
            done();
          },
          { timeout: 3000, maximumAge: 0 },
        );
      });
    }
  }
  return out;
})()
