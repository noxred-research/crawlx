/* g28 service worker: background fetches that no page action caused. */
// Consume each response before ending the worker event, including its body transfer.
function backgroundFetch(path) {
  return fetch(path).then(function (response) { return response.text(); }).catch(function () {});
}
self.addEventListener('install', function (event) {
  event.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', function (event) {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      backgroundFetch('/g28/api/sw/activate')
    ])
  );
});
// The page pings the worker every 2 s; the worker answers with its own fetch.
self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'sync') {
    event.waitUntil(backgroundFetch('/g28/api/sw/sync'));
  }
});
// Pass-through fetch handler: every navigation and subresource is observed by the worker,
// which also issues its own side request for page loads.
self.addEventListener('fetch', function (event) {
  if (event.request.mode === 'navigate') {
    event.waitUntil(backgroundFetch('/g28/api/sw/navigation'));
  }
});
