(function registerSW(){
  if (!('serviceWorker' in navigator)) return;
  // Prefer a root-scoped script, but fall back to the static path.
  const candidates = ['/service-worker.js', '/sw.js', '/static/js/sw.js'];

  function scopeFor(url){
    // If using a root script, request root scope; otherwise match the directory.
    if (url === '/service-worker.js' || url === '/sw.js') return '/';
    if (url === '/static/js/sw.js') return '/static/js/';
    try { return new URL(url, location.origin).pathname.replace(/[^/]+$/, ''); } catch { return '/'; }
  }

  function tryRegister(index){
    if (index >= candidates.length) return;
    const url = candidates[index];
    const scope = scopeFor(url);
    navigator.serviceWorker.register(url, { scope })
      .then(function(){ /* ok */ })
      .catch(function(){ tryRegister(index + 1); });
  }

  window.addEventListener('load', function(){ tryRegister(0); });
})();
