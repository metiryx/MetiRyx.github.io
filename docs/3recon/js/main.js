// dark-toggle.js
(function(){
  const STORAGE_KEY = 'site-dark-mode';
  const html = document.documentElement;

  function applyMode(mode) {
    if (mode === 'dark') html.classList.add('dark');
    else html.classList.remove('dark');
  }

  // 1. read saved preference
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    applyMode(saved);
  } else {
    // 2. fallback to system preference
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyMode(prefersDark ? 'dark' : 'light');
  }

  // 3. expose toggle function (useful for button onclick)
  window.toggleDarkMode = function() {
    const nowDark = html.classList.toggle('dark');
    localStorage.setItem(STORAGE_KEY, nowDark ? 'dark' : 'light');
  };
})();
