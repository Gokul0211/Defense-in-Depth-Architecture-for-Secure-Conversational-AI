/* ═══════════════════════════════════════════════════════════════════════════
   SENTINEL — App Orchestrator
   Handles: Preloader → Landing → Dashboard routing
   Custom cursor, scroll animations, page transitions
   ═══════════════════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  /* ── Custom cursor ── */
  const cursor = document.getElementById('cursor');
  const trail = document.getElementById('cursor-trail');
  let mx = -100, my = -100, tx = -100, ty = -100;

  document.addEventListener('mousemove', e => {
    mx = e.clientX; my = e.clientY;
    cursor.style.left = mx + 'px';
    cursor.style.top = my + 'px';
  });

  // Lerp trail
  (function tickTrail() {
    tx += (mx - tx) * 0.12;
    ty += (my - ty) * 0.12;
    trail.style.left = tx + 'px';
    trail.style.top = ty + 'px';
    requestAnimationFrame(tickTrail);
  })();

  document.addEventListener('mousedown', () => {
    cursor.classList.add('click');
    setTimeout(() => cursor.classList.remove('click'), 200);
  });

  // Hover effect on interactive elements
  function attachHover() {
    document.querySelectorAll('a, button, [data-hover], input, details summary').forEach(el => {
      if (el._sentinelHover) return;
      el._sentinelHover = true;
      el.addEventListener('mouseenter', () => { cursor.classList.add('hover'); trail.classList.add('hover'); });
      el.addEventListener('mouseleave', () => { cursor.classList.remove('hover'); trail.classList.remove('hover'); });
    });
  }
  setInterval(attachHover, 500); // re-run periodically for dynamic elements

  /* ── Preloader ── */
  const preloader = document.getElementById('preloader');
  const root = document.getElementById('root');

  function finishPreloader() {
    preloader.classList.add('done');
    root.style.opacity = '1';
    setTimeout(() => { preloader.remove(); }, 900);
  }

  // Minimum preloader time for drama
  const MIN_PRELOAD = 1800;
  const preloadStart = Date.now();

  /* ── View state ── */
  let currentView = 'landing'; // 'landing' | 'dashboard'

  /* ── Show Landing ── */
  function showLanding() {
    currentView = 'landing';
    document.title = 'SENTINEL — AI Security Fabric';

    // Clear root and rebuild landing
    root.innerHTML = '';

    if (window.SENTINEL_LANDING) {
      SENTINEL_LANDING.buildLanding();
    }

    // Bind CTA buttons (delegated, since landing builds its own DOM)
    root.addEventListener('click', handleLandingClick, {once:false});

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(a => {
      a.addEventListener('click', e => {
        const target = document.querySelector(a.getAttribute('href'));
        if (target) { e.preventDefault(); target.scrollIntoView({behavior:'smooth'}); }
      });
    });

    attachHover();
  }

  function handleLandingClick(e) {
    const btn = e.target.closest('#hero-enter-btn, #cta-enter-btn, #nav-demo-btn');
    if (btn) {
      e.stopPropagation();
      transitionToDashboard();
    }
  }

  /* ── Show Dashboard ── */
  function transitionToDashboard() {
    currentView = 'dashboard';
    document.title = 'SENTINEL — Command Center';

    // Page exit animation
    root.style.transition = 'opacity 0.4s ease, filter 0.4s ease';
    root.style.opacity = '0';
    root.style.filter = 'blur(8px)';

    setTimeout(() => {
      // Remove landing handler
      root.removeEventListener('click', handleLandingClick);
      root.innerHTML = '';

      // Mount React dashboard
      const dashMount = document.createElement('div');
      dashMount.id = 'dash-mount';
      dashMount.style.height = '100vh';
      root.appendChild(dashMount);

      ReactDOM.createRoot(dashMount).render(
        React.createElement(SENTINEL_DASHBOARD.Dashboard, { onBack: transitionToLanding })
      );

      // Fade in dashboard
      root.style.opacity = '1';
      root.style.filter = 'none';

      attachHover();
    }, 400);
  }

  function transitionToLanding() {
    root.style.transition = 'opacity 0.4s ease, filter 0.4s ease';
    root.style.opacity = '0';
    root.style.filter = 'blur(8px)';

    setTimeout(() => {
      showLanding();
      root.style.opacity = '1';
      root.style.filter = 'none';
      window.scrollTo({top:0, behavior:'smooth'});
    }, 400);
  }

  /* ── Init ── */
  function init() {
    const elapsed = Date.now() - preloadStart;
    const wait = Math.max(0, MIN_PRELOAD - elapsed);

    setTimeout(() => {
      finishPreloader();
      showLanding();
    }, wait);
  }

  // Wait for all scripts to load
  if (document.readyState === 'complete') {
    init();
  } else {
    window.addEventListener('load', init);
  }

  /* ── Keyboard shortcuts ── */
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && currentView === 'dashboard') transitionToLanding();
    if (e.key === 'd' && e.ctrlKey && e.shiftKey && currentView === 'landing') {
      e.preventDefault(); transitionToDashboard();
    }
  });

})();
