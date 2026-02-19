/**
 * effects.js - CineVault cinematic effects
 * Intro animation (once per session), mouse-follow glow, particles.
 * Does not change form names, API endpoints, or script.js submission logic.
 */

(function () {
  'use strict';

  /* ---------- Config ---------- */
  var INTRO_DURATION_MS = 1200;
  var REDIRECT_DELAY_MS = 800;
  var INTRO_STORAGE_KEY = 'cinevault-intro-done';
  var MOUSE_GLOW_ID = 'mouse-glow';
  var PARTICLES_ID = 'particles';
  var INTRO_OVERLAY_ID = 'intro-overlay';
  var PARTICLE_COUNT = 24;
  var LOADING_OVERLAY_ID = 'loading-overlay';

  /** Set to true to play optional "ta-dum" intro sound once on load. Add intro.mp3 to public/. */
  var ENABLE_INTRO_SOUND = false;
  var INTRO_SOUND_FILE = 'intro.mp3';

  /**
   * Premium Netflix-style intro: logo + light sweep + glow pulse, then fade out. No redirect.
   * Runs once per session. No loading text, spinners, or redirect delays.
   */
  function runIntro() {
    var intro = document.getElementById(INTRO_OVERLAY_ID);
    if (!intro) return;

    if (sessionStorage.getItem(INTRO_STORAGE_KEY)) {
      intro.classList.add('fade-out');
      document.body.classList.remove('intro-active');
      document.body.classList.add('intro-complete');
      intro.style.visibility = 'hidden';
      return;
    }

    document.body.classList.add('intro-active');

    if (ENABLE_INTRO_SOUND) {
      try {
        var sound = new Audio(INTRO_SOUND_FILE);
        sound.volume = 0.4;
        sound.play().catch(function () {});
      } catch (e) {}
    }

    setTimeout(function () {
      intro.classList.add('fade-out');
      sessionStorage.setItem(INTRO_STORAGE_KEY, '1');
      document.body.classList.remove('intro-active');
      document.body.classList.add('intro-complete');

      intro.addEventListener('transitionend', function onEnd() {
        intro.removeEventListener('transitionend', onEnd);
        intro.style.visibility = 'hidden';
      });
    }, INTRO_DURATION_MS);
  }

  /**
   * Shows centered loading overlay (spinner + "Loading..."). Fades in smoothly.
   */
  function showLoadingOverlay() {
    var el = document.getElementById(LOADING_OVERLAY_ID);
    if (el) {
      el.classList.add('loading-overlay-visible');
      return el;
    }
    el = document.createElement('div');
    el.id = LOADING_OVERLAY_ID;
    el.className = 'loading-overlay';
    el.setAttribute('aria-live', 'polite');
    el.setAttribute('aria-label', 'Loading');
    el.innerHTML = '<div class="loading-spinner" aria-hidden="true"></div><p class="loading-text">Loading...</p>';
    document.body.appendChild(el);
    requestAnimationFrame(function () {
      el.classList.add('loading-overlay-visible');
    });
    return el;
  }

  /**
   * Reusable fast redirect: show loading overlay immediately, then navigate after 800ms.
   * Use for logo clicks and post-login/register redirects.
   */
  function fastRedirect(url) {
    if (!url || typeof url !== 'string') return;
    showLoadingOverlay();
    setTimeout(function () {
      window.location.href = url;
    }, REDIRECT_DELAY_MS);
  }

  window.fastRedirect = fastRedirect;

  /**
   * Intercept CineVault logo clicks so redirect uses loading overlay and feels instant.
   */
  function initLogoRedirect() {
    document.querySelectorAll('a.cinevault-logo').forEach(function (link) {
      link.addEventListener('click', function (e) {
        var href = link.getAttribute('href');
        if (href && href !== '#') {
          e.preventDefault();
          fastRedirect(href);
        }
      });
    });
  }

  /**
   * Soft red radial glow following cursor. Low opacity for premium feel.
   */
  function initMouseGlow() {
    var glow = document.getElementById(MOUSE_GLOW_ID);
    if (!glow) return;

    function moveGlow(e) {
      glow.style.left = e.clientX + 'px';
      glow.style.top = e.clientY + 'px';
    }

    document.addEventListener('mousemove', moveGlow, { passive: true });
    document.addEventListener('mouseleave', function () {
      glow.style.opacity = '0';
    });
    document.addEventListener('mouseenter', function () {
      glow.style.opacity = '1';
    });
  }

  /**
   * Cinematic floating red particles: random size, slow movement, subtle blur. DOM-based, pointer-events: none.
   */
  function initParticles() {
    var container = document.getElementById(PARTICLES_ID);
    if (!container) return;

    for (var i = 0; i < PARTICLE_COUNT; i++) {
      var p = document.createElement('div');
      p.className = 'particle';

      var size = 3 + Math.random() * 10;
      var left = Math.random() * 100;
      var top = Math.random() * 100;
      var duration = 22 + Math.random() * 20;
      var delay = Math.random() * -25;

      p.style.width = size + 'px';
      p.style.height = size + 'px';
      p.style.left = left + '%';
      p.style.top = top + '%';
      p.style.animationDuration = duration + 's';
      p.style.animationDelay = delay + 's';

      container.appendChild(p);
    }
  }

  function init() {
    runIntro();
    initLogoRedirect();
    initMouseGlow();
    initParticles();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
