/**
 * Google Analytics 4 (GA4) Integration for cert-chain-doctor documentation
 * Measurement ID: cert-chain-doctor
 */

(function () {
  'use strict';

  var GA_MEASUREMENT_ID = 'cert-chain-doctor';

  // Detect PWA / standalone display mode
  function getPWAMode() {
    if (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true) {
      return 'standalone';
    }
    return 'browser';
  }

  // Safe wrapper around gtag so errors or ad blockers never break the documentation
  function trackEvent(eventName, params) {
    try {
      if (typeof window.gtag === 'function') {
        var enrichedParams = Object.assign(
          {
            pwa_mode: getPWAMode(),
            page_location: window.location.href,
            page_path: window.location.pathname + window.location.hash,
            timestamp: new Date().toISOString(),
          },
          params || {}
        );
        window.gtag('event', eventName, enrichedParams);
      }
    } catch (e) {
      // Intentionally swallowed to guarantee non-blocking execution
    }
  }

  function trackPageView(path) {
    trackEvent('page_view', {
      page_path: path || window.location.pathname + window.location.hash,
      page_title: document.title,
    });
  }

  function trackCopyCommand(commandText) {
    trackEvent('copy_code_snippet', {
      command: commandText ? commandText.substring(0, 100) : '',
    });
  }

  function trackDownload(fileName, url) {
    trackEvent('download_binary', {
      file_name: fileName,
      download_url: url,
    });
  }

  function trackSearch(query) {
    if (!query) return;
    trackEvent('search_documentation', {
      search_term: query.substring(0, 50),
    });
  }

  function trackExternalLink(url) {
    trackEvent('click_external_link', {
      link_url: url,
    });
  }

  // Export functions to global scope
  window.certChainDoctorAnalytics = {
    trackEvent: trackEvent,
    trackPageView: trackPageView,
    trackCopyCommand: trackCopyCommand,
    trackDownload: trackDownload,
    trackSearch: trackSearch,
    trackExternalLink: trackExternalLink,
  };

  // Initial page view
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      trackPageView();
      attachListeners();
    });
  } else {
    trackPageView();
    attachListeners();
  }

  // Listen to hash / route changes for SPA navigation
  window.addEventListener('hashchange', function () {
    trackPageView();
  });

  function attachListeners() {
    document.addEventListener('click', function (e) {
      var target = e.target;
      if (!target) return;

      // Track code copy buttons
      var copyBtn = target.closest('.copy-btn, button[data-copy]');
      if (copyBtn) {
        var code = copyBtn.getAttribute('data-clipboard-text') || copyBtn.textContent || '';
        trackCopyCommand(code.trim());
        return;
      }

      // Track download and external links
      var link = target.closest('a');
      if (link && link.href) {
        var href = link.href;
        if (href.includes('/releases/download/') || href.endsWith('.tar.gz') || href.endsWith('.zip')) {
          var fileName = href.substring(href.lastIndexOf('/') + 1);
          trackDownload(fileName, href);
        } else if (link.hostname && link.hostname !== window.location.hostname) {
          trackExternalLink(href);
        }
      }
    });
  }
})();
