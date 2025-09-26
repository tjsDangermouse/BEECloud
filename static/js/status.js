// Shared connection status widget
// Usage: StatusWidget.init({
//   dotMobileId: 'connection-status-dot-mobile',
//   dotDesktopId: 'connection-status-dot-desktop',
//   ringMobileId: 'progress-ring-mobile',
//   ringDesktopId: 'progress-ring-desktop',
//   storageKey: 'connectionStatusData',
//   endpoint: '/api/connection-status'
// })

(function () {
  const DEFAULTS = {
    dotMobileId: 'connection-status-dot-mobile',
    dotDesktopId: 'connection-status-dot-desktop',
    ringMobileId: 'progress-ring-mobile',
    ringDesktopId: 'progress-ring-desktop',
    storageKey: 'connectionStatusData',
    endpoint: '/api/connection-status',
    onStatusUpdate: null,
    onDataUpdate: null
  };

  let cfg = { ...DEFAULTS };
  let countdownInterval = null;
  let lastStatusData = null;

  async function refresh() {
    try {
      const resp = await fetch(cfg.endpoint);
      if (resp.ok) {
        const status = await resp.json();
        const previous = lastStatusData;
        lastStatusData = status;
        try {
          localStorage.setItem(cfg.storageKey, JSON.stringify({ ...status, fetchTime: Date.now() }));
        } catch {}
        setConnectionStatus(status.color, status.detail, status);
        startCountdownTimer();
        notifyStatusListeners(status, previous);
      } else {
        setConnectionStatus('gray', 'Status check failed');
      }
    } catch (err) {
      console.error('Error checking connection status:', err);
      setConnectionStatus('gray', 'Status check error');
    }
  }

  function notifyStatusListeners(status, previous) {
    if (typeof cfg.onStatusUpdate === 'function') {
      try {
        cfg.onStatusUpdate(status, previous);
      } catch (err) {
        console.error('StatusWidget onStatusUpdate error:', err);
      }
    }

    if (typeof cfg.onDataUpdate === 'function') {
      const currentCall = typeof status?.debug_info?.last_api_call === 'number'
        ? status.debug_info.last_api_call
        : null;
      const previousCall = typeof previous?.debug_info?.last_api_call === 'number'
        ? previous.debug_info.last_api_call
        : null;

      const hasNewData = currentCall !== null && (
        previousCall === null || currentCall > previousCall
      );

      if (hasNewData) {
        try {
          cfg.onDataUpdate(status, previous);
        } catch (err) {
          console.error('StatusWidget onDataUpdate error:', err);
        }
      }
    }
  }

  function setConnectionStatus(color, tooltip, statusData) {
    const mobileStatusDot = document.getElementById(cfg.dotMobileId);
    const desktopStatusDot = document.getElementById(cfg.dotDesktopId);
    const colorClasses = ['bg-green-500', 'bg-amber-400', 'bg-red-500', 'bg-gray-500'];

    if (mobileStatusDot) {
      colorClasses.forEach(cls => mobileStatusDot.classList.remove(cls));
      mobileStatusDot.classList.add(
        color === 'green' ? 'bg-green-500' :
        color === 'amber' ? 'bg-amber-400' :
        color === 'red' ? 'bg-red-500' : 'bg-gray-500'
      );
    }
    if (desktopStatusDot) {
      colorClasses.forEach(cls => desktopStatusDot.classList.remove(cls));
      desktopStatusDot.classList.add(
        color === 'green' ? 'bg-green-500' :
        color === 'amber' ? 'bg-amber-400' :
        color === 'red' ? 'bg-red-500' : 'bg-gray-500'
      );
    }

    // Show progress rings only when service is connected (green)
    const showRings = color === 'green';
    setRingVisibility(showRings);

    if (statusData) updateProgressRings(statusData.progress_percentage);
  }

  function setRingVisibility(show) {
    const mobileRing = document.getElementById(cfg.ringMobileId);
    const desktopRing = document.getElementById(cfg.ringDesktopId);
    if (mobileRing) mobileRing.style.display = show ? '' : 'none';
    if (desktopRing) desktopRing.style.display = show ? '' : 'none';
  }

  function updateProgressRings(progressPercentage) {
    const mobileRing = document.getElementById(cfg.ringMobileId);
    if (mobileRing) {
      const circ = 62.83; // r=10
      mobileRing.style.strokeDashoffset = circ - (progressPercentage / 100) * circ;
    }
    const desktopRing = document.getElementById(cfg.ringDesktopId);
    if (desktopRing) {
      const circ = 62.83; // r=10 to match markup
      desktopRing.style.strokeDashoffset = circ - (progressPercentage / 100) * circ;
    }
  }

  function startCountdownTimer() {
    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(() => {
      if (!lastStatusData) return;

      const now = Date.now() / 1000; // seconds
      const nextRefresh = lastStatusData.next_request_time;
      const interval = lastStatusData.interval_seconds || 600;
      const countdownSeconds = Math.max(0, Math.floor(nextRefresh - now));

      if (countdownSeconds <= 0) { refresh(); return; }

      // Progress since the start of the window
      const elapsed = now - (nextRefresh - interval);
      const progressPercentage = Math.min(100, Math.max(0, (elapsed / interval) * 100));
      updateProgressRings(progressPercentage);

      // Tooltip
      const minutes = Math.floor(countdownSeconds / 60);
      const seconds = countdownSeconds % 60;
      const timeString = minutes > 0 ? `${minutes}:${seconds.toString().padStart(2, '0')}` : `${seconds}s`;
      const tooltip = `${lastStatusData.detail} - Next refresh in: ${timeString}`;

      const mobileContainer = document.getElementById(cfg.dotMobileId)?.parentElement?.parentElement;
      const desktopContainer = document.getElementById(cfg.dotDesktopId)?.parentElement?.parentElement;
      if (mobileContainer) mobileContainer.setAttribute('title', tooltip);
      if (desktopContainer) desktopContainer.setAttribute('title', tooltip);
    }, 1000);
  }

  function restoreFromLocalStorage() {
    try {
      const stored = localStorage.getItem(cfg.storageKey);
      if (!stored) return false;
      const data = JSON.parse(stored);
      const now = Date.now();
      const age = (now - data.fetchTime) / 1000; // age in seconds
      if (age < 120) {
        const adjustedData = {
          ...data,
          countdown_seconds: Math.max(0, data.countdown_seconds - Math.floor(age)),
          // next_request_time is in seconds since epoch; subtract age (seconds)
          next_request_time: data.next_request_time - age
        };
        lastStatusData = adjustedData;
        setConnectionStatus(data.color, data.detail, adjustedData);
        startCountdownTimer();
        return true;
      }
    } catch {}
    return false;
  }

  function init(options) {
    cfg = { ...DEFAULTS, ...(options || {}) };
    const restored = restoreFromLocalStorage();
    // Always refresh immediately to align with service-side countdown
    // (restored data gives instant UI, refresh syncs precisely)
    refresh();
  }

  window.StatusWidget = { init, refresh };
})();
