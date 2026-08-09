'use strict';

(function() {
  document.addEventListener('DOMContentLoaded', function() {
    const configEl = document.getElementById('embed-config');
    if (!configEl) {
      console.error('Embed configuration not found.');
      return;
    }
    
    let config;
    try {
      config = JSON.parse(configEl.textContent);
    } catch (e) {
      console.error('Failed to parse embed configuration:', e);
      return;
    }

    const WHEP_URL    = config.whep_url;
    const CAPTION_URL = config.caption_url;
    const CAPTIONS_ON = config.captions_enabled;
    const EMBED_TOKEN = config.token;
    const TARGET_LANG = config.target_lang_code;

    const audioEl    = document.getElementById('embed-audio');
    const playBtn    = document.getElementById('play-btn');
    const statusDot  = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const captionsEl = document.getElementById('captions-box') || null;

    let playing = false;

    function setStatus(state, text) {
      statusDot.className = 'status-dot ' + (state || '');
      statusText.textContent = text;
    }

    function setExpired() {
      setStatus('error', 'Session expired');
      playBtn.textContent = '\u26a0 Session Expired \u2014 Reload Host Page';
      playBtn.disabled = true;
    }

    const whep = createWhepClient();

    whep.start({
      whepUrl: WHEP_URL,
      audioEl: audioEl,
      onState: function(s) {
        if (s.peerConnection === 'connected') {
          setStatus('live', 'Live');
          playBtn.disabled = false;
          playBtn.textContent = playing ? '\u23f8  Pause' : '\u25b6  Play Audio';
        } else if (s.peerConnection === 'failed' || s.peerConnection === 'closed') {
          setStatus('error', 'Stream unavailable');
          playBtn.disabled = false;
        } else {
          setStatus('connecting', 'Connecting\u2026');
        }
      },
      onLog: function() {},
    });

    playBtn.addEventListener('click', function() {
      if (!playing) {
        audioEl.play().then(function() {
          playing = true;
          playBtn.textContent = '\u23f8  Pause';
        }).catch(function() {
          setStatus('error', 'Playback blocked \u2014 check browser permissions');
        });
      } else {
        audioEl.pause();
        playing = false;
        playBtn.textContent = '\u25b6  Play Audio';
      }
    });

    if (CAPTIONS_ON && captionsEl) {
      var wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      var urlPath = new URL(CAPTION_URL).pathname;
      var wsUrl = wsProto + '//' + window.location.host + urlPath + '?token=' + encodeURIComponent(EMBED_TOKEN);
      var captionWs = new WebSocket(wsUrl);

      captionWs.onmessage = function(ev) {
        try {
          var msg = JSON.parse(ev.data);
          var isValid = false;
          
          if (msg.type === 'caption') {
              isValid = true;
          } else if (msg.type === 'translation' && msg.language_code === TARGET_LANG) {
              isValid = true;
          }

          if (isValid && msg.text) {
            captionsEl.textContent = msg.text;
            captionsEl.classList.remove('empty');
          }
        } catch (_) {}
      };

      captionWs.onclose = function(ev) {
        if (ev.code === 4001) { setExpired(); }
      };
    }
  });
})();
