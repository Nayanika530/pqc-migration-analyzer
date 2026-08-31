/**
 * Qryptis — Cursor-position-driven horizontal slider
 *
 * Desktop : mousemove clientX  →  0-1 progress  →  translateX() on track
 * Mobile  : touch drag / flick  →  discrete slide snap
 * Keyboard: ← → arrow keys     →  discrete slide nav
 * Dots    : click               →  jump to slide
 * API     : window.goToSlide(index)
 */
(function () {
    'use strict';

    // ---- DOM refs ----
    var track         = document.getElementById('sliderTrack');
    var dotsContainer = document.getElementById('navDots');
    var cursorHint    = document.getElementById('cursorHint');
    if (!track) return;

    var slides        = track.querySelectorAll('.slide');
    var totalSlides   = slides.length;

    if (totalSlides === 0) return;

    // ---- State ----
    var progress       = 0;       // 0 → 1, continuous position along the track
    var currentSlide   = 0;       // nearest discrete slide index
    var isTouchDevice  = false;
    var hasInteracted  = false;
    var isLocked       = false;   // locks mouse tracking temporarily when clicking buttons

    // ---- Build navigation dots ----
    var dots = [];
    if (dotsContainer) {
        dotsContainer.innerHTML = '';
        for (var i = 0; i < totalSlides; i++) {
            (function (idx) {
                var btn = document.createElement('button');
                btn.className = 'nav-dot' + (idx === 0 ? ' active' : '');
                btn.setAttribute('aria-label', 'Go to slide ' + (idx + 1));
                btn.addEventListener('click', function (e) {
                    e.stopPropagation();
                    enableSnap();
                    goToSlide(idx);
                });
                dotsContainer.appendChild(btn);
                dots.push(btn);
            })(i);
        }
    }

    // ---- Helpers ----
    function clamp(val, min, max) {
        return Math.max(min, Math.min(max, val));
    }

    /** Temporarily switch to the slower snap easing */
    function enableSnap() {
        track.classList.add('snapping');
        track.classList.remove('dragging');
    }

    function disableSnap() {
        track.classList.remove('snapping');
    }

    /** Dismiss the "move your cursor" hint on first interaction */
    function dismissHint() {
        if (!hasInteracted && cursorHint) {
            hasInteracted = true;
            cursorHint.classList.add('hidden');
        }
    }

    // ---- Core update ----
    function setProgress(p) {
        progress = clamp(p, 0, 1);
        var maxShift = (totalSlides - 1) * 100;  // vw units
        track.style.transform = 'translateX(' + (-progress * maxShift) + 'vw)';

        // Update active dot
        var activeIdx = Math.round(progress * (totalSlides - 1));
        for (var j = 0; j < dots.length; j++) {
            dots[j].classList.toggle('active', j === activeIdx);
        }
        currentSlide = activeIdx;
    }

    function goToSlide(index) {
        index = clamp(index, 0, totalSlides - 1);
        var p = totalSlides > 1 ? index / (totalSlides - 1) : 0;
        setProgress(p);
    }

    // Expose global helper
    window.goToSlide = goToSlide;
    window.goToQryptisSlide = goToSlide;

    // Handle data-goto attributes
    document.addEventListener('click', function (e) {
        var target = e.target.closest('[data-goto]');
        if (target) {
            e.preventDefault();
            var slideIdx = parseInt(target.getAttribute('data-goto'), 10);
            if (!isNaN(slideIdx)) {
                enableSnap();
                goToSlide(slideIdx);
            }
        }
    });

    // ================================================================
    //  MOUSE-DRIVEN NAVIGATION (desktop)
    // ================================================================
    document.addEventListener('mousemove', function (e) {
        if (isTouchDevice || isLocked) return;
        dismissHint();
        disableSnap();   // use the fast 0.15s easing for cursor tracking
        var p = e.clientX / window.innerWidth;
        setProgress(p);
    });

    // ================================================================
    //  TOUCH-DRIVEN NAVIGATION (mobile)
    // ================================================================
    var touchStartX        = 0;
    var touchStartProgress = 0;
    var touchStartTime     = 0;
    var touchDeltaX        = 0;

    document.addEventListener('touchstart', function (e) {
        isTouchDevice = true;
        dismissHint();
        touchStartX        = e.touches[0].clientX;
        touchStartProgress = progress;
        touchStartTime     = Date.now();
        touchDeltaX        = 0;

        // Remove transitions during active drag
        track.classList.add('dragging');
        track.classList.remove('snapping');
    }, { passive: true });

    document.addEventListener('touchmove', function (e) {
        touchDeltaX = e.touches[0].clientX - touchStartX;
        var dragProgress = -touchDeltaX / window.innerWidth;
        setProgress(touchStartProgress + dragProgress);
    }, { passive: true });

    document.addEventListener('touchend', function () {
        track.classList.remove('dragging');
        enableSnap();

        var elapsed  = Date.now() - touchStartTime;
        var velocity = touchDeltaX / (elapsed || 1);   // px/ms

        // Flick detection: fast swipe jumps a full slide
        var target;
        if (Math.abs(velocity) > 0.4) {
            target = velocity > 0 ? currentSlide - 1 : currentSlide + 1;
        } else {
            // Snap to nearest slide
            target = Math.round(progress * (totalSlides - 1));
        }
        goToSlide(target);
    });

    // ================================================================
    //  KEYBOARD NAVIGATION (arrow keys)
    // ================================================================
    document.addEventListener('keydown', function (e) {
        if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) {
            return; // don't intercept typing
        }
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            e.preventDefault();
            dismissHint();
            enableSnap();
            goToSlide(currentSlide + 1);
        } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            dismissHint();
            enableSnap();
            goToSlide(currentSlide - 1);
        }
    });

    // Clear snap class after transition ends so mouse tracking stays fast
    track.addEventListener('transitionend', function () {
        disableSnap();
    });

    // ---- Initialize at slide 0 ----
    setProgress(0);

})();
