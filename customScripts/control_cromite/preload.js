(function() {
  if (window.__clipi_installed) return;
  window.__clipi_installed = true;

  const installCursor = () => {
    if (document.getElementById('__clipi_cursor')) return;
    const c = document.createElement('div');
    c.id = '__clipi_cursor';
    c.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24"><path d="M2 2 L2 20 L7 15 L11 23 L14 21 L10 13 L16 13 Z" fill="white" stroke="black" stroke-width="1"/></svg>`;
    Object.assign(c.style, {
      position: 'fixed', top: '0', left: '0', width: '24px', height: '24px',
      pointerEvents: 'none', zIndex: '2147483647', transition: 'all 0.15s ease-out'
    });
    document.documentElement.appendChild(c);
    window.__cursorElement = c;
  };

  window.clipi = {
    spy: { active: false, toggle: () => { window.clipi.spy.active = !window.clipi.spy.active; return window.clipi.spy.active; } },
    page: {
      mouse: {
        move: (targetX, targetY) => {
          if (!window.__cursorElement) installCursor();
          const startX = parseFloat(window.__cursorElement.style.left || 0);
          const startY = parseFloat(window.__cursorElement.style.top || 0);
          const steps = 40;
          let currentStep = 0;

          const animate = () => {
            currentStep++;
            const progress = currentStep / steps;
            const curX = startX + (targetX - startX) * progress;
            const curY = startY + (targetY - startY) * progress;
            
            window.__cursorElement.style.left = `${curX}px`;
            window.__cursorElement.style.top = `${curY}px`;

            if (currentStep < steps) {
              requestAnimationFrame(animate);
            }
          };
          animate();
        },
        click: (x, y) => {
          window.clipi.page.mouse.move(x, y);
          setTimeout(() => {
            const el = document.elementFromPoint(x, y);
            if (el) el.click();
          }, 400);
        }
      },  
      click: async (selector) => {
        const el = document.querySelector(selector);
        if (el) {
          const r = el.getBoundingClientRect();
          window.clipi.page.mouse.click(r.left + r.width/2, r.top + r.height/2);
        }
      },
      type: async (selector, text) => {
        const el = document.querySelector(selector);
        if (el) { el.focus(); el.value = text; el.dispatchEvent(new Event('input', {bubbles:true})); }
      },
      autoScroll: async (max = 5) => {
        for (let i=0; i<max; i++) {
          window.scrollBy(0, window.innerHeight);
          await new Promise(r => setTimeout(r, 800));
        }
      },
      extract: async (selector) => {
        const results = Array.from(document.querySelectorAll(selector)).map(el => ({ text: el.innerText?.trim(), val: el.href || el.src || null }));
        await fetch('http://127.0.0.1:3000/data', { method: 'POST', body: JSON.stringify({ url: location.href, results }) });
      }
    }
  };

  const startPolling = () => {
    setInterval(async () => {
      try {
        const r = await fetch('http://127.0.0.1:3000');
        const cmd = await r.json();
        if (cmd.action === 'eval') eval(cmd.code);
      } catch (e) {}
    }, 1000);
  };

  document.addEventListener('click', (e) => {
    if (!window.clipi.spy.active) return;
    const s = e.target.id ? `#${e.target.id}` : `${e.target.tagName.toLowerCase()}.${e.target.className.split(' ').join('.')}`;
    fetch('http://127.0.0.1:3000/spy', { method: 'POST', body: JSON.stringify({ selector: s, text: e.target.innerText?.slice(0,20) }) });
  }, true);

  installCursor();
  startPolling();
})();
