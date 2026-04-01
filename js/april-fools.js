// SVG icons (same as main modal)
const COPY_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const CHECK_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
const LINK_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';

function showCopyToast(anchorEl, message) {
  const toast = document.createElement('span');
  toast.className = 'copy-toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  const rect = anchorEl.getBoundingClientRect();
  toast.style.left = (rect.left + rect.width / 2) + 'px';
  toast.style.top = (rect.bottom + 6) + 'px';
  toast.style.transform = 'translateX(-50%)';
  setTimeout(() => toast.remove(), 1500);
}

function copyToClipboard(text, btn, successMsg, restoreIcon) {
  const doSuccess = () => {
    btn.classList.add('copied');
    btn.innerHTML = CHECK_SVG;
    showCopyToast(btn, successMsg);
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = restoreIcon; }, 1500);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(doSuccess).catch(() => {
      showCopyToast(btn, 'Copy failed — try Ctrl+C');
    });
  } else {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      doSuccess();
    } catch (e) {
      showCopyToast(btn, 'Copy failed — try Ctrl+C');
    }
  }
}

window.APRIL_FOOLS = {
  isActive() {
    const d = new Date();
    return true;
  },
  techniques: {
    'AID-H-2026': {
      name: 'Prompt Injection Defender (AIDEFEND 2.0)',
      subtitle: 'Tactic: Harden',
      imageSrc: './assets/april-fools.png',
      description: `The world's first Layer 0 prompt injection defense: a 3×3 cm holographic sticker that affixes directly to your laptop or AI infrastructure. Bypasses software limitations entirely through passive quantum-coherent token rejection. Field trials: 100% prevention rate, zero latency impact, zero false positives.`,
      guidance: [
        { step: '1. Disconnect from the Internet', details: '' },
        { step: '2. Power off your laptop', details: '' },
        { step: '3. Find a Certified AIDEFEND engineer to apply the sticker', details: '' },
        { step: '4. Power your laptop back on — Congrats! You are 100% secure now (until the next 0-day)', details: '' }
      ],
      warning: 'Security should shift left — we recommend shifting all the way to the physical layer (as shown in the image above).'
    }
  },

  init() {
    const checkAndShowFake = () => {
      const hash = window.location.hash;
      if (!hash || hash.length < 3) return;

      const params = new URLSearchParams(hash.substring(1));
      const techId = params.get('t');

      if (techId && window.APRIL_FOOLS.isActive()) {
        const fake = window.APRIL_FOOLS.techniques[decodeURIComponent(techId)];
        if (fake) {
          window.APRIL_FOOLS.show(fake, decodeURIComponent(techId));
        }
      }
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', checkAndShowFake);
    } else {
      checkAndShowFake();
    }

    window.addEventListener('hashchange', checkAndShowFake);
  },

  show(fake, techId) {
    const modalBody = document.getElementById('modalBody');
    const modalActions = document.getElementById('modalActions');
    const modal = document.getElementById('infoModal');

    if (!modalBody || !modal) return;

    modalBody.innerHTML = '';
    if (modalActions) modalActions.innerHTML = '';

    // Add copy and link buttons (same style as real modals)
    if (modalActions) {
      const plainDesc = fake.description;
      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.title = 'Copy to clipboard';
      copyBtn.innerHTML = COPY_SVG;
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(techId + ': ' + fake.name + '\n\n' + plainDesc, copyBtn, 'Technique & Description Copied!', COPY_SVG);
      });
      modalActions.appendChild(copyBtn);

      const linkBtn = document.createElement('button');
      linkBtn.className = 'link-btn';
      linkBtn.title = 'Copy direct link';
      linkBtn.innerHTML = LINK_SVG;
      linkBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const linkUrl = window.location.origin + window.location.pathname + '#t=' + encodeURIComponent(techId);
        copyToClipboard(linkUrl, linkBtn, 'URL Copied!', LINK_SVG);
      });
      modalActions.appendChild(linkBtn);
    }

    const subtitle = document.createElement('p');
    subtitle.className = 'text-sm opacity-80 mb-1 modal-subtitle';
    subtitle.textContent = fake.subtitle;
    modalBody.appendChild(subtitle);

    const title = document.createElement('h2');
    title.textContent = techId + ': ' + fake.name;
    modalBody.appendChild(title);

    const img = document.createElement('img');
    img.src = fake.imageSrc;
    img.alt = fake.name;
    img.style.cssText = 'width:100%;border-radius:8px;margin:1rem 0';
    modalBody.appendChild(img);

    const descEl = document.createElement('div');
    descEl.className = 'technique-description mb-4 leading-relaxed text-sm';
    descEl.textContent = fake.description;
    modalBody.appendChild(descEl);

    if (fake.warning) {
      const warningDiv = document.createElement('div');
      warningDiv.className = 'warning-note mt-4';

      const warningP = document.createElement('p');
      warningP.innerHTML = '<strong>💡 Insight: </strong>' + DOMPurify.sanitize(fake.warning);
      warningDiv.appendChild(warningP);

      modalBody.appendChild(warningDiv);
    }

    if (fake.guidance && Array.isArray(fake.guidance)) {
      const section = document.createElement('div');
      section.className = 'mt-4';

      const heading = document.createElement('h3');
      heading.className = 'font-semibold text-lg mb-2';
      heading.textContent = 'Implementation Guidance:';
      section.appendChild(heading);

      fake.guidance.forEach(item => {
        const stepDiv = document.createElement('div');
        stepDiv.className = 'mb-2';

        const stepP = document.createElement('p');
        stepP.className = 'font-semibold text-sm';
        stepP.textContent = item.step;
        stepDiv.appendChild(stepP);

        if (item.details) {
          const detailP = document.createElement('p');
          detailP.className = 'text-xs opacity-80 ml-2';
          detailP.textContent = item.details;
          stepDiv.appendChild(detailP);
        }

        section.appendChild(stepDiv);
      });

      modalBody.appendChild(section);
    }

    history.replaceState(null, '', '#t=' + encodeURIComponent(techId));
    document.title = techId + ': ' + fake.name + ' | AIDEFEND Framework';

    modal.classList.add('active');
    document.body.classList.add('modal-open');
  }
};

window.APRIL_FOOLS.init();
