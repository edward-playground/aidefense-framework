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
    const modal = document.getElementById('infoModal');

    if (!modalBody || !modal) return;

    modalBody.innerHTML = '';

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
