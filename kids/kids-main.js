import { kidsDataEn, kidsDataZh } from './kids-data.js';

const translations = {
    en: {
        pageTitle: "🎈 AIDEFEND for Kids 🛡️",
        pageSubtitle: "Join us to protect our AI friends!",
        introTitle: "🌍 Why do we need to protect AI friends?",
        introText: `
            <p><strong>Hello, future Cyber Hero! 🛡️</strong></p>
            <p>You've probably already talked to an AI — like <strong>ChatGPT</strong>, <strong>Gemini</strong>, or <strong>Siri</strong>! AI is like a super-smart robot brain that helps with homework, helps doctors heal people, and even helps astronauts fly rockets!</p>
            <p>But sneaky <strong>"Computer Bad Guys"</strong> are out there trying to trick AI and do bad things — so we need YOU, the <strong>Cyber Hero!</strong> Let's learn the 7 magic shield moves the world's best defenders use! 👇</p>
        `,
        toggleBtn: "中文",
        badgeTitle: "AIDEFEND Cyber Hero",
        badgeSubtitle: "Congratulations! You've mastered all 7 defensive moves!",
        claimBadge: "🏆"
    },
    zh: {
        pageTitle: "🎈 AIDEFEND for Kids 🛡️",
        pageSubtitle: "跟我們一起保護 AI 夥伴的安全！",
        introTitle: "🌍 為什麼我們需要保護 AI 夥伴？",
        introText: `
            <p><strong>哈囉，AI 安全小英雄！🛡️</strong></p>
            <p>你可能已經跟 AI 說過話了——像是 <strong>ChatGPT</strong>、<strong>Gemini</strong>，或是爸爸媽媽手機裡的語音助理！AI 就像一個超強機器人大腦，能幫我們想問題、幫醫生看病，甚至幫太空人開火箭！</p>
            <p>但網路上有調皮的<strong>「電腦壞人」</strong>想破壞 AI，所以我們需要你——<strong>「AI 安全小英雄！」</strong>快來學世界上最厲害的 7 招安全魔法吧！👇</p>
        `,
        toggleBtn: "English",
        badgeTitle: "AIDEFEND 資安小英雄",
        badgeSubtitle: "恭喜！你已經學會全部 7 種AI安全絕招！",
        claimBadge: "🏆"
    }
};

let currentLang = 'en';

// Track individual card opens: "tacticIndex-cardIndex" strings
const exploredCards = new Set();

function isTacticDone(tacticIndex, itemCount) {
    for (let c = 0; c < itemCount; c++) {
        if (!exploredCards.has(`${tacticIndex}-${c}`)) return false;
    }
    return true;
}

// ── Shared fireworks helpers ──────────────────────────────────────────────
const FW_COLORS = [
    '#FF6B6B','#FF8E53','#FFE66D','#4ECDC4','#45B7D1',
    '#a29bfe','#fd79a8','#00cec9','#fdcb6e','#e17055',
    '#6c5ce7','#00b894','#fab1a0','#74b9ff'
];

function _fwRandomColor() {
    return FW_COLORS[Math.floor(Math.random() * FW_COLORS.length)];
}

function _fwSpawnBurst(particles, x, y, count, speedMin, speedMax, radiusMin, radiusMax) {
    for (let i = 0; i < count; i++) {
        const angle = (Math.PI * 2 / count) * i + (Math.random() - 0.5) * 0.4;
        const speed = speedMin + Math.random() * (speedMax - speedMin);
        particles.push({
            x, y,
            vx: Math.cos(angle) * speed,
            vy: Math.sin(angle) * speed,
            alpha: 1,
            color: _fwRandomColor(),
            radius: radiusMin + Math.random() * (radiusMax - radiusMin),
            trail: Math.random() < 0.35  // some particles leave fading trails
        });
    }
}

function _fwAnimate(ctx, particles, rafHolder, onEmpty) {
    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
    for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.09;
        p.vx *= 0.99;
        p.alpha -= p.trail ? 0.012 : 0.019;
        if (p.alpha <= 0) { particles.splice(i, 1); continue; }
        ctx.globalAlpha = p.alpha;
        ctx.fillStyle = p.color;
        if (p.trail) {
            // Elongated sparkle
            ctx.beginPath();
            ctx.ellipse(p.x, p.y, p.radius * 0.5, p.radius * 1.8, Math.atan2(p.vy, p.vx), 0, Math.PI * 2);
            ctx.fill();
        } else {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fill();
        }
    }
    ctx.globalAlpha = 1;
    if (particles.length === 0 && onEmpty) { onEmpty(); return; }
    rafHolder.id = requestAnimationFrame(() => _fwAnimate(ctx, particles, rafHolder, onEmpty));
}

// ── Badge overlay fireworks (continuous) ─────────────────────────────────
let fireworksInterval = null;

function startFireworks(canvas) {
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = [];
    const rafHolder = { id: null };

    function spawnFirework() {
        const x = Math.random() * canvas.width;
        const y = Math.random() * canvas.height * 0.6;
        const count = 70 + Math.floor(Math.random() * 50);
        _fwSpawnBurst(particles, x, y, count, 2, 7, 2.5, 5);
    }

    function animate() {
        _fwAnimate(ctx, particles, rafHolder, null);
    }

    spawnFirework();
    animate();
    const spawnTimer = setInterval(spawnFirework, 700);
    canvas._spawnTimer = spawnTimer;
    fireworksInterval = rafHolder; // store reference so stopFireworks can cancel
}

function stopFireworks(canvas) {
    if (fireworksInterval) { cancelAnimationFrame(fireworksInterval.id); fireworksInterval = null; }
    if (canvas._spawnTimer) { clearInterval(canvas._spawnTimer); canvas._spawnTimer = null; }
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
}

// ── Quick celebration fireworks (5 s, then auto-stop) ────────────────────
let quickFwTimer = null;
let quickFwRAF = { id: null };
let quickFwSpawn = null;

function startQuickFireworks(canvas, durationMs = 5000, cx = null, cy = null, focusW = null, focusH = null) {
    // Cancel any running quick fireworks
    if (quickFwTimer)  { clearTimeout(quickFwTimer);   quickFwTimer = null; }
    if (quickFwSpawn)  { clearInterval(quickFwSpawn);  quickFwSpawn = null; }
    if (quickFwRAF.id) { cancelAnimationFrame(quickFwRAF.id); quickFwRAF.id = null; }
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = [];

    const spreadX = cx !== null ? (focusW !== null ? focusW : Math.min(canvas.width, canvas.height) * 0.28) : null;
    const spreadY = cy !== null ? (focusH !== null ? focusH : Math.min(canvas.width, canvas.height) * 0.22) : null;

    function spawnFirework() {
        let x, y;
        if (cx !== null && cy !== null) {
            x = cx + (Math.random() - 0.5) * spreadX * 2;
            y = cy + (Math.random() - 0.5) * spreadY * 2;
            x = Math.max(20, Math.min(canvas.width  - 20, x));
            y = Math.max(20, Math.min(canvas.height - 20, y));
        } else {
            x = Math.random() * canvas.width;
            y = Math.random() * canvas.height * 0.65;
        }
        const count = 65 + Math.floor(Math.random() * 45);
        _fwSpawnBurst(particles, x, y, count, 2, 7, 2.5, 5);
        // Occasionally add a second simultaneous burst for richness
        if (Math.random() < 0.45) {
            let x2, y2;
            if (cx !== null && cy !== null) {
                x2 = cx + (Math.random() - 0.5) * spreadX * 2;
                y2 = cy + (Math.random() - 0.5) * spreadY * 2;
                x2 = Math.max(20, Math.min(canvas.width  - 20, x2));
                y2 = Math.max(20, Math.min(canvas.height - 20, y2));
            } else {
                x2 = Math.random() * canvas.width;
                y2 = Math.random() * canvas.height * 0.65;
            }
            _fwSpawnBurst(particles, x2, y2, 40 + Math.floor(Math.random() * 25), 1.5, 5, 2, 4);
        }
    }

    spawnFirework();
    _fwAnimate(ctx, particles, quickFwRAF, null);
    quickFwSpawn = setInterval(spawnFirework, 650);

    quickFwTimer = setTimeout(() => {
        if (quickFwSpawn) { clearInterval(quickFwSpawn); quickFwSpawn = null; }
        // Let remaining particles finish fading, then clear
        const waitForEmpty = setInterval(() => {
            if (particles.length === 0) {
                clearInterval(waitForEmpty);
                if (quickFwRAF.id) { cancelAnimationFrame(quickFwRAF.id); quickFwRAF.id = null; }
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }, 100);
        quickFwTimer = null;
    }, durationMs);
}

document.addEventListener('DOMContentLoaded', () => {
    const mainContainer = document.getElementById('kids-main');
    const modal = document.getElementById('kidsModal');
    const closeModalBtn = document.getElementById('closeModal');
    const modalBody = document.getElementById('modalBody');
    const langToggleBtn = document.getElementById('langToggleBtn');
    const progressTactics = document.getElementById('progressTactics');
    const claimBadgeBtn = document.getElementById('claimBadgeBtn');
    const badgeOverlay = document.getElementById('badgeOverlay');
    const closeBadgeBtn = document.getElementById('closeBadgeBtn');
    const fireworksCanvas = document.getElementById('fireworksCanvas');
    const celebrationCanvas = document.getElementById('celebrationCanvas');

    const modalNavLeft = document.getElementById('modalNavLeft');
    const modalNavRight = document.getElementById('modalNavRight');
    const modalScrollHint = document.getElementById('modalScrollHint');
    const downloadBadgeBtn = document.getElementById('downloadBadgeBtn');

    const DOMPurify = window.DOMPurify || null;
    let lastOpenedCard = null; // tracks which card element triggered the current modal
    let currentModalTacticIndex = null;
    let currentModalCardIndex = null;

    function getTacticEmoji(tactic) {
        return tactic.split(' ')[0];
    }

    function renderProgressBar() {
        const data = currentLang === 'en' ? kidsDataEn : kidsDataZh;
        progressTactics.innerHTML = '';
        data.forEach((tacticBlock, index) => {
            const itemCount = tacticBlock.items.length;
            const emoji = getTacticEmoji(tacticBlock.tactic);
            const done = isTacticDone(index, itemCount);

            const wrapper = document.createElement('div');
            wrapper.className = 'progress-tactic-wrapper';
            wrapper.title = tacticBlock.tactic;
            wrapper.addEventListener('click', () => {
                let targetEl = document.getElementById(`tactic-section-${index}`);
                let scrollBlock = 'start';
                const anyStarted = Array.from({length: itemCount}, (_, c) => exploredCards.has(`${index}-${c}`)).some(Boolean);
                if (anyStarted) {
                    for (let c = 0; c < itemCount; c++) {
                        if (!exploredCards.has(`${index}-${c}`)) {
                            const cardEl = document.getElementById(`tactic-card-${index}-${c}`);
                            if (cardEl) { targetEl = cardEl; scrollBlock = 'center'; }
                            break;
                        }
                    }
                }
                if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth', block: scrollBlock });
            });

            const pill = document.createElement('div');
            pill.className = 'progress-tactic' + (done ? ' progress-tactic--done' : '');
            pill.innerHTML = `<span class="progress-emoji">${emoji}</span>${done ? '<span class="progress-check">✓</span>' : ''}`;

            const dotsDiv = document.createElement('div');
            dotsDiv.className = 'progress-dots';
            for (let c = 0; c < itemCount; c++) {
                const dot = document.createElement('div');
                dot.className = 'progress-dot' + (exploredCards.has(`${index}-${c}`) ? ' progress-dot--done' : '');
                dotsDiv.appendChild(dot);
            }

            wrapper.appendChild(pill);
            wrapper.appendChild(dotsDiv);
            progressTactics.appendChild(wrapper);
        });

        const allDone = data.every((tacticBlock, i) => isTacticDone(i, tacticBlock.items.length));
        claimBadgeBtn.disabled = !allDone;
    }

    function markCardExplored(tacticIndex, cardIndex) {
        const key = `${tacticIndex}-${cardIndex}`;
        if (!exploredCards.has(key)) {
            const data = currentLang === 'en' ? kidsDataEn : kidsDataZh;
            const itemCount = data[tacticIndex]?.items.length ?? 2;
            const wasDone = isTacticDone(tacticIndex, itemCount);
            exploredCards.add(key);
            const cardEl = document.getElementById(`tactic-card-${tacticIndex}-${cardIndex}`);
            if (cardEl) cardEl.classList.add('kids-card--done');
            renderProgressBar();
            if (!wasDone && isTacticDone(tacticIndex, itemCount)) {
                startQuickFireworks(celebrationCanvas, 2000);
            }
        }
    }

    // ── Modal navigation helpers ──
    function getNavList() {
        const data = currentLang === 'en' ? kidsDataEn : kidsDataZh;
        const list = [];
        data.forEach((t, ti) => t.items.forEach((item, ci) => list.push({ ti, ci, item })));
        return list;
    }

    function updateNavButtons() {
        const navList = getNavList();
        const idx = navList.findIndex(n => n.ti === currentModalTacticIndex && n.ci === currentModalCardIndex);
        modalNavLeft.classList.toggle('hidden', idx <= 0);
        modalNavRight.classList.toggle('hidden', idx >= navList.length - 1);
    }

    function navigateModal(dir) {
        if (modal.classList.contains('hidden')) return;
        const navList = getNavList();
        const idx = navList.findIndex(n => n.ti === currentModalTacticIndex && n.ci === currentModalCardIndex);
        const newIdx = idx + dir;
        if (newIdx < 0 || newIdx >= navList.length) return;
        const next = navList[newIdx];
        currentModalTacticIndex = next.ti;
        currentModalCardIndex = next.ci;
        lastOpenedCard = document.getElementById(`tactic-card-${next.ti}-${next.ci}`);
        markCardExplored(next.ti, next.ci);
        openModal(next.item);
    }

    function updateScrollHint() {
        if (!modalScrollHint) return;
        const scrollable = modalBody.scrollHeight > modalBody.clientHeight + 20;
        const nearBottom = modalBody.scrollHeight - modalBody.scrollTop - modalBody.clientHeight < 30;
        modalScrollHint.classList.toggle('hidden', !scrollable || nearBottom);
    }

    function renderPage() {
        document.getElementById('pageTitle').innerText = translations[currentLang].pageTitle;
        document.getElementById('pageSubtitle').innerText = translations[currentLang].pageSubtitle;
        document.getElementById('introTitle').innerText = translations[currentLang].introTitle;
        document.getElementById('introText').innerHTML = translations[currentLang].introText;
        langToggleBtn.innerText = translations[currentLang].toggleBtn;

        mainContainer.innerHTML = '';

        const dataToRender = currentLang === 'en' ? kidsDataEn : kidsDataZh;

        dataToRender.forEach((tacticBlock, tacticIndex) => {
            const section = document.createElement('section');
            section.className = 'tactic-section';
            section.id = `tactic-section-${tacticIndex}`;

            const header = document.createElement('div');
            header.className = 'tactic-header';

            const tacticTitleTokens = tacticBlock.tactic.split(" ");
            const emoji = tacticTitleTokens[0];
            const titleText = tacticTitleTokens.slice(1).join(" ");

            header.innerHTML = `
                <span class="tactic-icon">${emoji}</span>
                <h2 class="tactic-title">${titleText}</h2>
            `;

            const desc = document.createElement('p');
            desc.className = 'tactic-desc';
            desc.textContent = tacticBlock.tacticDesc;

            const grid = document.createElement('div');
            grid.className = 'grid-container';

            tacticBlock.items.forEach((item, itemIndex) => {
                const card = document.createElement('div');
                card.className = 'kids-card' + (exploredCards.has(`${tacticIndex}-${itemIndex}`) ? ' kids-card--done' : '');
                card.id = `tactic-card-${tacticIndex}-${itemIndex}`;
                card.innerHTML = `
                    <span class="card-icon">${item.icon}</span>
                    <h3 class="card-title">${item.name}</h3>
                    <span class="card-done-badge">✓</span>
                `;
                card.addEventListener('click', () => {
                    lastOpenedCard = card;
                    currentModalTacticIndex = tacticIndex;
                    currentModalCardIndex = itemIndex;
                    markCardExplored(tacticIndex, itemIndex);
                    openModal(item);
                });
                grid.appendChild(card);
            });

            section.appendChild(header);
            section.appendChild(desc);
            section.appendChild(grid);
            mainContainer.appendChild(section);
        });

        renderProgressBar();
    }

    renderPage();

    langToggleBtn.addEventListener('click', () => {
        currentLang = currentLang === 'en' ? 'zh' : 'en';
        document.documentElement.lang = currentLang === 'en' ? 'en' : 'zh-Hant';
        renderPage();
    });

    function openModal(item) {
        // Stop any lingering celebration fireworks from previous modal close
        if (quickFwTimer)  { clearTimeout(quickFwTimer);   quickFwTimer = null; }
        if (quickFwSpawn)  { clearInterval(quickFwSpawn);  quickFwSpawn = null; }
        if (quickFwRAF.id) { cancelAnimationFrame(quickFwRAF.id); quickFwRAF.id = null; }
        celebrationCanvas.getContext('2d').clearRect(0, 0, celebrationCanvas.width, celebrationCanvas.height);

        let formattedDesc = item.description;
        if (DOMPurify) {
            formattedDesc = DOMPurify.sanitize(formattedDesc.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>'));
        } else {
            formattedDesc = formattedDesc.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        }

        const parentNoteTitle = currentLang === 'zh' ? '給大人的話' : 'A Note for Parents';
        const learnMoreText = currentLang === 'zh' ? '查看完整技術細節' : 'View full technique details';
        const aidefendLink = item.aidefendId ? `https://aidefend.net/#t=${encodeURIComponent(item.aidefendId)}` : '';
        const parentNoteHtml = item.parentNote ? `
            <div class="parent-note">
                <h3 class="parent-note-title">👨‍👩‍👧 ${parentNoteTitle}</h3>
                <p class="parent-note-id">${item.aidefendId}</p>
                <p class="parent-note-text">${item.parentNote}</p>
                ${aidefendLink ? `<a href="${aidefendLink}" target="_blank" rel="noopener noreferrer" class="parent-note-link">🔗 ${learnMoreText} →</a>` : ''}
            </div>
        ` : '';

        modalBody.innerHTML = `
            <span class="modal-header-icon">${item.icon}</span>
            <h2 class="modal-title">${item.name}</h2>
            <div class="modal-text">${formattedDesc}</div>
            ${parentNoteHtml}
        `;
        modal.classList.remove('hidden');
        requestAnimationFrame(() => {
            modal.scrollTop = 0;
            modal.querySelector('.kids-modal-content').scrollTop = 0;
            modalBody.scrollTop = 0;
            updateNavButtons();
            updateScrollHint();
        });
    }

    function closeModal() {
        if (!modal.classList.contains('hidden')) {
            const rect = lastOpenedCard ? lastOpenedCard.getBoundingClientRect() : null;
            const cx = rect ? rect.left + rect.width  / 2 : null;
            const cy = rect ? rect.top  + rect.height / 2 : null;
            const fw = rect ? rect.width  * 0.5 : null;
            const fh = rect ? rect.height * 0.5 : null;
            modal.classList.add('hidden');
            startQuickFireworks(celebrationCanvas, 1500, cx, cy, fw, fh);
        }
    }

    closeModalBtn.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    modalNavLeft.addEventListener('click', (e) => { e.stopPropagation(); navigateModal(-1); });
    modalNavRight.addEventListener('click', (e) => { e.stopPropagation(); navigateModal(1); });
    modalBody.addEventListener('scroll', updateScrollHint);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            if (!badgeOverlay.classList.contains('hidden')) closeBadge();
        }
        if (!modal.classList.contains('hidden')) {
            if (e.key === 'ArrowLeft')  { e.preventDefault(); navigateModal(-1); }
            if (e.key === 'ArrowRight') { e.preventDefault(); navigateModal(1); }
            if (e.key === 'ArrowUp')    { e.preventDefault(); modalBody.scrollBy({ top: -100, behavior: 'smooth' }); }
            if (e.key === 'ArrowDown')  { e.preventDefault(); modalBody.scrollBy({ top: 100, behavior: 'smooth' }); }
        }
    });

    // Badge & Fireworks
    claimBadgeBtn.addEventListener('click', () => {
        badgeOverlay.classList.remove('hidden');
        fireworksCanvas.width = window.innerWidth;
        fireworksCanvas.height = window.innerHeight;
        startFireworks(fireworksCanvas);
    });

    function closeBadge() {
        badgeOverlay.classList.add('hidden');
        stopFireworks(fireworksCanvas);
    }

    closeBadgeBtn.addEventListener('click', closeBadge);
    badgeOverlay.addEventListener('click', (e) => { if (e.target === badgeOverlay) closeBadge(); });

    // ── Badge download (static image) ──
    downloadBadgeBtn.addEventListener('click', () => {
        const link = document.createElement('a');
        link.href = './kids/badge.png';
        link.download = 'AIDEFEND-Cyber-Hero-Badge.png';
        link.click();
    });

    window.addEventListener('resize', () => {
        if (!badgeOverlay.classList.contains('hidden')) {
            fireworksCanvas.width = window.innerWidth;
            fireworksCanvas.height = window.innerHeight;
        }
    });
});
