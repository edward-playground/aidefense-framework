const DIRECTION_PARTS = Object.freeze({
    'up-left': { vertical: 'up', horizontal: 'left' },
    up: { vertical: 'up', horizontal: 'center' },
    'up-right': { vertical: 'up', horizontal: 'right' },
    left: { vertical: 'center', horizontal: 'left' },
    right: { vertical: 'center', horizontal: 'right' },
    'down-left': { vertical: 'down', horizontal: 'left' },
    down: { vertical: 'down', horizontal: 'center' },
    'down-right': { vertical: 'down', horizontal: 'right' }
});

const ATLAS_TECHNIQUE_ID_PATTERN = /^AML\.T\d{4}(?:\.\d{3})?$/;

export const ATLAS_SEARCH_DIRECTIONS = Object.freeze({
    'up-left': { arrow: '\u2196', label: 'upper left' },
    up: { arrow: '\u2191', label: 'above' },
    'up-right': { arrow: '\u2197', label: 'upper right' },
    left: { arrow: '\u2190', label: 'to the left' },
    right: { arrow: '\u2192', label: 'to the right' },
    'down-left': { arrow: '\u2199', label: 'lower left' },
    down: { arrow: '\u2193', label: 'below' },
    'down-right': { arrow: '\u2198', label: 'lower right' }
});

function clamp(value, minimum, maximum) {
    return Math.min(Math.max(value, minimum), Math.max(minimum, maximum));
}

export function normalizeAtlasSearchId(searchTerm) {
    const match = String(searchTerm || '').trim().match(/^(?:(?:aml\.)?t)?(\d{4}(?:\.\d{3})?)$/i);
    return match ? 'AML.T' + match[1] : null;
}

export function buildAtlasTechniqueUrl(atlasId) {
    const normalizedId = String(atlasId || '').trim().toUpperCase();
    if (!ATLAS_TECHNIQUE_ID_PATTERN.test(normalizedId)) {
        throw new TypeError('Invalid MITRE ATLAS technique ID: ' + atlasId);
    }
    return 'https://atlas.mitre.org/techniques/' + normalizedId;
}

/**
 * Classify a result against the actual two-dimensional visible region.
 * Any partial intersection counts as visible on that axis.
 */
export function classifyAtlasMatchDirection(matchRect, visibleRect, tolerance = 1) {
    let horizontal = 'center';
    let vertical = 'center';

    if (matchRect.right <= visibleRect.left + tolerance) horizontal = 'left';
    else if (matchRect.left >= visibleRect.right - tolerance) horizontal = 'right';

    if (matchRect.bottom <= visibleRect.top + tolerance) vertical = 'up';
    else if (matchRect.top >= visibleRect.bottom - tolerance) vertical = 'down';

    if (horizontal === 'center' && vertical === 'center') return 'visible';
    if (vertical === 'center') return horizontal;
    if (horizontal === 'center') return vertical;
    return vertical + '-' + horizontal;
}

export function distanceFromAtlasVisibleRegion(matchRect, visibleRect) {
    const dx = matchRect.right < visibleRect.left
        ? visibleRect.left - matchRect.right
        : matchRect.left > visibleRect.right
            ? matchRect.left - visibleRect.right
            : 0;
    const dy = matchRect.bottom < visibleRect.top
        ? visibleRect.top - matchRect.bottom
        : matchRect.top > visibleRect.bottom
            ? matchRect.top - visibleRect.bottom
            : 0;
    return Math.hypot(dx, dy);
}

export function getAtlasNavigationSide(direction, matchRect, visibleRect) {
    if (direction.includes('left')) return 'left';
    if (direction.includes('right')) return 'right';
    const matchCenterX = (matchRect.left + matchRect.right) / 2;
    const visibleCenterX = (visibleRect.left + visibleRect.right) / 2;
    return matchCenterX <= visibleCenterX ? 'left' : 'right';
}

/**
 * Collapse all off-screen matches into at most one left-side and one right-side
 * navigation choice. Multiple directions on one side use the horizontal side
 * arrow and target that side's topmost result. A single direction keeps its
 * precise arrow and targets the nearest result, preferring an exact ID match.
 */
export function selectAtlasNavigationSlots(matches, visibleRect) {
    const working = {
        left: { total: 0, directions: new Set(), topmost: null, nearest: null, nearestScore: Infinity },
        right: { total: 0, directions: new Set(), topmost: null, nearest: null, nearestScore: Infinity }
    };

    matches.forEach(match => {
        const direction = classifyAtlasMatchDirection(match.rect, visibleRect);
        if (direction === 'visible') return;
        const side = getAtlasNavigationSide(direction, match.rect, visibleRect);
        const slot = working[side];
        slot.total++;
        slot.directions.add(direction);

        if (!slot.topmost
            || match.rect.top < slot.topmost.rect.top
            || (match.rect.top === slot.topmost.rect.top && match.rect.left < slot.topmost.rect.left)) {
            slot.topmost = match;
        }

        const exactPriority = match.exact ? -1000000 : 0;
        const score = exactPriority + distanceFromAtlasVisibleRegion(match.rect, visibleRect);
        if (score < slot.nearestScore) {
            slot.nearestScore = score;
            slot.nearest = match;
        }
    });

    return Object.fromEntries(Object.entries(working).map(([side, slot]) => {
        if (!slot.total) return [side, null];
        const merged = slot.directions.size > 1;
        return [side, {
            side,
            total: slot.total,
            direction: merged ? side : slot.directions.values().next().value,
            target: merged ? slot.topmost.value : slot.nearest.value,
            merged
        }];
    }));
}

/**
 * Return stable horizontal-container and document scroll targets for a result.
 * An axis that is already fully visible is intentionally left unchanged.
 */
export function calculateAtlasRevealTargets({
    matchRect,
    scrollRect,
    scrollLeft,
    scrollWidth,
    clientWidth,
    windowScrollY,
    viewportTop,
    viewportBottom,
    documentHeight,
    viewportHeight,
    horizontalPadding = 16,
    verticalPadding = 16
}) {
    const safeLeft = scrollRect.left + horizontalPadding;
    const safeRight = scrollRect.right - horizontalPadding;
    const safeTop = viewportTop + verticalPadding;
    const safeBottom = viewportBottom - verticalPadding;

    let targetScrollLeft = scrollLeft;
    if (matchRect.left < safeLeft || matchRect.right > safeRight) {
        const matchCenterX = (matchRect.left + matchRect.right) / 2;
        const scrollCenterX = (scrollRect.left + scrollRect.right) / 2;
        targetScrollLeft = scrollLeft + matchCenterX - scrollCenterX;
    }
    targetScrollLeft = clamp(targetScrollLeft, 0, scrollWidth - clientWidth);

    let targetWindowScrollY = windowScrollY;
    if (matchRect.top < safeTop || matchRect.bottom > safeBottom) {
        const matchCenterY = (matchRect.top + matchRect.bottom) / 2;
        const viewportCenterY = (safeTop + safeBottom) / 2;
        targetWindowScrollY = windowScrollY + matchCenterY - viewportCenterY;
    }
    const maximumWindowScrollY = Math.max(0, documentHeight - viewportHeight);
    targetWindowScrollY = clamp(targetWindowScrollY, 0, maximumWindowScrollY);

    return { targetScrollLeft, targetWindowScrollY };
}

export function getAtlasIndicatorAnchor(direction, visibleRect, horizontalInset, verticalInset) {
    const parts = DIRECTION_PARTS[direction];
    if (!parts) throw new Error('Unknown ATLAS search direction: ' + direction);

    const x = parts.horizontal === 'left'
        ? visibleRect.left + horizontalInset
        : parts.horizontal === 'right'
            ? visibleRect.right - horizontalInset
            : (visibleRect.left + visibleRect.right) / 2;
    const y = parts.vertical === 'up'
        ? visibleRect.top + verticalInset
        : parts.vertical === 'down'
            ? visibleRect.bottom - verticalInset
            : (visibleRect.top + visibleRect.bottom) / 2;

    return { x, y };
}
