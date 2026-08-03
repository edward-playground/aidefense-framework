import assert from 'node:assert/strict';
import test from 'node:test';

import {
    calculateAtlasRevealTargets,
    classifyAtlasMatchDirection,
    distanceFromAtlasVisibleRegion,
    getAtlasIndicatorAnchor,
    getAtlasNavigationSide,
    normalizeAtlasSearchId,
    selectAtlasNavigationSlots
} from '../js/atlas-matrix-navigation.js';

const visible = { left: 100, right: 500, top: 200, bottom: 700 };

test('normalizes every supported ATLAS ID search form without accepting substrings', () => {
    assert.equal(normalizeAtlasSearchId('0115'), 'AML.T0115');
    assert.equal(normalizeAtlasSearchId('t0115'), 'AML.T0115');
    assert.equal(normalizeAtlasSearchId('AML.T0115'), 'AML.T0115');
    assert.equal(normalizeAtlasSearchId(' t0115.002 '), 'AML.T0115.002');
    assert.equal(normalizeAtlasSearchId('find t0115'), null);
});

test('classifies every off-screen direction and preserves partial visibility', () => {
    const cases = [
        [{ left: 20, right: 80, top: 100, bottom: 180 }, 'up-left'],
        [{ left: 200, right: 300, top: 100, bottom: 180 }, 'up'],
        [{ left: 520, right: 600, top: 100, bottom: 180 }, 'up-right'],
        [{ left: 20, right: 80, top: 300, bottom: 400 }, 'left'],
        [{ left: 520, right: 600, top: 300, bottom: 400 }, 'right'],
        [{ left: 20, right: 80, top: 720, bottom: 800 }, 'down-left'],
        [{ left: 200, right: 300, top: 720, bottom: 800 }, 'down'],
        [{ left: 520, right: 600, top: 720, bottom: 800 }, 'down-right'],
        [{ left: 200, right: 300, top: 300, bottom: 400 }, 'visible'],
        [{ left: 90, right: 110, top: 690, bottom: 710 }, 'visible']
    ];

    cases.forEach(([rect, expected]) => {
        assert.equal(classifyAtlasMatchDirection(rect, visible), expected);
    });
});

test('measures the nearest result by its real two-dimensional gap', () => {
    assert.equal(distanceFromAtlasVisibleRegion(
        { left: 200, right: 300, top: 750, bottom: 800 },
        visible
    ), 50);
    assert.equal(distanceFromAtlasVisibleRegion(
        { left: 550, right: 600, top: 750, bottom: 800 },
        visible
    ), Math.hypot(50, 50));
});

test('assigns vertical results by horizontal half and preserves explicit sides', () => {
    assert.equal(getAtlasNavigationSide('up-left', { left: 600, right: 650 }, visible), 'left');
    assert.equal(getAtlasNavigationSide('down-right', { left: 0, right: 50 }, visible), 'right');
    assert.equal(getAtlasNavigationSide('up', { left: 120, right: 180 }, visible), 'left');
    assert.equal(getAtlasNavigationSide('down', { left: 360, right: 440 }, visible), 'right');
});

test('collapses multiple directions per side and targets the topmost result', () => {
    const slots = selectAtlasNavigationSlots([
        { value: 'upper-left', rect: { left: 20, right: 80, top: 100, bottom: 180 }, exact: false },
        { value: 'lower-left-exact', rect: { left: 20, right: 80, top: 740, bottom: 800 }, exact: true },
        { value: 'visible', rect: { left: 200, right: 300, top: 300, bottom: 400 }, exact: false },
        { value: 'upper-right', rect: { left: 520, right: 600, top: 100, bottom: 180 }, exact: false },
        { value: 'right', rect: { left: 520, right: 600, top: 300, bottom: 400 }, exact: false }
    ], visible);

    assert.deepEqual(slots.left, {
        side: 'left', total: 2, direction: 'left', target: 'upper-left', merged: true
    });
    assert.deepEqual(slots.right, {
        side: 'right', total: 2, direction: 'right', target: 'upper-right', merged: true
    });
});

test('keeps a single precise direction and prefers its exact match target', () => {
    const slots = selectAtlasNavigationSlots([
        { value: 'nearest-down', rect: { left: 120, right: 180, top: 720, bottom: 780 }, exact: false },
        { value: 'exact-down', rect: { left: 120, right: 180, top: 900, bottom: 960 }, exact: true }
    ], visible);

    assert.deepEqual(slots.left, {
        side: 'left', total: 2, direction: 'down', target: 'exact-down', merged: false
    });
    assert.equal(slots.right, null);
});

test('keeps an already-visible axis stable while revealing the other axis', () => {
    const result = calculateAtlasRevealTargets({
        matchRect: { left: 180, right: 360, top: 1200, bottom: 1300 },
        scrollRect: { left: 100, right: 500 },
        scrollLeft: 400,
        scrollWidth: 3200,
        clientWidth: 400,
        windowScrollY: 0,
        viewportTop: 200,
        viewportBottom: 700,
        documentHeight: 4000,
        viewportHeight: 800
    });

    assert.equal(result.targetScrollLeft, 400);
    assert.equal(result.targetWindowScrollY, 800);
});

test('reveals a diagonal result on both axes and clamps document bounds', () => {
    const result = calculateAtlasRevealTargets({
        matchRect: { left: 900, right: 1100, top: 1500, bottom: 1600 },
        scrollRect: { left: 100, right: 500 },
        scrollLeft: 0,
        scrollWidth: 2400,
        clientWidth: 400,
        windowScrollY: 100,
        viewportTop: 200,
        viewportBottom: 700,
        documentHeight: 5000,
        viewportHeight: 800
    });

    assert.equal(result.targetScrollLeft, 700);
    assert.equal(result.targetWindowScrollY, 1200);

    const clamped = calculateAtlasRevealTargets({
        matchRect: { left: -500, right: -400, top: -900, bottom: -800 },
        scrollRect: { left: 100, right: 500 },
        scrollLeft: 0,
        scrollWidth: 2400,
        clientWidth: 400,
        windowScrollY: 0,
        viewportTop: 200,
        viewportBottom: 700,
        documentHeight: 5000,
        viewportHeight: 800
    });
    assert.deepEqual(clamped, { targetScrollLeft: 0, targetWindowScrollY: 0 });
});

test('anchors indicators to matrix edges and corners', () => {
    assert.deepEqual(getAtlasIndicatorAnchor('up-left', visible, 32, 36), { x: 132, y: 236 });
    assert.deepEqual(getAtlasIndicatorAnchor('down', visible, 32, 36), { x: 300, y: 664 });
    assert.deepEqual(getAtlasIndicatorAnchor('right', visible, 32, 36), { x: 468, y: 450 });
    assert.deepEqual(getAtlasIndicatorAnchor('down-right', visible, 32, 36), { x: 468, y: 664 });
});
