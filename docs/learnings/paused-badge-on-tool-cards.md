# Tool Cards Should Show "Paused" Badge When Engagement Paused

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** LOW — visual clarity

## Problem

When engagement is paused, running tool call cards in the AI drawer keep showing "Running..." status. When stopped, they correctly show "Cancelled" badge (red). There's no "Paused" badge equivalent.

## Expected

When paused:
- Running tool cards → show "Paused" badge (yellow/orange)
- When resumed → badge changes back to "Running..."
- If stopped while paused → badge changes to "Cancelled"

## Implementation

In `index.html`, the existing stop handler at `setCtrlState('idle')` marks running badges as "Cancelled". Add similar logic for `setCtrlState('paused')`:

```js
if (state === 'paused') {
    document.querySelectorAll('.tool-status-badge.running').forEach(badge => {
        badge.textContent = 'Paused';
        badge.className = 'tool-status-badge paused';
    });
}
```

CSS for `.tool-status-badge.paused` likely already exists (from the agent chip paused styling). If not, add:
```css
.tool-status-badge.paused {
    background: color-mix(in srgb, var(--zerok-primary) 12%, transparent);
    color: var(--zerok-primary);
}
```
