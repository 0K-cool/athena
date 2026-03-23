# System CONTROL Card Text Clipping

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** MEDIUM — operator misses critical info

## Problem

System CONTROL cards in the AI drawer clip long messages. Example: "Assign VF to verify using different tools than AR. Meth..." — cuts off mid-word, losing the verification method instructions.

## Fix

Check CSS for `.timeline-event .event-detail` or the system card body — likely has `max-height`, `overflow: hidden`, or `text-overflow: ellipsis`. Either:
1. Remove the height cap (let cards expand)
2. Add "show more" toggle for long messages
3. Increase max-height to fit typical system messages
