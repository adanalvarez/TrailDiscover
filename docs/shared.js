// Helpers shared by the event browser (app.js) and the Insights page (insights.js).
(function () {
    'use strict';

    // ATT&CK release the catalogue is mapped to. Links are pinned to it so they keep
    // pointing at the technique TrailDiscover meant (v19 revoked some, e.g. T1562).
    // Keep in step with ATTACK_VERSION in tools/build.py.
    const ATTACK_VERSION = 'v18';

    // Enterprise tactics in ATT&CK matrix order. Pages show only the ones the catalogue uses
    // (see activeTactics), so a newly used tactic appears without code changes.
    const TACTICS = [
        ['TA0043', 'Reconnaissance'],
        ['TA0042', 'Resource Development'],
        ['TA0001', 'Initial Access'],
        ['TA0002', 'Execution'],
        ['TA0003', 'Persistence'],
        ['TA0004', 'Privilege Escalation'],
        ['TA0005', 'Defense Evasion'],
        ['TA0006', 'Credential Access'],
        ['TA0007', 'Discovery'],
        ['TA0008', 'Lateral Movement'],
        ['TA0009', 'Collection'],
        ['TA0011', 'Command and Control'],
        ['TA0010', 'Exfiltration'],
        ['TA0040', 'Impact'],
    ];
    const TACTIC_ORDER = new Map(TACTICS.map(([id], i) => [id, i]));

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function safeUrl(url) {
        return /^https?:\/\//i.test(url || '') ? url : '';
    }

    // External link; `text` is plain text and is escaped here.
    function extLink(url, text, className) {
        const href = safeUrl(url);
        if (!href) return esc(text);
        return `<a href="${esc(href)}" target="_blank" rel="noopener"${className ? ` class="${className}"` : ''}>${esc(text)}</a>`;
    }

    // Host name without "www.", unwrapping web.archive.org copies to the original site.
    function domainOf(url) {
        try {
            const u = new URL(url);
            if (u.hostname.endsWith('web.archive.org')) {
                const original = u.pathname.slice(u.pathname.indexOf('http'));
                if (original.startsWith('http')) return new URL(original).hostname.replace(/^www\./, '');
            }
            return u.hostname.replace(/^www\./, '');
        } catch (e) {
            return '';
        }
    }

    function plural(n, one) {
        return `${n} ${n === 1 ? one : one + 's'}`;
    }

    // "TA0003 - Persistence" -> { id: "TA0003", name: "Persistence" }. Also accepts the
    // "T1078.004: Name" and "T1562.001 Name" variants found in some event files.
    function splitAttack(value) {
        const m = /^\s*(TA?\d{4}(?:\.\d{3})?)\b\s*[-:]?\s*(.*)$/.exec(value || '');
        return m ? { id: m[1], name: m[2].trim() } : { id: '', name: String(value || '') };
    }

    function attackUrl(id) {
        const base = `https://attack.mitre.org/versions/${ATTACK_VERSION}`;
        if (/^TA\d{4}$/.test(id)) return `${base}/tactics/${id}/`;
        const m = /^(T\d{4})(?:\.(\d{3}))?$/.exec(id);
        if (!m) return '';
        return `${base}/techniques/${m[1]}/${m[2] ? m[2] + '/' : ''}`;
    }

    function eventId(raw) {
        return `${raw.awsService}-${raw.eventName}`;
    }

    // Incident sources are identified by a short, stable hash of the normalised URL.
    function normUrl(url) {
        let s = String(url || '').trim();
        try {
            const u = new URL(s);
            u.hash = '';
            s = u.protocol + '//' + u.host.toLowerCase() + u.pathname + u.search;
        } catch (e) { /* keep the trimmed string */ }
        return s.replace(/\/+$/, '');
    }

    // 32-bit FNV-1a as 8 hex characters.
    function sourceId(url) {
        const s = normUrl(url);
        let h = 0x811c9dc5;
        for (let i = 0; i < s.length; i++) {
            h ^= s.charCodeAt(i);
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return h.toString(16).padStart(8, '0');
    }

    // Distinct incident sources of one event, as source ids.
    function sourceIdsOf(raw) {
        return [...new Set((raw.incidents || []).filter(inc => safeUrl(inc.link)).map(inc => sourceId(inc.link)))];
    }

    // Tactic ids (in matrix order) that at least one event is mapped to.
    function activeTactics(rawEvents) {
        const used = new Set();
        rawEvents.forEach(raw => (raw.mitreAttackTactics || []).forEach(t => used.add(splitAttack(t).id)));
        return TACTICS.filter(([id]) => used.has(id));
    }

    // Lower-cased service key -> the spelling most events use (e.g. "Lightsail" vs "LightSail").
    function serviceLabels(rawEvents) {
        const spellings = new Map();
        rawEvents.forEach(raw => {
            const key = raw.awsService.toLowerCase();
            if (!spellings.has(key)) spellings.set(key, new Map());
            const counts = spellings.get(key);
            counts.set(raw.awsService, (counts.get(raw.awsService) || 0) + 1);
        });
        const labels = new Map();
        spellings.forEach((counts, key) => labels.set(key, [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]));
        return labels;
    }

    // Incident sources across the catalogue: id -> { id, url, title, domain, eventIds }.
    function indexSources(rawEvents) {
        const sources = new Map();
        rawEvents.forEach(raw => {
            (raw.incidents || []).forEach(inc => {
                if (!safeUrl(inc.link)) return;
                const id = sourceId(inc.link);
                if (!sources.has(id)) {
                    sources.set(id, { id, url: inc.link, title: inc.description || inc.link, domain: domainOf(inc.link), eventIds: [] });
                }
                const src = sources.get(id);
                const evId = eventId(raw);
                if (!src.eventIds.includes(evId)) src.eventIds.push(evId);
            });
        });
        return sources;
    }

    // events.json can briefly list an event twice if it was not regenerated; keep the first.
    function uniqueEvents(rawEvents) {
        const seen = new Set();
        return rawEvents.filter(raw => {
            const id = eventId(raw);
            if (seen.has(id)) return false;
            seen.add(id);
            return true;
        });
    }

    window.TD = {
        TACTICS, TACTIC_ORDER,
        esc, safeUrl, extLink, domainOf, plural, splitAttack, attackUrl,
        eventId, normUrl, sourceId, sourceIdsOf, indexSources, uniqueEvents, activeTactics, serviceLabels,
    };
})();
