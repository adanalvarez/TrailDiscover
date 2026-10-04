// Insights page: incident sources, ATT&CK techniques and AWS services in the catalogue.
// Counts come from the same events.json the event table uses, so every number links to a
// table view that returns exactly that many events. The ATT&CK index is generated at build
// time from the same file (tools/build.py) and carries its data version.
(function () {
    'use strict';

    const {
        esc, safeUrl, extLink, plural, splitAttack, attackUrl,
        eventId, normUrl, sourceIdsOf, indexSources, uniqueEvents, activeTactics, serviceLabels,
    } = window.TD;

    const NAVIGATOR = 'https://mitre-attack.github.io/attack-navigator/';
    // Rows shown before "Show all", so each section stays short.
    const LIMIT = { sources: 10, services: 12, techniquesPerTactic: 4 };
    // Short column headers; the full name is in the header's title.
    const SHORT_TACTIC = {
        TA0043: 'Recon', TA0042: 'Resource Dev.', TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence',
        TA0004: 'Priv. Escalation', TA0005: 'Def. Evasion', TA0006: 'Cred. Access', TA0007: 'Discovery',
        TA0008: 'Lateral Mov.', TA0009: 'Collection', TA0011: 'C2', TA0010: 'Exfiltration', TA0040: 'Impact',
    };

    const el = id => document.getElementById(id);
    const params = new URLSearchParams(location.search);

    const state = {
        srcSort: { key: params.get('src_sort') || 'events', order: params.get('src_order') },
        srcQ: params.get('src_q') || '',
        srcService: (params.get('src_service') || '').toLowerCase(),
        svcSort: { key: params.get('svc_sort') || 'events', order: params.get('svc_order') },
        source: (params.get('source') || '').toLowerCase(),
        expanded: { sources: false, services: false, techniques: false },
    };

    let events = [];
    let byId = new Map();
    let sources = new Map();
    let tactics = [];             // [id, name] of the tactics the catalogue uses, in ATT&CK order
    let tacticIndex = new Map();  // tactic id -> column index
    let labels = new Map();       // service key -> display label

    // ------------------------------------------------------------------
    // Sorting and URL state
    // ------------------------------------------------------------------

    const TEXT_KEYS = new Set(['title', 'label']);
    const SORT_KEYS = { sources: ['title', 'events'], services: ['label', 'events', 'wild', 'sources'] };

    function defaultDir(key) {
        return TEXT_KEYS.has(key) ? 1 : -1;
    }

    // Validate a sort from the URL once the tactic columns are known.
    function resolveSort(sort, table) {
        const valid = SORT_KEYS[table].includes(sort.key) || tacticIndex.has(sort.key);
        const key = valid ? sort.key : 'events';
        return { key, dir: sort.order === 'asc' ? 1 : sort.order === 'desc' ? -1 : defaultDir(key) };
    }

    let urlTimer = null;
    // Filter typing updates the URL at most every 250ms.
    function updateUrl() {
        clearTimeout(urlTimer);
        urlTimer = setTimeout(() => {
            const p = new URLSearchParams();
            const putSort = (sort, keyParam, orderParam) => {
                if (sort.key !== 'events') p.set(keyParam, sort.key);
                if (sort.dir !== defaultDir(sort.key)) p.set(orderParam, sort.dir === 1 ? 'asc' : 'desc');
            };
            putSort(state.srcSort, 'src_sort', 'src_order');
            if (state.srcQ) p.set('src_q', state.srcQ);
            if (state.srcService) p.set('src_service', labels.get(state.srcService) || state.srcService);
            putSort(state.svcSort, 'svc_sort', 'svc_order');
            if (state.source) p.set('source', state.source);
            const qs = p.toString();
            history.replaceState(null, '', location.pathname + (qs ? `?${qs}` : '') + location.hash);
        }, 250);
    }

    function table(q) {
        return `./${q ? '?' + q : ''}`;
    }

    function compareRows(sort, valueOf, nameOf) {
        return (a, b) => {
            const va = valueOf(a, sort.key);
            const vb = valueOf(b, sort.key);
            const d = typeof va === 'string' ? va.localeCompare(vb, 'en', { sensitivity: 'base' }) : va - vb;
            return sort.dir * d || nameOf(a).localeCompare(nameOf(b), 'en', { sensitivity: 'base' });
        };
    }

    function bindSort(tableEl, getSort, rerender) {
        tableEl.addEventListener('click', e => {
            const btn = e.target.closest('button[data-sort]');
            if (!btn) return;
            const sort = getSort();
            const key = btn.dataset.sort;
            sort.dir = sort.key === key ? -sort.dir : defaultDir(key);
            sort.key = key;
            rerender();
            updateUrl();
            tableEl.querySelector(`button[data-sort="${key}"]`).focus();
        });
    }

    // "Show all" / "Show fewer" below a section.
    function renderMore(button, section, shown, total, noun) {
        button.hidden = total <= shown && !state.expanded[section];
        button.textContent = state.expanded[section] ? `Show fewer ${noun}` : `Show all ${total} ${noun}`;
        button.setAttribute('aria-expanded', String(state.expanded[section]));
    }

    // ------------------------------------------------------------------
    // Data
    // ------------------------------------------------------------------

    function prepare(raw) {
        const tacticIds = (raw.mitreAttackTactics || []).map(t => splitAttack(t).id);
        return {
            raw,
            id: eventId(raw),
            name: raw.eventName,
            service: raw.awsService,
            serviceKey: raw.awsService.toLowerCase(),
            eventSource: (raw.eventSource || '').replace(/\.amazonaws\.com$/, ''),
            wild: !!raw.usedInWild,
            tactics: [...new Set(tacticIds)].filter(id => tacticIndex.has(id)),
            research: (raw.researchLinks || []).filter(r => safeUrl(r.link)),
            sourceIds: sourceIdsOf(raw),
        };
    }

    // One count per tactic column.
    function tacticCounts(evs) {
        const counts = tactics.map(() => 0);
        evs.forEach(ev => ev.tactics.forEach(t => { counts[tacticIndex.get(t)] += 1; }));
        return counts;
    }

    // ------------------------------------------------------------------
    // Presence strip (shared by the sources and services tables)
    // ------------------------------------------------------------------

    function stripCells(counts, hrefFor) {
        return tactics.map(([ta, name], i) => {
            const n = counts[i];
            if (!n) return '<td class="strip__cell"></td>';
            const label = `${name}: ${plural(n, 'event')}`;
            return `<td class="strip__cell is-on"><a href="${esc(hrefFor(ta))}" aria-label="${esc(label)}" title="${esc(label)}">${n}</a></td>`;
        }).join('');
    }

    // Phones show the strip as a line of text instead of narrow columns.
    function stripLine(counts, hrefFor) {
        const parts = tactics.map(([ta, name], i) => (counts[i] ? `<a href="${esc(hrefFor(ta))}">${esc(name)} ${counts[i]}</a>` : '')).filter(Boolean);
        return parts.length ? `<p class="strip-line">${parts.join(' · ')}</p>` : '';
    }

    function headerHtml(columns, sort) {
        const th = (key, label, cls, title) => {
            const sorted = sort.key === key ? ` aria-sort="${sort.dir === 1 ? 'ascending' : 'descending'}"` : '';
            return `<th scope="col" class="${cls}"${sorted}${title ? ` title="${esc(title)}"` : ''}>` +
                `<button type="button" data-sort="${key}">${label}</button></th>`;
        };
        return '<thead><tr>' +
            columns.map(c => th(c.key, esc(c.label), c.cls || '')).join('') +
            tactics.map(([ta, name]) => th(ta, `<span aria-hidden="true">${esc(SHORT_TACTIC[ta] || name)}</span><span class="visually-hidden">${esc(name)}</span>`,
                'strip__head', `${name} (${ta}): sort by this tactic`)).join('') +
            '</tr></thead>';
    }

    // ------------------------------------------------------------------
    // Intro and header stats
    // ------------------------------------------------------------------

    function renderIntro() {
        const linked = events.filter(ev => ev.sourceIds.length).length;
        const unlinked = events.length - linked;
        const neither = events.filter(ev => !ev.sourceIds.length && !ev.research.length).length;
        const wild = events.filter(ev => ev.wild).length;

        el('stats').innerHTML = `${events.length} events · ${labels.size} AWS services · ${sources.size} incident sources · ` +
            `<span class="stats__wild"><span class="wild-dot" aria-hidden="true"></span>${wild} seen in the wild</span>`;

        el('introLede').innerHTML =
            `TrailDiscover catalogues <a href="${table('')}"><strong>${events.length}</strong> CloudTrail events</a>. ` +
            `<a href="${table('minsources=1')}"><strong>${linked}</strong></a> are linked to at least one of ` +
            `<a href="#incident-sources"><strong>${sources.size}</strong> public incident sources</a>; ` +
            `the other <a href="${table('nosources=1')}"><strong>${unlinked}</strong></a> are backed only by research links` +
            (neither ? ` (${neither} have no reference yet)` : '') + '.';

        const items = [];
        const walk = events.filter(ev => ev.sourceIds.length >= 4)
            .sort((a, b) => b.sourceIds.length - a.sourceIds.length || a.name.localeCompare(b.name));
        if (walk.length) {
            items.push(`<li><a href="${table('minsources=4&sort=incidents')}#${esc(walk[0].id)}">Walk the ${walk.length} events linked from 4 or more incident sources</a>, starting with the most linked.</li>`);
        }
        const example = [...sources.values()]
            .filter(s => s.eventIds.length >= 8 && s.eventIds.length <= 20)
            .map(s => ({ s, tactics: tacticCounts(s.eventIds.map(id => byId.get(id))).filter(Boolean).length }))
            .sort((a, b) => b.tactics - a.tactics || b.s.eventIds.length - a.s.eventIds.length || a.s.title.localeCompare(b.s.title))[0];
        if (example) {
            items.push(`<li><a href="${table(`incident=${example.s.id}&sort=tactic`)}">Open the ${example.s.eventIds.length} events catalogued from “${esc(example.s.title)}”</a> in ATT&amp;CK order.</li>`);
        }
        items.push('<li><a href="#techniques">Load the techniques into ATT&amp;CK Navigator</a> and compare them with your own coverage layer.</li>');
        el('startHere').innerHTML = items.join('');
    }

    // ------------------------------------------------------------------
    // Incident sources
    // ------------------------------------------------------------------

    let multiSources = [];
    let singleSources = [];

    function buildSources() {
        // Research links by URL, to note when a source is also filed as research elsewhere.
        const research = new Map();
        events.forEach(ev => ev.research.forEach(r => {
            const key = normUrl(r.link);
            if (!research.has(key)) research.set(key, []);
            research.get(key).push({ id: ev.id, title: r.description });
        }));

        const rows = [...sources.values()].map(src => {
            const evs = src.eventIds.map(id => byId.get(id)).filter(Boolean);
            const serviceCounts = new Map();
            evs.forEach(ev => serviceCounts.set(ev.serviceKey, (serviceCounts.get(ev.serviceKey) || 0) + 1));
            const serviceKeys = [...serviceCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k]) => k);
            const alsoResearch = (research.get(normUrl(src.url)) || [])
                .filter(r => !src.eventIds.includes(r.id) && r.title === src.title).length;
            let host = '';
            try { host = new URL(src.url).hostname; } catch (e) { /* ignore */ }
            return {
                ...src,
                n: evs.length,
                counts: tacticCounts(evs),
                serviceKeys,
                alsoResearch,
                archived: /(^|\.)web\.archive\.org$/.test(host),
                tweet: /(^|\.)(twitter|x)\.com$/.test(host),
                events: evs,
                haystack: [src.title, src.domain, ...serviceKeys.map(k => labels.get(k)), ...evs.map(ev => `${ev.service} ${ev.name}`)].join(' ').toLowerCase(),
            };
        });
        multiSources = rows.filter(r => r.n >= 2);
        singleSources = rows.filter(r => r.n === 1).sort((a, b) => a.title.localeCompare(b.title));

        const sizes = rows.map(r => r.n).sort((a, b) => a - b);
        const median = sizes.length ? sizes[Math.floor((sizes.length - 1) / 2)] : 0;
        el('srcLede').textContent = `${sources.size} documents that TrailDiscover cites as incident evidence, and the events catalogued from each. ` +
            `${multiSources.length} have two or more events (median ${median} per source); ${singleSources.length} have one.`;
    }

    function sourceValue(row, key) {
        if (key === 'title') return row.title;
        if (key === 'events') return row.n;
        return row.counts[tacticIndex.get(key)] || 0;
    }

    function sourceMatches(row) {
        const q = state.srcQ.trim().toLowerCase();
        return (!q || row.haystack.includes(q)) && (!state.srcService || row.serviceKeys.includes(state.srcService));
    }

    function renderSources() {
        const filtering = !!(state.srcQ.trim() || state.srcService);
        const matches = multiSources.filter(sourceMatches).sort(compareRows(state.srcSort, sourceValue, r => r.title));
        const showAll = state.expanded.sources || filtering;
        const list = showAll ? matches : matches.slice(0, LIMIT.sources);
        const maxN = Math.max(1, ...multiSources.map(r => r.n));
        const columns = [{ key: 'title', label: 'Source', cls: 'col-source' }, { key: 'events', label: 'Events', cls: 'col-num' }];

        const body = list.map(r => {
            const tactic = ta => table(`incident=${r.id}&tactic=${ta}`);
            const keys = r.serviceKeys.map(k => labels.get(k));
            const services = keys.slice(0, 3).join(', ') + (keys.length > 3 ? ` +${keys.length - 3}` : '');
            const tags = (r.archived ? '<span class="ins-tag">archived copy</span>' : '') + (r.tweet ? '<span class="ins-tag">tweet</span>' : '');
            const note = r.alsoResearch ? `<p class="src-note">Also cited as research on ${plural(r.alsoResearch, 'other event')} (not counted here).</p>` : '';
            return `<tr id="src-${r.id}"${r.id === state.source ? ' class="is-target"' : ''}>` +
                `<th scope="row" class="col-source">${extLink(r.url, r.title, 'src-title')}` +
                `<span class="src-meta"><span class="mono">${esc(r.domain)}</span>${tags}<span>${esc(services)}</span></span>${note}` +
                `${stripLine(r.counts, tactic)}</th>` +
                `<td class="col-num"><a href="${table(`incident=${r.id}`)}" aria-label="Open the ${r.n} events catalogued from this source">${r.n}</a>` +
                `<span class="count-bar" style="width:${Math.max(6, Math.round(100 * r.n / maxN))}%"></span></td>` +
                stripCells(r.counts, tactic) +
                '</tr>';
        }).join('');

        const empty = `<tr><td class="ins-empty" colspan="${columns.length + tactics.length}">No sources match this filter.</td></tr>`;
        el('srcTable').innerHTML = el('srcTable').querySelector('caption').outerHTML +
            headerHtml(columns, state.srcSort) + `<tbody>${list.length ? body : empty}</tbody>`;
        el('srcCount').textContent = filtering
            ? `${matches.length} of ${multiSources.length} sources with two or more events match`
            : `Showing ${list.length} of ${multiSources.length} sources with two or more events`;
        if (filtering) el('srcMore').hidden = true;
        else renderMore(el('srcMore'), 'sources', list.length, matches.length, 'sources');

        el('srcServiceNote').hidden = !state.srcService;
        if (state.srcService) {
            el('srcServiceNote').innerHTML = `Sources with ${esc(labels.get(state.srcService) || state.srcService)} events. ` +
                '<button type="button" class="link-button" data-clear-service>Show all services</button>';
        }

        const singles = singleSources.filter(sourceMatches);
        el('singleSummary').textContent = `${singles.length}${filtering ? ` of ${singleSources.length}` : ''} sources with a single catalogued event`;
        el('singleList').innerHTML = singles.map(r => {
            const ev = r.events[0];
            return `<li id="src-${r.id}"${r.id === state.source ? ' class="is-target"' : ''}>${extLink(r.url, r.title)} ` +
                `<span class="mono src-domain">${esc(r.domain)}</span> · ` +
                `<a class="mono" href="./#${esc(ev.id)}">${esc(ev.service)} ${esc(ev.name)}</a></li>`;
        }).join('');
    }

    function showTargetSource() {
        if (!state.source) return;
        const exists = multiSources.concat(singleSources).find(r => r.id === state.source);
        if (!exists) return;
        if (!sourceMatches(exists)) {
            state.srcQ = '';
            state.srcService = '';
            el('srcFilter').value = '';
        }
        state.expanded.sources = true;
        renderSources();
        updateUrl();
        const target = document.getElementById(`src-${state.source}`);
        if (!target) return;
        if (target.tagName === 'LI') el('singles').open = true;
        target.scrollIntoView({ block: 'center' });
        const link = target.querySelector('a');
        if (link) link.focus({ preventScroll: true });
    }

    // ------------------------------------------------------------------
    // ATT&CK techniques
    // ------------------------------------------------------------------

    let techIndex = null;

    function renderTechniques() {
        const index = techIndex;
        const tagged = new Map();
        events.forEach(ev => ev.tactics.forEach(t => tagged.set(t, (tagged.get(t) || 0) + 1)));
        const cellsByTactic = new Map();
        index.cells.forEach(c => {
            if (!cellsByTactic.has(c.tactic)) cellsByTactic.set(c.tactic, []);
            cellsByTactic.get(c.tactic).push(c);
        });
        const unplaced = new Map(index.unplaced.map(u => [u.tactic, u.events]));
        const name = id => (index.techniques[id] && index.techniques[id].name) || id;
        const wildIn = ids => ids.filter(id => byId.get(id) && byId.get(id).wild).length;
        const eventLinks = ids => ids.map(id => `<a class="mono" href="./#${esc(id)}">${esc(id.replace('-', ' '))}</a>`).join(', ');
        const all = state.expanded.techniques;

        const row = (tactic, techniqueId, cell, sub) => {
            const counts = cell
                ? `<a href="${table(`technique=${techniqueId}&tactic=${tactic}`)}">${plural(cell.events.length, 'event')}</a>` +
                  (wildIn(cell.events) ? ` <a class="tech-wild" href="${table(`technique=${techniqueId}&tactic=${tactic}&wild=1`)}">` +
                      `<span class="wild-dot" aria-hidden="true"></span>${wildIn(cell.events)} in the wild</a>` : '')
                : '<span class="muted">sub-techniques only</span>';
            return `<li class="tech-row${sub ? ' tech-row--sub' : ''}">${extLink(attackUrl(techniqueId), techniqueId, 'mono tech-id')}` +
                `<span class="tech-name">${esc(name(techniqueId))}</span><span class="tech-counts">${counts}</span></li>`;
        };

        let hidden = 0;
        const groups = index.tactics.filter(t => tagged.get(t.id)).map(t => {
            const cells = cellsByTactic.get(t.id) || [];
            const byTechnique = new Map(cells.map(c => [c.technique, c]));
            const size = id => (byTechnique.get(id) ? byTechnique.get(id).events.length : 0);
            // Most catalogued events first, so the short view shows the largest techniques.
            const parents = [...new Set(cells.map(c => c.technique.split('.')[0]))]
                .sort((a, b) => size(b) - size(a) || name(a).localeCompare(name(b)));
            const shownParents = all ? parents : parents.slice(0, LIMIT.techniquesPerTactic);
            const rows = shownParents.map(parent => {
                const subs = all ? cells.filter(c => c.technique.startsWith(parent + '.')).sort((a, b) => b.events.length - a.events.length || name(a.technique).localeCompare(name(b.technique))) : [];
                return row(t.id, parent, byTechnique.get(parent), false) + subs.map(c => row(t.id, c.technique, c, true)).join('');
            }).join('');
            const notShown = cells.length - shownParents.length - (all ? cells.length - parents.length : 0);
            hidden += Math.max(0, notShown);
            const missing = unplaced.get(t.id) || [];
            const missingLine = all && missing.length
                ? `<p class="tech-unplaced">${plural(missing.length, 'more event')} ${missing.length === 1 ? 'is' : 'are'} tagged ${esc(t.name)}, ` +
                  `but ATT&amp;CK v${esc(index.attackVersion)} does not list ${missing.length === 1 ? 'its techniques' : 'their techniques'} under ${esc(t.name)}: ${eventLinks(missing)}.</p>`
                : '';
            return `<section class="tech-group" aria-labelledby="tg-${t.id}">` +
                `<h3 id="tg-${t.id}"><a href="${table(`tactic=${t.id}`)}">${esc(t.name)}</a> ${extLink(attackUrl(t.id), t.id, 'mono tech-id')}` +
                `<span class="tech-group__count">${plural(tagged.get(t.id), 'event')} tagged</span></h3>` +
                (rows ? `<ul class="tech-list">${rows}</ul>` : '') + missingLine + '</section>';
        });

        const unknown = all && index.unknownTechniques.length
            ? `<p class="tech-unplaced">Not active in ATT&amp;CK v${esc(index.attackVersion)}: ` +
              index.unknownTechniques.map(u => `${esc(u.technique)} (${eventLinks(u.events)})`).join('; ') + '.</p>'
            : '';
        el('techIndex').innerHTML = staleNote + groups.join('') + unknown;

        const btn = el('techMore');
        btn.hidden = !all && hidden === 0;
        btn.textContent = all ? 'Show fewer techniques' : `Show all ${index.cells.length} techniques and sub-techniques`;
        btn.setAttribute('aria-expanded', String(all));
        el('techMode').textContent = all
            ? 'Every technique and sub-technique, most catalogued events first.'
            : `The ${LIMIT.techniquesPerTactic} techniques with the most catalogued events in each tactic; sub-techniques are in the full list.`;
    }

    let staleNote = '';

    function setUpTechniques(index, dataVersion) {
        techIndex = index;
        staleNote = dataVersion && index.dataVersion !== dataVersion
            ? '<p class="ins-warning">This index was generated from a different version of events.json, so some counts may differ until the site is rebuilt.</p>'
            : '';
        const parents = new Set(index.cells.map(c => c.technique.split('.')[0]));
        const subs = new Set(index.cells.filter(c => c.technique.includes('.')).map(c => c.technique));
        el('techLede').textContent = `${parents.size} techniques and ${subs.size} sub-techniques, placed in ${index.cells.length} tactic and technique pairs. ` +
            'Every count opens the matching events in the event table.';
        // The version text follows the index; the v19 sentence explains why links stay pinned.
        el('techVersionNote').textContent = `Mapped to ATT&CK Enterprise v${index.attackVersion}, and links go to the v${index.attackVersion.split('.')[0]} pages. ` +
            'ATT&CK v19 revoked some techniques the catalogue uses (for example T1562 Impair Defenses), so the index stays on this version until the catalogue is remapped.';
        el('navigatorLink').href = `${NAVIGATOR}#layerURL=${encodeURIComponent(new URL('attack-layer.json', location.href).href)}`;
        renderTechniques();
    }

    // ------------------------------------------------------------------
    // AWS services
    // ------------------------------------------------------------------

    let serviceRows = [];

    function buildServices() {
        const groups = new Map();
        events.forEach(ev => {
            if (!groups.has(ev.serviceKey)) groups.set(ev.serviceKey, []);
            groups.get(ev.serviceKey).push(ev);
        });
        serviceRows = [...groups.entries()].map(([key, evs]) => ({
            key,
            label: labels.get(key),
            eventSources: [...new Set(evs.map(ev => ev.eventSource))].sort(),
            n: evs.length,
            wild: evs.filter(ev => ev.wild).length,
            sources: new Set(evs.flatMap(ev => ev.sourceIds)).size,
            counts: tacticCounts(evs),
        }));
        const filled = serviceRows.reduce((sum, r) => sum + r.counts.filter(Boolean).length, 0);
        el('svcLede').textContent = `${serviceRows.length} AWS services with catalogued events. ` +
            `${filled} of the ${serviceRows.length * tactics.length} service and tactic pairs hold at least one event.`;
    }

    function serviceValue(row, key) {
        if (key === 'label') return row.label;
        if (key === 'events') return row.n;
        if (key === 'wild') return row.wild;
        if (key === 'sources') return row.sources;
        return row.counts[tacticIndex.get(key)] || 0;
    }

    function renderServices() {
        const sorted = [...serviceRows].sort(compareRows(state.svcSort, serviceValue, r => r.label));
        const list = state.expanded.services ? sorted : sorted.slice(0, LIMIT.services);
        const columns = [
            { key: 'label', label: 'Service', cls: 'col-source col-service' },
            { key: 'events', label: 'Events', cls: 'col-num' },
            { key: 'wild', label: 'In the wild', cls: 'col-num' },
            { key: 'sources', label: 'Incident sources', cls: 'col-num' },
        ];
        const body = list.map(r => {
            const svc = encodeURIComponent(r.label);
            const tactic = ta => table(`service=${svc}&tactic=${ta}`);
            return '<tr>' +
                `<th scope="row" class="col-source col-service"><a class="src-title" href="${table(`service=${svc}`)}">${esc(r.label)}</a>` +
                `<span class="src-meta"><span class="mono">${esc(r.eventSources.join(', '))}</span></span>${stripLine(r.counts, tactic)}</th>` +
                `<td class="col-num"><a href="${table(`service=${svc}`)}">${r.n}</a></td>` +
                `<td class="col-num">${r.wild ? `<a href="${table(`service=${svc}&wild=1`)}">${r.wild}</a>` : '<span class="muted">0</span>'}</td>` +
                `<td class="col-num">${r.sources ? `<a href="?src_service=${encodeURIComponent(r.label)}#incident-sources" data-src-service="${esc(r.key)}" ` +
                    `aria-label="Show the ${r.sources} incident sources with ${esc(r.label)} events">${r.sources}</a>` : '<span class="muted">0</span>'}</td>` +
                stripCells(r.counts, tactic) +
                '</tr>';
        }).join('');
        el('svcTable').innerHTML = el('svcTable').querySelector('caption').outerHTML + headerHtml(columns, state.svcSort) + `<tbody>${body}</tbody>`;
        renderMore(el('svcMore'), 'services', list.length, sorted.length, 'services');
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    async function sha256(text) {
        if (!(window.crypto && crypto.subtle)) return '';
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
        return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
    }

    function bindEvents() {
        el('srcFilter').addEventListener('input', () => {
            state.srcQ = el('srcFilter').value;
            renderSources();
            updateUrl();
        });
        bindSort(el('srcTable'), () => state.srcSort, renderSources);
        bindSort(el('svcTable'), () => state.svcSort, renderServices);

        const toggle = (id, section, rerender) => el(id).addEventListener('click', () => {
            state.expanded[section] = !state.expanded[section];
            rerender();
            if (!state.expanded[section]) el(id).closest('section').scrollIntoView({ block: 'start' });
        });
        toggle('srcMore', 'sources', renderSources);
        toggle('svcMore', 'services', renderServices);
        toggle('techMore', 'techniques', renderTechniques);

        // A service's "Incident sources" count filters the sources table to that service.
        el('svcTable').addEventListener('click', e => {
            const link = e.target.closest('[data-src-service]');
            if (!link || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
            e.preventDefault();
            state.srcService = link.dataset.srcService;
            state.srcQ = '';
            el('srcFilter').value = '';
            renderSources();
            updateUrl();
            el('incident-sources').scrollIntoView({ block: 'start' });
            el('srcCount').focus({ preventScroll: true });
        });
        el('srcServiceNote').addEventListener('click', e => {
            if (!e.target.closest('[data-clear-service]')) return;
            state.srcService = '';
            renderSources();
            updateUrl();
            el('srcFilter').focus();
        });
    }

    async function init() {
        const [eventsRes, indexRes] = await Promise.allSettled([
            fetch('events.json').then(r => (r.ok ? r.text() : Promise.reject(new Error(r.status)))),
            fetch('attack-index.json').then(r => (r.ok ? r.json() : Promise.reject(new Error(r.status)))),
        ]);
        if (eventsRes.status !== 'fulfilled') {
            el('introLede').innerHTML = 'Could not load the event data. Reload the page, or download it as <a href="events.json">JSON</a> or <a href="events.csv">CSV</a>.';
            ['incident-sources', 'techniques', 'services'].forEach(id => { el(id).hidden = true; });
            return;
        }
        const text = eventsRes.value;
        const raws = uniqueEvents(JSON.parse(text));
        tactics = activeTactics(raws);
        tacticIndex = new Map(tactics.map(([id], i) => [id, i]));
        labels = serviceLabels(raws);
        events = raws.map(prepare);
        byId = new Map(events.map(ev => [ev.id, ev]));
        sources = indexSources(raws);
        state.srcSort = resolveSort(state.srcSort, 'sources');
        state.svcSort = resolveSort(state.svcSort, 'services');
        if (state.srcService && !labels.has(state.srcService)) state.srcService = '';

        renderIntro();
        buildSources();
        el('srcFilter').value = state.srcQ;
        renderSources();
        buildServices();
        renderServices();

        if (indexRes.status === 'fulfilled') {
            const dataVersion = await sha256(text).catch(() => '');
            setUpTechniques(indexRes.value, dataVersion);
            el('dataStamp').textContent = `Built from events.json (data version ${indexRes.value.dataVersion}) and ATT&CK Enterprise v${indexRes.value.attackVersion}.`;
        } else {
            el('techIndex').innerHTML = '<p class="ins-warning">The ATT&amp;CK index (attack-index.json) could not be loaded. The event table still lists every technique.</p>';
            el('techMore').hidden = true;
        }

        bindEvents();
        showTargetSource();
        if (!state.source && location.hash) {
            const target = document.getElementById(location.hash.slice(1));
            if (target) target.scrollIntoView();
        }
    }

    init().catch(error => {
        console.error('Error building the Insights page:', error);
        el('introLede').textContent = 'Something went wrong while building this page. Reload it, or use the event table.';
    });
})();
