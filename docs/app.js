(function () {
    'use strict';

    const REPO_URL = 'https://github.com/adanalvarez/TrailDiscover';

    // ATT&CK enterprise tactics in kill-chain order (only those used by cloud events).
    const TACTICS = [
        ['TA0001', 'Initial Access'],
        ['TA0002', 'Execution'],
        ['TA0003', 'Persistence'],
        ['TA0004', 'Privilege Escalation'],
        ['TA0005', 'Defense Evasion'],
        ['TA0006', 'Credential Access'],
        ['TA0007', 'Discovery'],
        ['TA0008', 'Lateral Movement'],
        ['TA0009', 'Collection'],
        ['TA0010', 'Exfiltration'],
        ['TA0011', 'Command and Control'],
        ['TA0040', 'Impact'],
    ];
    const TACTIC_ORDER = new Map(TACTICS.map(([id], i) => [id, i]));

    const PAGE_SIZE = 25;

    // Default direction for each sort key (1 = ascending, -1 = descending).
    const SORT_DIRECTIONS = { default: -1, name: 1, service: 1, tactic: 1, wild: -1, incidents: -1, research: -1 };

    const BASE_TITLE = document.title;

    const WILD_BADGE = '<span class="wild-badge"><span class="wild-dot" aria-hidden="true"></span>In the wild</span>';

    const el = {
        stats: document.getElementById('stats'),
        controls: document.getElementById('controls'),
        results: document.getElementById('results'),
        search: document.getElementById('search'),
        service: document.getElementById('serviceFilter'),
        wild: document.getElementById('wildToggle'),
        wildCount: document.getElementById('wildCount'),
        tactics: document.getElementById('tacticFilter'),
        count: document.getElementById('resultCount'),
        clear: document.getElementById('clearFilters'),
        emptyClear: document.getElementById('emptyClear'),
        sort: document.getElementById('sortSelect'),
        table: document.getElementById('eventsTable'),
        tableCard: document.getElementById('tableCard'),
        body: document.getElementById('eventsBody'),
        pageInfo: document.getElementById('pageInfo'),
        pageNav: document.getElementById('pageNav'),
        empty: document.getElementById('emptyState'),
        drawer: document.getElementById('drawer'),
        drawerBody: document.getElementById('drawerBody'),
        drawerPrev: document.getElementById('drawerPrev'),
        drawerNext: document.getElementById('drawerNext'),
        drawerPos: document.getElementById('drawerPos'),
        drawerClose: document.getElementById('drawerClose'),
        copyLink: document.getElementById('copyLink'),
    };

    const state = {
        q: '',
        service: '',        // lower-cased service key
        tactics: new Set(), // tactic IDs, e.g. "TA0003"
        wild: false,
        sort: 'default',
        dir: SORT_DIRECTIONS.default,
        page: 1,
    };

    let events = [];        // prepared events
    let byId = new Map();   // lower-cased "Service-EventName" -> event
    let services = [];      // [{ key, label }]
    let techniqueCounts = new Map();
    let visible = [];       // current filtered + sorted list
    let openId = null;      // id of the event shown in the drawer
    let returnFocusTo = null;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

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

    function extLink(url, text, className) {
        const href = safeUrl(url);
        if (!href) return esc(text);
        return `<a href="${esc(href)}" target="_blank" rel="noopener"${className ? ` class="${className}"` : ''}>${esc(text)}</a>`;
    }

    function domainOf(url) {
        try {
            return new URL(url).hostname.replace(/^www\./, '');
        } catch (e) {
            return '';
        }
    }

    // Allow long CamelCase API names to wrap between words, e.g. Authorize<wbr>Security<wbr>Group...
    function breakable(name) {
        return esc(name).replace(/([a-z0-9])([A-Z])/g, '$1<wbr>$2');
    }

    function plural(n, one) {
        return `${n} ${n === 1 ? one : one + 's'}`;
    }

    // "TA0003 - Persistence" -> { id: "TA0003", name: "Persistence" }
    function splitAttack(value) {
        const m = /^\s*(TA?\d{4}(?:\.\d{3})?)\s*-\s*(.+)$/.exec(value || '');
        return m ? { id: m[1], name: m[2].trim() } : { id: '', name: String(value || '') };
    }

    function attackUrl(id) {
        if (/^TA\d{4}$/.test(id)) return `https://attack.mitre.org/tactics/${id}/`;
        const m = /^(T\d{4})(?:\.(\d{3}))?$/.exec(id);
        if (!m) return '';
        return `https://attack.mitre.org/techniques/${m[1]}/${m[2] ? m[2] + '/' : ''}`;
    }

    function tokenize(query) {
        return query.toLowerCase().split(/[\s,:]+/).filter(Boolean);
    }

    // ------------------------------------------------------------------
    // Data preparation
    // ------------------------------------------------------------------

    function prepare(raw) {
        const tactics = (raw.mitreAttackTactics || []).map(splitAttack);
        const techniques = (raw.mitreAttackTechniques || []).map(splitAttack);
        const subTechniques = (raw.mitreAttackSubTechniques || []).map(splitAttack);
        const simulation = raw.simulation || [];
        const cliEntry = simulation.find(s => s.type === 'commandLine');
        const cli = cliEntry && cliEntry.value && cliEntry.value !== 'N/A' ? cliEntry.value : '';
        const incidents = raw.incidents || [];
        const research = raw.researchLinks || [];
        const attackText = tactics.concat(techniques, subTechniques).map(t => `${t.id} ${t.name}`).join(' ');

        return {
            raw,
            id: `${raw.awsService}-${raw.eventName}`,
            name: raw.eventName,
            service: raw.awsService,
            serviceKey: raw.awsService.toLowerCase(),
            source: raw.eventSource,
            wild: !!raw.usedInWild,
            incidents,
            research,
            tactics,
            techniques,
            subTechniques,
            firstTactic: Math.min(...tactics.map(t => TACTIC_ORDER.has(t.id) ? TACTIC_ORDER.get(t.id) : 99), 99),
            cli,
            stratus: simulation.filter(s => s.type === 'stratusRedTeam' && safeUrl(s.value)).map(s => s.value),
            alerting: raw.alerting || [],
            permissions: safeUrl(raw.permissions),
            // Searchable text, from most to least specific. "visible" fields are shown in the table row.
            search: [
                { text: raw.eventName.toLowerCase(), weight: 100, visible: true },
                { text: `${raw.awsService} ${raw.eventSource}`.toLowerCase(), weight: 40, visible: true },
                { text: attackText.toLowerCase(), weight: 30, visible: true },
                { text: incidents.map(i => `${i.description} ${i.link}`).join(' ').toLowerCase(), weight: 12, label: 'Incident', items: incidents },
                { text: research.map(r => `${r.description} ${r.link}`).join(' ').toLowerCase(), weight: 10, label: 'Research', items: research },
                { text: (raw.description || '').toLowerCase(), weight: 6, label: 'Description', raw: raw.description },
                { text: (raw.securityImplications || '').toLowerCase(), weight: 4, label: 'Security implications', raw: raw.securityImplications },
            ],
        };
    }

    function buildIndexes() {
        byId = new Map(events.map(ev => [ev.id.toLowerCase(), ev]));

        const serviceMap = new Map();
        events.forEach(ev => {
            const entry = serviceMap.get(ev.serviceKey) || { key: ev.serviceKey, spellings: new Map() };
            entry.spellings.set(ev.service, (entry.spellings.get(ev.service) || 0) + 1);
            serviceMap.set(ev.serviceKey, entry);
        });
        services = [...serviceMap.values()].map(s => ({
            key: s.key,
            label: [...s.spellings.entries()].sort((a, b) => b[1] - a[1])[0][0],
        })).sort((a, b) => a.label.localeCompare(b.label, 'en', { sensitivity: 'base' }));

        techniqueCounts = new Map();
        events.forEach(ev => ev.techniques.forEach(t => {
            if (t.id) techniqueCounts.set(t.id, (techniqueCounts.get(t.id) || 0) + 1);
        }));
    }

    // ------------------------------------------------------------------
    // Filtering, search and sorting
    // ------------------------------------------------------------------

    // Returns null when the event does not match every token, otherwise a relevance score.
    function searchScore(ev, tokens, compact) {
        let score = 0;
        for (const token of tokens) {
            let best = 0;
            for (const field of ev.search) {
                if (field.weight > best && field.text.includes(token)) best = field.weight;
            }
            if (!best) return null;
            score += best;
        }
        const name = ev.name.toLowerCase();
        if (name === compact) score += 1000;
        else if (name.startsWith(compact)) score += 400;
        else if (name.includes(compact)) score += 200;
        return score;
    }

    function matchesFacets(ev, skip) {
        if (skip !== 'wild' && state.wild && !ev.wild) return false;
        if (skip !== 'service' && state.service && ev.serviceKey !== state.service) return false;
        if (skip !== 'tactic' && state.tactics.size && !ev.tactics.some(t => state.tactics.has(t.id))) return false;
        return true;
    }

    // Ascending comparators; the sort direction is applied by the caller. Numeric keys break
    // ties with a reversed name compare so that descending order still lists names A–Z.
    function compareBy(key) {
        const byName = (a, b) => a.name.localeCompare(b.name) || a.service.localeCompare(b.service);
        switch (key) {
            case 'name': return byName;
            case 'service': return (a, b) => a.service.localeCompare(b.service, 'en', { sensitivity: 'base' }) || byName(a, b);
            case 'tactic': return (a, b) => (a.firstTactic - b.firstTactic) || byName(a, b);
            case 'incidents': return (a, b) => (a.incidents.length - b.incidents.length) || -byName(a, b);
            case 'research': return (a, b) => (a.research.length - b.research.length) || -byName(a, b);
            default: // evidence: seen in the wild, then number of incidents, then research
                return (a, b) => (a.wild - b.wild) || (a.incidents.length - b.incidents.length) ||
                    (a.research.length - b.research.length) || -byName(a, b);
        }
    }

    function computeVisible() {
        const tokens = tokenize(state.q);
        const compact = tokens.join('');
        const scores = new Map();
        const searched = tokens.length
            ? events.filter(ev => {
                const s = searchScore(ev, tokens, compact);
                if (s === null) return false;
                scores.set(ev, s);
                return true;
            })
            : events;

        const list = searched.filter(ev => matchesFacets(ev));
        // Default order is relevance while searching, most evidence otherwise.
        const byRelevance = tokens.length > 0 && state.sort === 'default';
        const cmp = compareBy(state.sort);
        list.sort((a, b) => (byRelevance ? scores.get(b) - scores.get(a) : 0) || state.dir * cmp(a, b));
        return { list, searched, tokens };
    }

    // Short explanation of why a row matched when the match is not visible in the table.
    function matchHint(ev, tokens) {
        const hidden = tokens.filter(t => !ev.search.some(f => f.visible && f.text.includes(t)));
        if (!hidden.length) return '';
        const token = hidden[0];
        for (const field of ev.search) {
            if (field.visible || !field.text.includes(token)) continue;
            if (field.items) {
                const item = field.items.find(i => `${i.description} ${i.link}`.toLowerCase().includes(token));
                if (item) return `<span class="match-hint"><span>${field.label}:</span> ${esc(item.description)}</span>`;
            } else if (field.raw) {
                const idx = field.text.indexOf(token);
                const start = Math.max(0, idx - 40);
                const snippet = (start ? '…' : '') + field.raw.slice(start, idx + token.length + 60).trim() + '…';
                return `<span class="match-hint"><span>${field.label}:</span> ${esc(snippet)}</span>`;
            }
        }
        return '';
    }

    // ------------------------------------------------------------------
    // Rendering: filters and table
    // ------------------------------------------------------------------

    // Facet counts reflect the search and every other active filter.
    function renderServiceOptions(searched) {
        const counts = new Map();
        searched.forEach(ev => {
            if (!matchesFacets(ev, 'service')) return;
            counts.set(ev.serviceKey, (counts.get(ev.serviceKey) || 0) + 1);
        });
        const options = ['<option value="">All AWS services</option>'].concat(services.map(s => {
            const n = counts.get(s.key) || 0;
            return `<option value="${esc(s.key)}"${s.key === state.service ? ' selected' : ''}>${esc(s.label)} (${n})</option>`;
        }));
        el.service.innerHTML = options.join('');
        el.service.classList.toggle('is-active', !!state.service);
    }

    function renderTacticChips(searched) {
        const counts = new Map();
        searched.forEach(ev => {
            if (!matchesFacets(ev, 'tactic')) return;
            new Set(ev.tactics.map(t => t.id)).forEach(id => counts.set(id, (counts.get(id) || 0) + 1));
        });
        el.tactics.innerHTML = TACTICS.map(([id, name]) => {
            const n = counts.get(id) || 0;
            const active = state.tactics.has(id);
            return `<button type="button" class="chip${active ? ' is-active' : ''}" data-tactic="${id}" aria-pressed="${active}"` +
                `${!n && !active ? ' disabled' : ''} title="${id} · ${esc(name)}">${esc(name)} <span class="count">${n}</span></button>`;
        }).join('');
    }

    function renderWildToggle(searched) {
        const n = searched.filter(ev => ev.wild && matchesFacets(ev, 'wild')).length;
        el.wildCount.textContent = n;
        el.wild.setAttribute('aria-pressed', String(state.wild));
    }

    // "default" means relevance while searching and most evidence otherwise; "wild" (most
    // evidence) only exists as a separate choice while searching.
    function normalizeSort() {
        if (!state.q && state.sort === 'wild') state.sort = 'default';
    }

    function renderSortIndicators() {
        normalizeSort();
        const active = state.sort === 'default' ? (state.q ? '' : 'wild') : state.sort;
        el.table.querySelectorAll('th[data-sort]').forEach(th => {
            if (th.dataset.sort === active) th.setAttribute('aria-sort', state.dir === 1 ? 'ascending' : 'descending');
            else th.removeAttribute('aria-sort');
        });
        const options = [['default', state.q ? 'Relevance' : 'Most evidence']]
            .concat(state.q ? [['wild', 'Most evidence']] : [])
            .concat([['name', 'Event name'], ['service', 'AWS service'], ['tactic', 'ATT&CK tactic'],
                ['incidents', 'Incidents'], ['research', 'Research']]);
        el.sort.innerHTML = options.map(([value, label]) =>
            `<option value="${value}"${value === state.sort ? ' selected' : ''}>${esc(label)}</option>`).join('');
    }

    // One line per cell; the full tactic and technique lists are in each cell's title.
    function rowHtml(ev, tokens) {
        const hint = tokens.length ? matchHint(ev, tokens) : '';
        const tactics = ev.tactics.map(t => t.name).join(', ');
        const techniques = ev.techniques.map(t =>
            `<span class="mono tech__id">${esc(t.id)}</span><span class="tech__name"> ${esc(t.name)}</span>`).join(', ');
        const techniquesTitle = ev.techniques.map(t => `${t.id} ${t.name}`).join(', ');
        const num = (n, label) =>
            `<span class="${n ? 'num' : 'num num--zero'}">${n}</span><span class="m-label"> ${n === 1 ? label : label + 's'}</span>`;
        return `<tr data-id="${esc(ev.id)}"${ev.id === openId ? ' class="is-open"' : ''}>` +
            `<td class="c-event"><a class="event-link mono" href="#${esc(ev.id)}" title="${esc(ev.name)} (${esc(ev.source)})">${breakable(ev.name)}</a>${hint}</td>` +
            `<td class="c-service" title="${esc(ev.service)}">${esc(ev.service)}</td>` +
            `<td class="c-tactics" title="${esc(tactics)}">${esc(tactics)}</td>` +
            `<td class="c-tech" title="${esc(techniquesTitle)}">${techniques}</td>` +
            `<td class="c-num c-inc">${num(ev.incidents.length, 'incident')}</td>` +
            `<td class="c-num c-res">${num(ev.research.length, 'research link')}</td>` +
            `<td class="c-wild">${ev.wild ? WILD_BADGE : '<span class="no-evidence" title="No documented in-the-wild use referenced yet">—</span>'}</td>` +
            `</tr>`;
    }

    // Page numbers to show: first, last, and the current page with its neighbours; null marks a gap.
    function pageNumbers(current, total) {
        const pages = [...new Set([1, current - 1, current, current + 1, total])]
            .filter(n => n >= 1 && n <= total)
            .sort((a, b) => a - b);
        const out = [];
        pages.forEach((n, i) => {
            if (i && n - pages[i - 1] > 1) out.push(null);
            out.push(n);
        });
        return out;
    }

    function renderPager(total, start, count, pages) {
        el.pageInfo.innerHTML = `Showing <strong>${start + 1}</strong> to <strong>${start + count}</strong> of <strong>${total}</strong> results`;
        if (pages <= 1) {
            el.pageNav.innerHTML = '';
            return;
        }
        const nav = [`<button type="button" class="page-btn" data-nav="prev" data-page="${state.page - 1}"${state.page === 1 ? ' disabled' : ''}>Previous</button>`];
        pageNumbers(state.page, pages).forEach(n => {
            if (n === null) {
                nav.push('<span class="page-gap" aria-hidden="true">…</span>');
            } else {
                const current = n === state.page;
                nav.push(`<button type="button" class="page-btn page-btn--num${current ? ' is-current' : ''}" data-page="${n}"` +
                    `${current ? ' aria-current="page"' : ''} aria-label="Page ${n}">${n}</button>`);
            }
        });
        nav.push(`<button type="button" class="page-btn" data-nav="next" data-page="${state.page + 1}"${state.page === pages ? ' disabled' : ''}>Next</button>`);
        el.pageNav.innerHTML = nav.join('');
    }

    function hasFilters() {
        return !!(state.q || state.service || state.tactics.size || state.wild);
    }

    function render() {
        const { list, searched, tokens } = computeVisible();
        visible = list;

        renderServiceOptions(searched);
        renderTacticChips(searched);
        renderWildToggle(searched);
        renderSortIndicators();

        const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
        state.page = Math.min(Math.max(1, state.page), pages);
        const start = (state.page - 1) * PAGE_SIZE;
        const pageItems = list.slice(start, start + PAGE_SIZE);
        el.body.innerHTML = pageItems.map(ev => rowHtml(ev, tokens)).join('');
        renderPager(list.length, start, pageItems.length, pages);

        el.empty.hidden = list.length > 0;
        el.tableCard.hidden = list.length === 0;
        el.clear.hidden = !hasFilters();

        const total = events.length;
        el.count.innerHTML = list.length === total
            ? `<strong>${total}</strong> events`
            : `<strong>${list.length}</strong> of ${total} events`;

        updateUrl();
    }

    // Filters, search and sort changes start again from the first page.
    function refresh() {
        state.page = 1;
        render();
        revealResults();
    }

    // When the list changes while the user is scrolled further down, bring the results back into view.
    function revealResults() {
        if (el.results.getBoundingClientRect().top < el.controls.offsetHeight) {
            el.results.scrollIntoView({ block: 'start' });
        }
    }

    function updateStats() {
        const wild = events.filter(ev => ev.wild).length;
        el.stats.innerHTML =
            `${events.length} events · ${services.length} AWS services · ` +
            `<span class="stats__wild"><span class="wild-dot" aria-hidden="true"></span>${wild} seen in the wild</span>` +
            ` <span class="stats__def">(documented attacker use in public incident reports)</span>`;
    }

    // ------------------------------------------------------------------
    // URL state: ?q=&service=&tactic=&wild=1&sort=&page=  #Service-EventName
    // ------------------------------------------------------------------

    let urlTimer = null;

    function queryString() {
        const p = new URLSearchParams();
        if (state.q) p.set('q', state.q);
        if (state.service) {
            const s = services.find(x => x.key === state.service);
            p.set('service', s ? s.label : state.service);
        }
        if (state.tactics.size) p.set('tactic', [...state.tactics].join(','));
        if (state.wild) p.set('wild', '1');
        if (state.sort !== 'default') p.set('sort', state.sort);
        if (state.dir !== SORT_DIRECTIONS[state.sort]) p.set('order', state.dir === 1 ? 'asc' : 'desc');
        if (state.page > 1) p.set('page', state.page);
        const qs = p.toString();
        return qs ? `?${qs}` : '';
    }

    function writeUrl() {
        clearTimeout(urlTimer);
        const url = location.pathname + queryString() + location.hash;
        if (url !== location.pathname + location.search + location.hash) {
            history.replaceState(history.state, '', url);
        }
    }

    // Typing updates the URL at most every 250ms.
    function updateUrl() {
        clearTimeout(urlTimer);
        urlTimer = setTimeout(writeUrl, 250);
    }

    function readUrl() {
        const p = new URLSearchParams(location.search);
        state.q = (p.get('q') || '').trim();
        const svc = (p.get('service') || '').toLowerCase();
        state.service = services.some(s => s.key === svc) ? svc : '';
        state.tactics = new Set((p.get('tactic') || '').split(',').map(t => t.trim().toUpperCase()).filter(t => TACTIC_ORDER.has(t)));
        state.wild = p.get('wild') === '1' || p.get('wild') === 'true';
        const sort = p.get('sort');
        state.sort = Object.prototype.hasOwnProperty.call(SORT_DIRECTIONS, sort) ? sort : 'default';
        const order = p.get('order');
        state.dir = order === 'asc' ? 1 : order === 'desc' ? -1 : SORT_DIRECTIONS[state.sort];
        state.page = Math.max(1, parseInt(p.get('page'), 10) || 1);
        el.search.value = state.q;
    }

    function idFromHash() {
        let hash;
        try {
            hash = decodeURIComponent(location.hash.replace(/^#/, '')).toLowerCase();
        } catch (e) {
            return null; // malformed escape sequence
        }
        return byId.has(hash) ? byId.get(hash).id : null;
    }

    function permalink(id) {
        return `${location.origin}${location.pathname}#${id}`;
    }

    // ------------------------------------------------------------------
    // Drawer
    // ------------------------------------------------------------------

    function section(title, body, extra) {
        return `<section class="panel-section"${extra || ''}><h3 class="panel-section__title">${title}</h3>${body}</section>`;
    }

    function linkList(items) {
        if (!items.length) return '';
        return `<ol class="source-list">` + items.map(item => {
            const domain = domainOf(item.link);
            return `<li>${extLink(item.link, item.description || item.link)}` +
                (domain ? ` <span class="source-list__domain mono">${esc(domain)}</span>` : '') + `</li>`;
        }).join('') + `</ol>`;
    }

    function attackRows(label, items, withPivot) {
        if (!items.length) return '';
        return `<div class="attack-row"><div class="attack-row__label">${label}</div><ul class="attack-list">` +
            items.map(t => {
                const url = attackUrl(t.id);
                const id = t.id ? (url ? extLink(url, t.id, 'mono attack-id') : `<span class="mono attack-id">${esc(t.id)}</span>`) : '';
                const count = withPivot && t.id ? techniqueCounts.get(t.id) || 0 : 0;
                const pivot = count > 1
                    ? ` <button type="button" class="link-button pivot" data-pivot-q="${esc(t.id)}">${count} events</button>`
                    : '';
                return `<li>${id} <span>${esc(t.name)}</span>${pivot}</li>`;
            }).join('') + `</ul></div>`;
    }

    function detectionHtml(ev) {
        const items = ev.alerting.filter(a => safeUrl(a.value)).map(a => {
            if (a.type === 'sigma') {
                const file = a.value.split('/').pop();
                return `<li><span class="kv__key">Sigma rule</span>${extLink(a.value, file, 'mono')}</li>`;
            }
            if (a.type === 'cloudwatchCISControls') {
                const frag = (a.value.split('#')[1] || '').replace(/^cloudwatch-(\d+)$/i, 'CloudWatch.$1');
                return `<li><span class="kv__key">Security Hub control</span>${extLink(a.value, frag || 'CloudWatch controls', 'mono')}</li>`;
            }
            return `<li><span class="kv__key">${esc(a.type)}</span>${extLink(a.value, a.value, 'mono')}</li>`;
        });
        return items.length
            ? `<ul class="kv">${items.join('')}</ul>`
            : `<p class="muted">No detection rules referenced yet.</p>`;
    }

    function permissionHtml(ev) {
        if (!ev.permissions) return `<p class="muted">No IAM permission reference.</p>`;
        let action = '';
        try {
            const url = new URL(ev.permissions);
            const prefix = url.pathname.split('/').filter(Boolean).pop();
            const frag = decodeURIComponent(url.hash.slice(1));
            if (prefix && frag.startsWith(prefix + '-')) action = `${prefix}:${frag.slice(prefix.length + 1)}`;
        } catch (e) { /* fall through to plain link */ }
        return `<ul class="kv"><li><span class="kv__key">IAM action</span>` +
            (action ? `<code class="mono">${esc(action)}</code> ` : '') +
            `${extLink(ev.permissions, 'permissions.cloud')}</li></ul>`;
    }

    function simulationHtml(ev) {
        const parts = [];
        if (ev.stratus.length) {
            parts.push(`<ul class="kv">` + ev.stratus.map(url =>
                `<li><span class="kv__key">Stratus Red Team</span>${extLink(url, url.split('/').pop(), 'mono')}</li>`).join('') + `</ul>`);
        }
        if (ev.cli) {
            const cmd = esc(ev.cli).replace(/&lt;[^&\s]+?&gt;/g, m => `<span class="placeholder">${m}</span>`);
            parts.push(`<div class="code-block"><div class="code-block__bar"><span>AWS CLI</span>` +
                `<button type="button" class="button button--ghost button--small" data-copy="cli">Copy</button></div>` +
                `<pre class="mono"><code>${cmd}</code></pre></div>`);
        }
        return parts.length ? parts.join('') : `<p class="muted">No simulation or CLI example yet.</p>`;
    }

    function evidenceSummary(ev) {
        const inc = ev.incidents.length;
        if (ev.wild) {
            return `<p class="evidence">${WILD_BADGE}<span>Documented attacker use in ` +
                `<a href="#sec-incidents" data-scroll="sec-incidents">${plural(inc, 'incident report')}</a>.</span></p>`;
        }
        return `<p class="evidence"><span class="no-evidence-badge">Unconfirmed</span><span>No documented in-the-wild use referenced yet` +
            (inc ? `; mentioned in <a href="#sec-incidents" data-scroll="sec-incidents">${plural(inc, 'incident report')}</a>` : '') +
            `.</span></p>`;
    }

    function renderDrawer(ev) {
        const tacticChips = ev.tactics.map(t => TACTIC_ORDER.has(t.id)
            ? `<button type="button" class="tactic tactic--button" data-pivot-tactic="${esc(t.id)}" title="Show all ${esc(t.name)} events"><span class="mono">${esc(t.id)}</span> ${esc(t.name)}</button>`
            : `<span class="tactic">${esc(t.id)} ${esc(t.name)}</span>`).join('');
        const serviceCount = events.filter(e => e.serviceKey === ev.serviceKey).length;

        const html = [];
        html.push(`<div class="panel-head">
            <p class="panel-head__meta">
                <button type="button" class="link-button" data-pivot-service="${esc(ev.serviceKey)}" title="Show all ${serviceCount} ${esc(ev.service)} events">${esc(ev.service)}</button>
                <span aria-hidden="true">·</span>
                <span class="mono">${esc(ev.source)}</span>
            </p>
            <h2 class="panel-head__title mono" id="drawerTitle" tabindex="-1">${breakable(ev.name)}</h2>
            ${evidenceSummary(ev)}
            <div class="panel-head__tactics">${tacticChips}</div>
        </div>`);

        html.push(section('Description', `<p>${esc(ev.raw.description)}</p>`));
        if (ev.raw.securityImplications) {
            html.push(section('Security implications', `<p>${esc(ev.raw.securityImplications)}</p>`));
        }

        html.push(section('MITRE ATT&amp;CK mapping',
            attackRows('Tactics', ev.tactics, false) +
            attackRows('Techniques', ev.techniques, true) +
            attackRows('Sub-techniques', ev.subTechniques, false)));

        html.push(section(`Incidents <span class="count">${ev.incidents.length}</span>`,
            ev.incidents.length ? linkList(ev.incidents) : `<p class="muted">No incident reports referenced yet.</p>`,
            ' id="sec-incidents"'));
        html.push(section(`Research <span class="count">${ev.research.length}</span>`,
            ev.research.length ? linkList(ev.research) : `<p class="muted">No research referenced yet.</p>`));

        html.push(section('Detection', detectionHtml(ev)));
        html.push(section('Permissions', permissionHtml(ev)));
        html.push(section('Simulation', simulationHtml(ev)));
        html.push(section('Example CloudTrail log', `<div id="logSlot"><p class="muted">Looking for an example log…</p></div>`, ' id="sec-log"'));

        const issueTitle = encodeURIComponent(`[${ev.service}] ${ev.name}: `);
        html.push(`<div class="panel-foot">Have more evidence or spotted a mistake? ` +
            `<a href="${REPO_URL}/issues/new?title=${issueTitle}" target="_blank" rel="noopener">Open an issue</a> or ` +
            `<a href="${REPO_URL}#how-to-contribute" target="_blank" rel="noopener">contribute on GitHub</a>.</div>`);

        el.drawerBody.innerHTML = html.join('');
        el.drawerBody.scrollTop = 0;
        el.drawer.dataset.cli = ev.cli;

        const index = visible.findIndex(v => v.id === ev.id);
        el.drawerPrev.disabled = index <= 0;
        el.drawerNext.disabled = index < 0 || index >= visible.length - 1;
        el.drawerPos.textContent = index >= 0 ? `${index + 1} of ${visible.length}` : '';

        loadLog(ev);
    }

    // Logs are copied to docs/logExamples as "<EventName>.json.cloudtrail"; some older copies
    // are prefixed with the service. Event names are not unique across services (the build
    // overwrites same-named files), so only show a log whose records come from this event's
    // eventSource, falling back to the service-prefixed copy.
    const logCache = new Map();

    function fetchLog(file) {
        if (!logCache.has(file)) {
            logCache.set(file, fetch(`logExamples/${file}`)
                .then(r => (r.ok ? r.json() : null))
                .catch(() => null));
        }
        return logCache.get(file);
    }

    async function loadLog(ev) {
        const candidates = [`${ev.name}.json.cloudtrail`, `${ev.service}-${ev.name}.json.cloudtrail`];
        let found = null;
        for (const file of candidates) {
            const data = await fetchLog(file);
            const records = Array.isArray(data) ? data : data ? [data] : [];
            if (records.some(r => r && r.eventSource === ev.source)) {
                found = { data, records };
                break;
            }
        }
        if (openId !== ev.id) return;
        const slot = document.getElementById('logSlot');
        if (!slot) return;
        if (!found) {
            slot.innerHTML = `<p class="muted">No example log for this event yet.</p>`;
            return;
        }
        const recorded = [...new Set(found.records.map(r => r.eventName).filter(Boolean))];
        const note = recorded.length && !recorded.includes(ev.name)
            ? `<p class="muted small">This example was recorded with eventName <code class="mono">${esc(recorded.join(', '))}</code>.</p>`
            : '';
        const fullPage = `logExamples/?event=${encodeURIComponent(ev.name)}&service=${encodeURIComponent(ev.service)}`;
        slot.innerHTML = note + `<div class="code-block code-block--log"><div class="code-block__bar">` +
            `<span>${plural(found.records.length, 'record')} · redacted test data</span>` +
            `<span class="code-block__actions"><a href="${esc(fullPage)}" class="button button--ghost button--small">Full page</a>` +
            `<button type="button" class="button button--ghost button--small" data-copy="log">Copy</button></span></div>` +
            `<pre class="mono"><code>${highlightJson(found.data)}</code></pre></div>`;
        slot.dataset.log = JSON.stringify(found.data, null, 2);
    }

    function highlightJson(value) {
        const json = JSON.stringify(value, null, 2);
        const re = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
        let out = '';
        let last = 0;
        let m;
        while ((m = re.exec(json))) {
            out += esc(json.slice(last, m.index));
            if (m[1]) {
                out += m[2]
                    ? `<span class="j-key">${esc(m[1])}</span>${esc(m[2])}`
                    : `<span class="j-str">${esc(m[1])}</span>`;
            } else if (m[3]) {
                out += `<span class="j-lit">${m[3]}</span>`;
            } else {
                out += `<span class="j-num">${m[0]}</span>`;
            }
            last = re.lastIndex;
        }
        return out + esc(json.slice(last));
    }

    function markOpenRow() {
        el.body.querySelectorAll('tr.is-open').forEach(tr => tr.classList.remove('is-open'));
        if (!openId) return;
        const row = el.body.querySelector(`tr[data-id="${CSS.escape(openId)}"]`);
        if (row) row.classList.add('is-open');
    }

    function showEvent(id) {
        const ev = byId.get(id.toLowerCase());
        if (!ev) return;
        openId = ev.id;
        document.title = `${ev.name} (${ev.service}) - TrailDiscover`;
        renderDrawer(ev);
        const index = visible.indexOf(ev);
        const page = Math.floor(index / PAGE_SIZE) + 1;
        if (index >= 0 && page !== state.page) {
            state.page = page;
            render();
        }
        markOpenRow();
        if (!el.drawer.open) {
            document.documentElement.classList.add('has-drawer');
            el.drawer.showModal();
            focusTitle();
        }
    }

    function focusTitle() {
        document.getElementById('drawerTitle').focus({ preventScroll: true });
    }

    function openEvent(id, trigger) {
        returnFocusTo = trigger || null;
        if (location.hash.replace(/^#/, '').toLowerCase() !== id.toLowerCase()) {
            writeUrl(); // the list's entry must hold the current filters before we push
            history.pushState({ traildiscover: id }, '', location.pathname + location.search + '#' + id);
        }
        showEvent(id);
    }

    function hideDrawer() {
        if (el.drawer.open) el.drawer.close();
        document.documentElement.classList.remove('has-drawer');
        document.title = BASE_TITLE;
        const closedId = openId;
        openId = null;
        markOpenRow();
        if (returnFocusTo && document.contains(returnFocusTo)) {
            returnFocusTo.focus();
        } else if (closedId) {
            const link = el.body.querySelector(`tr[data-id="${CSS.escape(closedId)}"] .event-link`);
            if (link) link.focus();
        }
        returnFocusTo = null;
    }

    // If we pushed the drawer's history entry, go back to the list's entry; otherwise (deep link)
    // just drop the hash.
    function closeEvent() {
        hideDrawer();
        if (history.state && history.state.traildiscover) {
            history.back();
        } else {
            history.replaceState(null, '', location.pathname + location.search);
        }
    }

    function stepEvent(delta) {
        const index = visible.findIndex(v => v.id === openId);
        const next = visible[index + delta];
        if (index < 0 || !next) return;
        history.replaceState(history.state, '', location.pathname + location.search + '#' + next.id);
        showEvent(next.id);
        const row = el.body.querySelector(`tr[data-id="${CSS.escape(next.id)}"]`);
        if (row) row.scrollIntoView({ block: 'nearest' });
        // Keep keyboard focus on Prev/Next unless that button just became disabled.
        if (document.activeElement.disabled || document.activeElement === document.body) focusTitle();
    }

    function withoutPage(search) {
        const p = new URLSearchParams(search);
        p.delete('page');
        return p.toString();
    }

    function syncFromHash() {
        // Back/forward restores filters from the URL. The page number is kept as it is:
        // closing the drawer goes back to an entry recorded before the table changed page.
        if (withoutPage(location.search) !== withoutPage(queryString())) {
            clearTimeout(urlTimer);
            readUrl();
            render();
        } else if (location.search !== queryString()) {
            updateUrl();
        }
        const id = idFromHash();
        if (id) {
            if (id !== openId) showEvent(id);
        } else if (el.drawer.open) {
            hideDrawer();
        }
    }

    // Pivot from the drawer to a filtered list. The drawer's history entry becomes the new
    // list, so Back returns to the list the user came from.
    function pivot(filter) {
        state.q = filter.q || '';
        state.service = filter.service || '';
        state.tactics = new Set(filter.tactic ? [filter.tactic] : []);
        state.wild = false;
        state.page = 1;
        el.search.value = state.q;
        returnFocusTo = el.count;
        hideDrawer();
        render();
        clearTimeout(urlTimer);
        history.replaceState(null, '', location.pathname + queryString());
        window.scrollTo(0, 0);
    }

    async function copyText(text, button) {
        try {
            await navigator.clipboard.writeText(text);
            flash(button, 'Copied');
        } catch (e) {
            flash(button, 'Copy failed');
        }
    }

    function flash(button, text) {
        if (!button) return;
        const original = button.dataset.label || button.textContent;
        button.dataset.label = original;
        button.textContent = text;
        clearTimeout(button._flash);
        button._flash = setTimeout(() => { button.textContent = original; }, 1500);
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    function bindEvents() {
        el.search.addEventListener('input', () => {
            state.q = el.search.value.trim();
            refresh();
        });
        el.search.addEventListener('keydown', e => {
            if (e.key === 'Escape' && el.search.value) {
                el.search.value = '';
                state.q = '';
                refresh();
            } else if (e.key === 'Enter') {
                // Open the event whose name matches exactly, or the only result.
                const q = state.q.toLowerCase();
                const match = visible.find(ev => ev.name.toLowerCase() === q) || (visible.length === 1 && visible[0]);
                if (match) openEvent(match.id, el.search);
            }
        });

        el.service.addEventListener('change', () => {
            state.service = el.service.value;
            refresh();
        });

        el.wild.addEventListener('click', () => {
            state.wild = !state.wild;
            refresh();
        });

        el.tactics.addEventListener('click', e => {
            const chip = e.target.closest('[data-tactic]');
            if (!chip) return;
            const id = chip.dataset.tactic;
            if (state.tactics.has(id)) state.tactics.delete(id);
            else state.tactics.add(id);
            refresh();
            const again = el.tactics.querySelector(`[data-tactic="${id}"]`);
            (again && !again.disabled ? again : el.search).focus({ preventScroll: true });
        });

        el.sort.addEventListener('change', () => {
            state.sort = el.sort.value;
            state.dir = SORT_DIRECTIONS[state.sort];
            refresh();
        });

        el.table.querySelector('thead').addEventListener('click', e => {
            const th = e.target.closest('th[data-sort]');
            if (!th) return;
            const key = th.dataset.sort === 'wild' && !state.q ? 'default' : th.dataset.sort;
            state.dir = state.sort === key ? -state.dir : SORT_DIRECTIONS[key];
            state.sort = key;
            refresh();
        });

        const clearAll = () => {
            state.q = '';
            state.service = '';
            state.tactics.clear();
            state.wild = false;
            el.search.value = '';
            refresh();
            el.search.focus();
        };
        el.clear.addEventListener('click', clearAll);
        el.emptyClear.addEventListener('click', clearAll);

        el.pageNav.addEventListener('click', e => {
            const btn = e.target.closest('[data-page]');
            if (!btn || btn.disabled) return;
            const nav = btn.dataset.nav;
            state.page = Number(btn.dataset.page);
            render();
            revealResults();
            const again = el.pageNav.querySelector(nav ? `[data-nav="${nav}"]:not(:disabled)` : '.is-current') ||
                el.pageNav.querySelector('.is-current');
            if (again) again.focus({ preventScroll: true });
        });

        el.body.addEventListener('click', e => {
            const row = e.target.closest('tr[data-id]');
            if (!row) return;
            const link = e.target.closest('a');
            if (link && (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0)) return; // let the browser open a new tab
            if (!link && window.getSelection().toString()) return; // user is selecting text
            e.preventDefault();
            openEvent(row.dataset.id, row.querySelector('.event-link'));
        });

        el.drawerClose.addEventListener('click', closeEvent);
        el.drawer.addEventListener('cancel', e => {
            e.preventDefault();
            closeEvent();
        });
        // Clicking the backdrop (outside the panel) closes the drawer.
        el.drawer.addEventListener('mousedown', e => {
            if (e.target !== el.drawer) return;
            const r = el.drawer.getBoundingClientRect();
            const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
            if (!inside) closeEvent();
        });
        el.drawerPrev.addEventListener('click', () => stepEvent(-1));
        el.drawerNext.addEventListener('click', () => stepEvent(1));
        el.copyLink.addEventListener('click', () => openId && copyText(permalink(openId), el.copyLink));

        el.drawerBody.addEventListener('click', e => {
            const copy = e.target.closest('[data-copy]');
            if (copy) {
                const text = copy.dataset.copy === 'cli'
                    ? el.drawer.dataset.cli
                    : (document.getElementById('logSlot') || {}).dataset.log;
                if (text) copyText(text, copy);
                return;
            }
            const scroll = e.target.closest('[data-scroll]');
            if (scroll) {
                e.preventDefault();
                const target = document.getElementById(scroll.dataset.scroll);
                if (target) target.scrollIntoView({ block: 'start' });
                return;
            }
            const svc = e.target.closest('[data-pivot-service]');
            if (svc) return pivot({ service: svc.dataset.pivotService });
            const tac = e.target.closest('[data-pivot-tactic]');
            if (tac) return pivot({ tactic: tac.dataset.pivotTactic });
            const q = e.target.closest('[data-pivot-q]');
            if (q) return pivot({ q: q.dataset.pivotQ });
        });

        document.addEventListener('keydown', e => {
            const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
            if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
            if (el.drawer.open) {
                if (e.key === 'j') stepEvent(1);
                else if (e.key === 'k') stepEvent(-1);
                return;
            }
            if (e.key === '/') {
                e.preventDefault();
                el.search.focus();
                el.search.select();
            }
        });

        // Fires for back/forward and for hash edits in the address bar.
        window.addEventListener('popstate', syncFromHash);

        // Keep the table header pinned just below the sticky search bar.
        const setOffset = () => {
            const sticky = getComputedStyle(el.controls).position === 'sticky';
            document.documentElement.style.setProperty('--controls-h', `${sticky ? el.controls.offsetHeight : 0}px`);
        };
        if ('ResizeObserver' in window) new ResizeObserver(setOffset).observe(el.controls);
        window.addEventListener('resize', setOffset);
        setOffset();

        // Show the search bar's bottom border only once it is pinned.
        const header = document.querySelector('.site-header');
        if (header && 'IntersectionObserver' in window) {
            new IntersectionObserver(([entry]) => el.controls.classList.toggle('is-stuck', !entry.isIntersecting))
                .observe(header);
        }
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    fetch('events.json')
        .then(r => r.json())
        .then(data => {
            // Skip duplicate entries (a stale events.json can list an event twice).
            const seen = new Set();
            events = data.map(prepare).filter(ev => !seen.has(ev.id) && seen.add(ev.id));
            buildIndexes();
            updateStats();
            readUrl();
            if (window.matchMedia('(max-width: 760px)').matches) {
                el.search.placeholder = 'Search events, ATT&CK IDs, incidents';
            }
            bindEvents();
            render();
            syncFromHash();
        })
        .catch(error => {
            console.error('Error loading the events data:', error);
            el.count.innerHTML = 'Could not load the event data. Reload the page, or download it as ' +
                '<a href="events.json">JSON</a> or <a href="events.csv">CSV</a>.';
        });
})();
