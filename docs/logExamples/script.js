// script.js
document.addEventListener("DOMContentLoaded", function() {
    const viewer = document.getElementById('jsonViewer');
    const meta = document.getElementById('logMeta');
    const title = document.getElementById('logTitle');
    const backLink = document.getElementById('backLink');
    const copyButton = document.getElementById('copyLog');
    const NAME_PATTERN = /^[a-zA-Z0-9\-_]+$/;

    const urlParams = new URLSearchParams(window.location.search);
    const eventName = urlParams.get('event'); // Get 'event' parameter from URL
    const service = urlParams.get('service'); // Optional AWS service, e.g. 'IAM'

    // Validate the parameters to contain only allowed characters
    function candidateFiles() {
        if (!eventName || !NAME_PATTERN.test(eventName)) {
            console.error('Invalid event name provided. Only CloudTrail eventNames accepted');
            return [];
        }
        const files = [`${eventName}.json.cloudtrail`];
        // Event names are not unique across services; prefer the service-specific copy when it exists.
        if (service && NAME_PATTERN.test(service)) files.unshift(`${service}-${eventName}.json.cloudtrail`);
        return files;
    }

    function esc(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    function highlightJson(json) {
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

    async function load() {
        const files = candidateFiles();
        if (!files.length) throw new Error('No valid event name in the URL.');
        for (const fileName of files) {
            const response = await fetch(fileName);
            if (response.ok) return response.json();
        }
        throw new Error('No example log found for ' + eventName);
    }

    if (eventName && NAME_PATTERN.test(eventName)) {
        title.textContent = eventName;
        document.title = `${eventName} - CloudTrail Log Example - TrailDiscover`;
        if (service && NAME_PATTERN.test(service)) backLink.href = `../#${service}-${eventName}`;
    }

    load()
        .then(jsonData => {
            const text = JSON.stringify(jsonData, null, 2);
            const records = Array.isArray(jsonData) ? jsonData.length : 1;
            viewer.innerHTML = highlightJson(text);
            meta.textContent = `${records} ${records === 1 ? 'record' : 'records'}`;
            copyButton.disabled = false;
            copyButton.addEventListener('click', () => {
                navigator.clipboard.writeText(text).then(() => {
                    copyButton.textContent = 'Copied';
                    setTimeout(() => { copyButton.textContent = 'Copy'; }, 1500);
                });
            });
        })
        .catch(error => {
            console.error('Error loading the JSON file:', error);
            meta.textContent = 'Not available';
            viewer.textContent = 'Failed to load JSON data: ' + error.message;
        });
});
