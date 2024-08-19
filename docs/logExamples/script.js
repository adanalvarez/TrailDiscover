// script.js
document.addEventListener("DOMContentLoaded", function() {
    const viewer = document.getElementById('jsonViewer');

    function getEventFileName() {
        const urlParams = new URLSearchParams(window.location.search);
        const eventName = urlParams.get('event'); // Get 'event' parameter from URL
    
        // Validate the eventName to contain only allowed characters
        if (eventName && /^[a-zA-Z0-9\-_]+$/.test(eventName)) {
            return `${eventName}.json.cloudtrail`;
        } else {
            console.error('Invalid event name provided. Only CloudTrail eventNames accepted');
            return 'default.json'; 
        }
    }
    

    function createJsonHtml(obj, indent = 0) {
        const indentSpace = '&nbsp;'.repeat(indent * 4); // Creates indentation
        if (typeof obj === 'object' && obj !== null) {
            if (Array.isArray(obj)) {
                const items = obj.map(item => `${createJsonHtml(item, indent + 1)}`);
                return `[ <br>${indentSpace}${items.join(', <br>' + indentSpace)}<br>${indentSpace}]`;
            } else {
                const props = Object.keys(obj).map(key => {
                    return `${indentSpace}<span class="key">${key}:</span> ${createJsonHtml(obj[key], indent + 1)}`;
                });
                return `{<br>${props.join(',<br>')}<br>${indentSpace}}`;
            }
        } else {
            return formatPrimitive(obj);
        }
    }

    function formatPrimitive(value) {
        if (typeof value === 'string') return `<span class="string">"${value}"</span>`;
        if (typeof value === 'number') return `<span class="number">${value}</span>`;
        if (typeof value === 'boolean') return `<span class="boolean">${value}</span>`;
        if (value === null) return `<span class="null">null</span>`;
        return value; // Fallback for other types, if any
    }

    const fileName = getEventFileName();
    fetch(fileName)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok for ' + fileName);
            }
            return response.json();
        })
        .then(jsonData => {
            viewer.innerHTML = createJsonHtml(jsonData);
        })
        .catch(error => {
            console.error('Error loading the JSON file:', error);
            viewer.textContent = 'Failed to load JSON data: ' + error.message;
        });
});
