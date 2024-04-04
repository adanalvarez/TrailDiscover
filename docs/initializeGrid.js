document.addEventListener('DOMContentLoaded', function() {
    const toggleUsedInWild = document.getElementById('toggleUsedInWild');
    const mitreAttackTacticFilter = document.getElementById('mitreAttackTacticFilter');
    let filterUsedInWild = false;
    let selectedTactic = '';
    let allEventsData = [];

    // Function to render or update the grid
    function renderGrid(eventsData) {
        if (window.gridInstance) {
            window.gridInstance.updateConfig({
                data: eventsData
            }).forceRender();
        } else {
            window.gridInstance = new gridjs.Grid({
                columns: [
                    {
                        name: "Event Name",
                        width: '21%', 
                    },
                    {
                        name: "Event Source",
                        hidden: true,   
                    },
                    {
                        name: "AWS Service",
                        width: '10%',
                    },
                    {
                        name: "Description",
                        hidden: true, 
                    },
                    {
                        name: "MITRE Attack Tactics",
                        width: '21%',
                    },
                    {
                        name: "MITRE Attack Techniques",
                        width: '21%',
                    },
                    {
                        name: "Incidents",
                        width: '8%',
                    },
                    {
                        name: "Incidents",
                        hidden: true,                    
                    },
                    {
                        name: "Researchs",
                        width: '8%',
                    },
                    {
                        name: "Researchs",
                        hidden: true,                   
                    },
                    {
                        name: "Used in the Wild",
                        width: '10%',
                    },
                    {
                        name: "Security Implications",
                        hidden: true,                   
                    },
                    {
                        name: "Command Line Simulation",
                        hidden: true,                   
                    },
                    {
                        name: "Permisions",
                        hidden: true,                   
                    },
                    {
                        name: "Alerting",
                        hidden: true,                   
                    }
                ],
                data: eventsData,
                search: true,
                sort: true,
                pagination: {
                    limit: 10
                },
                className: {
                    tr: 'my-tr-class'
                  }
            }).render(document.getElementById("grid"));
            window.gridInstance.on('rowClick', (...args) => {
                const rowData = args[1].cells.map(cell => cell.data);
                const service = rowData[2]; // Assuming this is AWS Service
                const eventName = rowData[0]; // Assuming this is Event Name
                window.location.hash = `${service}-${eventName}`;
            });
        }
    }

    function parseHash() {
        const hash = window.location.hash.substring(1); // Remove '#'
        return hash ? hash.split('-') : [];
    }

    // Function to fetch and filter data
    function fetchDataAndFilter() {
        return fetch('events.json')
            .then(response => response.json())
            .then(data => {
                allEventsData = data;
                // Filter by "Used in the Wild" if toggled
                let filteredData = filterUsedInWild ? allEventsData.filter(event => event.usedInWild) : allEventsData;
                // Further filter by selected MITRE Attack Tactic if any
                if (selectedTactic) {
                    filteredData = filteredData.filter(event => event.mitreAttackTactics.includes(selectedTactic));
                }
                // Map data for grid display
                const mappedData = filteredData.map(event => [
                    event.eventName,
                    event.eventSource,
                    event.awsService,
                    event.description,
                    event.mitreAttackTactics.join(", "),
                    event.mitreAttackTechniques.join(", "),
                    event.incidents ? event.incidents.length : 0,
                    event.incidents,
                    event.researchLinks ? event.researchLinks.length : 0,
                    event.researchLinks,
                    event.usedInWild ? "True" : "Unknown",
                    event.securityImplications,
                    event.simulation,
                    event.permissions,
                    event.alerting
                ]);
                renderGrid(mappedData);
            })
            .catch(error => console.error('Error loading the events data:', error));
    }

    function findAndShowEventFromHash() {
        const [service, eventName] = parseHash();
        if (service && eventName) {
            const event = allEventsData.find(e => e.awsService === service && e.eventName === eventName);
            if (event) showModalWithEventData(event);
        }
    }
    // Function to show modal with event data
    function showModalWithEventData(event) {
        const modalBody = document.getElementById('eventModalBody');
        modalBody.innerHTML = ''; // Clear previous content
    
        // Title
        const title = document.createElement('h5');
        title.textContent = event.eventName;
        modalBody.appendChild(title);
    
        // Event Source
        const eventSource = document.createElement('p');
        eventSource.innerHTML = `<strong>Event Source:</strong> ${event.eventSource}`;
        modalBody.appendChild(eventSource);
    
        // Service
        const service = document.createElement('p');
        service.innerHTML = `<strong>Service:</strong> ${event.awsService}`;
        modalBody.appendChild(service);
    
        // Description
        const description = document.createElement('p');
        description.innerHTML = `<strong>Description:</strong> ${event.description}`;
        modalBody.appendChild(description);
    
        // MITRE Attack Tactics
        const mitreAttackTactics = document.createElement('p');
        mitreAttackTactics.innerHTML = `<strong>MITRE Attack Tactics:</strong> ${event.mitreAttackTactics.join(", ")}`;
        modalBody.appendChild(mitreAttackTactics);
    
        // MITRE Attack Techniques
        const mitreAttackTechniques = document.createElement('p');
        mitreAttackTechniques.innerHTML = `<strong>MITRE Attack Techniques:</strong> ${event.mitreAttackTechniques.join(", ")}`;
        modalBody.appendChild(mitreAttackTechniques);
        // Add Related Incidents if they exist
        if (event.incidents.length > 0) {
            const incidentsTitle = document.createElement('p');
            incidentsTitle.innerHTML = `<strong>Related Incidents:</strong>`;
            modalBody.appendChild(incidentsTitle);
        
            // Create an unordered list for incidents
            const incidentsList = document.createElement('ul');
            event.incidents.forEach(incident => {
                const listItem = document.createElement('li');
                const incidentElement = document.createElement('a');
                incidentElement.href = incident.link;
                incidentElement.textContent = incident.description;
                incidentElement.target = "_blank";
                listItem.appendChild(incidentElement); 
                incidentsList.appendChild(listItem);
            });
            modalBody.appendChild(incidentsList);
        }
        
        // Add Related Research if it exists
        if (event.researchLinks.length > 0) {
            const researchTitle = document.createElement('p');
            researchTitle.innerHTML = `<strong>Related Research:</strong>`;
            modalBody.appendChild(researchTitle);
        
            // Create an unordered list for research links
            const researchList = document.createElement('ul');
            event.researchLinks.forEach(research => {
                const listItem = document.createElement('li');
                const researchElement = document.createElement('a');
                researchElement.href = research.link;
                researchElement.textContent = research.description;
                researchElement.target = "_blank"; 
                listItem.appendChild(researchElement);
                researchList.appendChild(listItem);
            });
            modalBody.appendChild(researchList);
        }
    
        // Security Implications       
        const securityImplications = document.createElement('p');
        securityImplications.innerHTML = `<strong>Security Implications:</strong> ${event.securityImplications}`;
        modalBody.appendChild(securityImplications);

        // Permissions
        const permissions = document.createElement('p');
        permissions.innerHTML = `<strong>Permissions:&nbsp&nbsp</strong>`;
        const permissionsLink = event.permissions;
        if ( permissionsLink != "N/A"){
            const permissionsAnchor = document.createElement('a');
            permissionsAnchor.href = permissionsLink;
            permissionsAnchor.target = "_blank";
            const permissionsImage = document.createElement('img');
            permissionsImage.src = 'logos/permissions.png';
            permissionsImage.alt = 'Click to permissions.cloud';
            permissionsImage.style.width = '30px';
            permissionsImage.style.height = 'auto';
            permissionsImage.style.cursor = 'pointer';
            permissionsAnchor.appendChild(permissionsImage);
            permissions.appendChild(permissionsAnchor);  
        }
        modalBody.appendChild(permissions);
        
        // Alerting
        const alerting = document.createElement('p');
        alerting.innerHTML = `<strong>Alerting:&nbsp;&nbsp;</strong>`;
        // cloudwatchCISControls
        event.alerting.forEach(item => {
            if (item.type === "cloudwatchCISControls") {
                const alertingLink = item.value;
                const alertingAnchor = document.createElement('a');
                alertingAnchor.href = alertingLink;
                alertingAnchor.target = "_blank";
                const alertingImage = document.createElement('img');
                alertingImage.src = 'logos/cloudwatch.png';
                alertingImage.alt = 'Click to docs.aws.amazon.com';
                alertingImage.style.width = '30px';
                alertingImage.style.height = 'auto';
                alertingImage.style.cursor = 'pointer';
                alertingImage.style.marginRight = '10px'; // Adds space to the right of each image

                alertingAnchor.appendChild(alertingImage);
                alerting.appendChild(alertingAnchor);
            }
        });

        // Finally, append the alerting paragraph (with all images) to the modal body
        modalBody.appendChild(alerting);

        // Simulation
        const simulation = document.createElement('p');
        simulation.innerHTML = `<strong>Simulation:&nbsp;&nbsp;</strong>`;
        // stratusRedTeam
        event.simulation.forEach(item => {
            if (item.type === "stratusRedTeam") {
                const stratusLink = item.value;
                const stratusAnchor = document.createElement('a');
                stratusAnchor.href = stratusLink;
                stratusAnchor.target = "_blank";
                const stratusImage = document.createElement('img');
                stratusImage.src = 'logos/stratusredteam.png';
                stratusImage.alt = 'Click to stratus-red-team.cloud';
                stratusImage.style.width = '30px';
                stratusImage.style.height = 'auto';
                stratusImage.style.cursor = 'pointer';
                stratusImage.style.marginRight = '5px';
                stratusAnchor.appendChild(stratusImage);
                simulation.appendChild(stratusAnchor);
            }
        });
        modalBody.appendChild(simulation);
        // Command Line
        const commandLine = document.createElement('p');
        commandLine.innerHTML = `<h6>Command Line:</h6>`;
        modalBody.appendChild(commandLine);
        const commandLineContainer = document.createElement('div');
        commandLineContainer.className = 'command-line-container';

        const commandLineText = document.createElement('pre');
        commandLineText.textContent = event.simulation.find(item => item.type === "commandLine").value
        commandLineContainer.appendChild(commandLineText);

        const copyIcon = document.createElement('i');
        copyIcon.className = 'copy-icon fas fa-copy';
        copyIcon.onclick = function() {
            navigator.clipboard.writeText(commandLineText.textContent);
        };

        commandLineContainer.appendChild(copyIcon);
        modalBody.appendChild(commandLineContainer);

    
        // Create a new instance of the Modal and show it
        const eventModal = new bootstrap.Modal(document.getElementById('eventModal'));
        eventModal.show();
    }

    // Event listeners for filters
    toggleUsedInWild.addEventListener('click', () => {
        filterUsedInWild = !filterUsedInWild; // Toggle the "Used in Wild" filter
        toggleUsedInWild.style.backgroundColor = filterUsedInWild ? "#219EBC" : ""; // Toggle color
        fetchDataAndFilter(); // Refetch and filter data
    });

    mitreAttackTacticFilter.addEventListener('change', function() {
        selectedTactic = this.value; // Set the selected MITRE Attack Tactic
        fetchDataAndFilter(); // Refetch and filter data
    });

    window.addEventListener('hashchange', function() {
        const hash = window.location.hash.substring(1); // Remove '#'
        const [service, eventName] = hash.split('-');
        const event = allEventsData.find(e => e.awsService === service && e.eventName === eventName);
        if (event) showModalWithEventData(event);
    });
  
    // Initial data fetch and render
    fetchDataAndFilter().then(findAndShowEventFromHash);
});