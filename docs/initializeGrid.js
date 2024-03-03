document.addEventListener('DOMContentLoaded', function() {
    const toggleUsedInWild = document.getElementById('toggleUsedInWild');
    const mitreAttackTacticFilter = document.getElementById('mitreAttackTacticFilter');
    let filterUsedInWild = false;
    let selectedTactic = '';

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
                        width: '19%', 
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
                        width: '22%',
                    },
                    {
                        name: "MITRE Attack Techniques",
                        width: '22%',
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
                showModalWithEventData(rowData);
            });
        }
    }

    // Function to fetch and filter data
    function fetchDataAndFilter() {
        fetch('events.json')
            .then(response => response.json())
            .then(allEventsData => {
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
                    event.securityImplications
                ]);
                renderGrid(mappedData);
            })
            .catch(error => console.error('Error loading the events data:', error));
    }
    // Function to show modal with event data
    function showModalWithEventData(data) {
        const modalBody = document.getElementById('eventModalBody');
        modalBody.innerHTML = ''; // Clear previous content
    
        // Title
        const title = document.createElement('h5');
        title.textContent = data[0];
        modalBody.appendChild(title);
    
        // Event Source
        const eventSource = document.createElement('p');
        eventSource.innerHTML = `<strong>Event Source:</strong> ${data[1]}`;
        modalBody.appendChild(eventSource);
    
        // Service
        const service = document.createElement('p');
        service.innerHTML = `<strong>Service:</strong> ${data[2]}`;
        modalBody.appendChild(service);
    
        // Description
        const description = document.createElement('p');
        description.innerHTML = `<strong>Description:</strong> ${data[3]}`;
        modalBody.appendChild(description);
    
        // MITRE Attack Tactics
        const mitreAttackTactics = document.createElement('p');
        mitreAttackTactics.innerHTML = `<strong>MITRE Attack Tactics:</strong> ${data[4]}`;
        modalBody.appendChild(mitreAttackTactics);
    
        // MITRE Attack Techniques
        const mitreAttackTechniques = document.createElement('p');
        mitreAttackTechniques.innerHTML = `<strong>MITRE Attack Techniques:</strong> ${data[5]}`;
        modalBody.appendChild(mitreAttackTechniques);
    
        // Add Related Incidents if they exist
        if (data[7].length > 0) {
            const incidentsTitle = document.createElement('p');
            incidentsTitle.innerHTML = `<strong>Related Incidents:</strong>`;
            modalBody.appendChild(incidentsTitle);
        
            // Create an unordered list for incidents
            const incidentsList = document.createElement('ul');
            data[7].forEach(incident => {
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
        if (data[9].length > 0) {
            const researchTitle = document.createElement('p');
            researchTitle.innerHTML = `<strong>Related Research:</strong>`;
            modalBody.appendChild(researchTitle);
        
            // Create an unordered list for research links
            const researchList = document.createElement('ul');
            data[9].forEach(research => {
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
        securityImplications.innerHTML = `<strong>Security Implications:</strong> ${data[data.length - 1]}`;
        modalBody.appendChild(securityImplications);
    
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
  
    // Initial data fetch and render
    fetchDataAndFilter();
});