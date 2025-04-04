document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const scanForm = document.getElementById('scanForm');
    const scanButton = document.getElementById('scanButton');
    const scanSpinner = document.getElementById('scanSpinner');
    const resultsInfo = document.getElementById('resultsInfo');
    const resultsTable = document.getElementById('resultsTable');
    const resultsBody = document.getElementById('resultsBody');
    const downloadCsvButton = document.getElementById('downloadCsvButton');
    
    // Current subnet
    let currentSubnet = '';
    
    // Form submit event
    scanForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Get form data
        const formData = new FormData(scanForm);
        const subnet = formData.get('subnet');
        currentSubnet = subnet;
        
        // Show loading state
        scanButton.disabled = true;
        scanSpinner.classList.remove('d-none');
        resultsInfo.classList.remove('alert-success', 'alert-danger');
        resultsInfo.classList.add('alert-info');
        resultsInfo.textContent = 'Scanning network... This may take a while.';
        resultsTable.classList.add('d-none');
        downloadCsvButton.classList.add('d-none');
        
        try {
            // Send request to the server
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData
            });
            
            // Check if request was successful
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.statusText}`);
            }
            
            // Parse JSON response
            const hosts = await response.json();
            
            // Display results
            displayResults(hosts);
            
            // Show success message
            resultsInfo.classList.remove('alert-info', 'alert-danger');
            resultsInfo.classList.add('alert-success');
            resultsInfo.textContent = `Scan completed successfully. Found ${hosts.length} active hosts.`;
            
            // Show download button
            if (hosts.length > 0) {
                downloadCsvButton.classList.remove('d-none');
            }
        } catch (error) {
            // Show error message
            resultsInfo.classList.remove('alert-info', 'alert-success');
            resultsInfo.classList.add('alert-danger');
            resultsInfo.textContent = `Error during scan: ${error.message}`;
            console.error('Error:', error);
        } finally {
            // Reset loading state
            scanButton.disabled = false;
            scanSpinner.classList.add('d-none');
        }
    });
    
    // Download CSV button click event
    downloadCsvButton.addEventListener('click', function() {
        if (!currentSubnet) return;
        
        // Create a download link
        const downloadUrl = `/api/download-csv?subnet=${encodeURIComponent(currentSubnet)}`;
        window.location.href = downloadUrl;
    });
    
    // Function to display scan results
    function displayResults(hosts) {
        // Clear previous results
        resultsBody.innerHTML = '';
        
        // If no hosts found
        if (hosts.length === 0) {
            resultsTable.classList.add('d-none');
            return;
        }
        
        // Add each host to the table
        hosts.forEach(host => {
            const row = document.createElement('tr');
            
            // IP Address
            const ipCell = document.createElement('td');
            ipCell.textContent = host.ipAddress;
            row.appendChild(ipCell);
            
            // Hostname
            const hostnameCell = document.createElement('td');
            hostnameCell.textContent = host.hostname || 'unknown';
            row.appendChild(hostnameCell);
            
            // FQDN
            const fqdnCell = document.createElement('td');
            fqdnCell.textContent = host.fqdn || '-';
            row.appendChild(fqdnCell);
            
            // Add the row to the table
            resultsBody.appendChild(row);
        });
        
        // Show the table
        resultsTable.classList.remove('d-none');
    }
}); 