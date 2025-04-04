document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const scanForm = document.getElementById('scanForm');
    const scanButton = document.getElementById('scanButton');
    const scanSpinner = document.getElementById('scanSpinner');
    const resultsInfo = document.getElementById('resultsInfo');
    const resultsTable = document.getElementById('resultsTable');
    const resultsBody = document.getElementById('resultsBody');
    const downloadCsvButton = document.getElementById('downloadCsvButton');
    const includePortScanCheckbox = document.getElementById('includePortScan');
    
    // Modal elements
    const serviceModal = new bootstrap.Modal(document.getElementById('serviceModal'));
    const serviceModalLabel = document.getElementById('serviceModalLabel');
    const portsTableBody = document.getElementById('portsTableBody');
    const servicesTableBody = document.getElementById('servicesTableBody');
    const osInfoText = document.getElementById('osInfoText');
    
    // Changelog modal
    const changelogModal = new bootstrap.Modal(document.getElementById('changelogModal'));
    const changelogLink = document.getElementById('changelogLink');
    
    // Show changelog when link is clicked
    if (changelogLink) {
        changelogLink.addEventListener('click', function(e) {
            e.preventDefault();
            changelogModal.show();
        });
    }
    
    // Current subnet and port scan option
    let currentSubnet = '';
    let currentPortScan = false;
    
    // Show services column if port scanning is enabled
    includePortScanCheckbox.addEventListener('change', function() {
        const servicesColumn = document.querySelector('.col-services');
        const osColumn = document.querySelector('.col-os');
        if (this.checked) {
            servicesColumn.classList.remove('d-none');
            osColumn.classList.remove('d-none');
        } else {
            servicesColumn.classList.add('d-none');
            osColumn.classList.add('d-none');
        }
    });
    
    // Form submit event
    scanForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Get form data
        const formData = new FormData(scanForm);
        const subnet = formData.get('subnet');
        currentSubnet = subnet;
        currentPortScan = formData.has('includePortScan') && formData.get('includePortScan') === 'true';
        
        // Update UI based on port scan option
        const servicesColumn = document.querySelector('.col-services');
        const osColumn = document.querySelector('.col-os');
        if (currentPortScan) {
            servicesColumn.classList.remove('d-none');
            osColumn.classList.remove('d-none');
        } else {
            servicesColumn.classList.add('d-none');
            osColumn.classList.add('d-none');
        }
        
        // Show loading state
        scanButton.disabled = true;
        scanSpinner.classList.remove('d-none');
        resultsInfo.classList.remove('alert-success', 'alert-danger');
        resultsInfo.classList.add('alert-info');
        resultsInfo.textContent = currentPortScan ? 
            'Scanning network and detecting services... This may take a while.' : 
            'Scanning network... This may take a while.';
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
        
        // Create a download link with port scan option
        const downloadUrl = `/api/download-csv?subnet=${encodeURIComponent(currentSubnet)}${currentPortScan ? '&includePortScan=true' : ''}`;
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
            row.setAttribute('data-host', JSON.stringify(host));
            
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
            
            // Services (if port scan was performed)
            const servicesCell = document.createElement('td');
            if (host.detectedServices && host.detectedServices.length > 0) {
                // Create button to show services
                const servicesButton = document.createElement('button');
                servicesButton.className = 'btn btn-sm btn-outline-primary';
                servicesButton.innerHTML = '<i class="bi bi-info-circle"></i> ' + host.detectedServices.length + ' services';
                servicesButton.addEventListener('click', function() {
                    showServiceDetails(host);
                });
                servicesCell.appendChild(servicesButton);
            } else if (host.openPorts && host.openPorts.length > 0) {
                // Create button to show ports
                const portsButton = document.createElement('button');
                portsButton.className = 'btn btn-sm btn-outline-secondary';
                portsButton.innerHTML = '<i class="bi bi-hdd-network"></i> ' + host.openPorts.length + ' ports';
                portsButton.addEventListener('click', function() {
                    showServiceDetails(host);
                });
                servicesCell.appendChild(portsButton);
            } else {
                servicesCell.textContent = 'No services detected';
            }
            servicesCell.classList.add('col-services');
            if (!currentPortScan) {
                servicesCell.classList.add('d-none');
            }
            row.appendChild(servicesCell);
            
            // OS Info
            const osCell = document.createElement('td');
            if (host.osInfo) {
                osCell.textContent = host.osInfo;
            } else {
                osCell.textContent = '—';
            }
            osCell.classList.add('col-os');
            if (!currentPortScan) {
                osCell.classList.add('d-none');
            }
            row.appendChild(osCell);
            
            // Add the row to the table
            resultsBody.appendChild(row);
        });
        
        // Show the table
        resultsTable.classList.remove('d-none');
    }
    
    // Function to show service details modal
    function showServiceDetails(host) {
        // Set modal title
        serviceModalLabel.textContent = `Services on ${host.ipAddress} (${host.hostname})`;
        
        // Set OS information
        osInfoText.textContent = host.osInfo || 'Unknown';
        
        // Clear previous data
        portsTableBody.innerHTML = '';
        servicesTableBody.innerHTML = '';
        
        // Add open ports
        if (host.openPorts && host.openPorts.length > 0) {
            host.openPorts.forEach(port => {
                const row = document.createElement('tr');
                
                // Port
                const portCell = document.createElement('td');
                portCell.textContent = port.port;
                row.appendChild(portCell);
                
                // Service
                const serviceCell = document.createElement('td');
                serviceCell.textContent = port.serviceName || '-';
                row.appendChild(serviceCell);
                
                // Version
                const versionCell = document.createElement('td');
                versionCell.textContent = port.version || '-';
                row.appendChild(versionCell);
                
                portsTableBody.appendChild(row);
            });
        } else {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = 'No open ports detected';
            cell.colSpan = 3;
            cell.className = 'text-center';
            row.appendChild(cell);
            portsTableBody.appendChild(row);
        }
        
        // Add detected services
        if (host.detectedServices && host.detectedServices.length > 0) {
            host.detectedServices.forEach(service => {
                const row = document.createElement('tr');
                
                // Service
                const serviceCell = document.createElement('td');
                serviceCell.textContent = service.serviceName;
                row.appendChild(serviceCell);
                
                // Vendor
                const vendorCell = document.createElement('td');
                vendorCell.textContent = service.vendorName;
                row.appendChild(vendorCell);
                
                // Access URL
                const accessCell = document.createElement('td');
                if (service.accessUrl) {
                    const link = document.createElement('a');
                    link.href = service.accessUrl;
                    link.textContent = 'Open';
                    link.target = '_blank';
                    link.className = 'btn btn-sm btn-outline-primary';
                    accessCell.appendChild(link);
                } else {
                    accessCell.textContent = '-';
                }
                row.appendChild(accessCell);
                
                servicesTableBody.appendChild(row);
            });
        } else {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = 'No services identified';
            cell.colSpan = 3;
            cell.className = 'text-center';
            row.appendChild(cell);
            servicesTableBody.appendChild(row);
        }
        
        // Show modal
        serviceModal.show();
    }
}); 