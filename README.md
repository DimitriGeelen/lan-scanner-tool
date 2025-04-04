# LAN Scanner Tool v2.0

A powerful C# application that scans a local area network subnet, retrieves hostnames, and exports the results to a CSV file. The tool features both a command-line interface and a web-based UI.

## Features

- **Scan Capabilities**:
  - Scans an entire subnet (e.g., 192.168.1.0/24) for active hosts
  - Automatically installs Nmap if not present on the system
  - Uses Nmap for efficient and accurate host discovery
  - Falls back to ping (ICMP) scan if Nmap fails

- **Host Resolution**:
  - Advanced hostname resolution using multiple methods
  - Fully Qualified Domain Names (FQDN) included when available
  - NetBIOS name resolution for Windows machines

- **Output Options**:
  - Command-line CSV output
  - Web interface with interactive results table
  - CSV download option in web UI

- **User Interfaces**:
  - Command-line interface
  - Modern web-based UI with Bootstrap

## Requirements

- .NET 8.0 SDK or later
- Linux/Ubuntu system (for auto-installation of Nmap)
- Sudo privileges (for installing Nmap if not present)
- Web browser (for web interface)

## Usage

### Command-line Mode

```bash
# Simple subnet scan
dotnet run 192.168.1

# Specific subnet with mask
dotnet run 192.168.1.0/24
```

### Web Interface Mode

```bash
# Start the web server
dotnet run --web
```

Then open your browser and navigate to `http://localhost:5000`

## Web Interface Features

- User-friendly form for entering subnet to scan
- Real-time scan status updates
- Tabular display of scan results
- CSV export functionality
- Responsive design for desktop and mobile

## How It Works

1. The application can run in either command-line or web interface mode
2. In both modes, it first checks if Nmap is installed
3. If Nmap is not found, it attempts to install it using `apt-get`
4. It then uses Nmap to perform a host discovery scan on the specified subnet
5. For each discovered host, it attempts to resolve the hostname and FQDN
6. If Nmap fails for any reason, it falls back to a basic ping scan
7. In command-line mode, results are displayed in the console and saved to a CSV file
8. In web mode, results are displayed in the browser and can be downloaded as CSV

## Project Structure

```
LanScannerTool/
├── Program.cs              # Main program with both console and web mode
├── LanScanner.csproj       # Project file
├── README.md               # This file
├── wwwroot/                # Web assets
│   ├── css/                # CSS stylesheets
│   │   └── site.css        # Custom styles
│   ├── js/                 # JavaScript files
│   │   └── site.js         # Client-side functionality
│   └── index.html          # Main web interface page
```

## Notes

- The scan operation may take some time depending on the network size
- Administrator privileges may be required for network operations and Nmap installation
- The tool works best on Linux/Ubuntu systems but can be adapted for other platforms

## License

MIT 