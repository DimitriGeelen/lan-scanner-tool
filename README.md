# LAN Scanner Tool

A powerful C# console application that scans a local area network subnet, retrieves hostnames, and exports the results to a CSV file. The tool uses Nmap for better host discovery and integrates with DNS resolution.

## Features

- Scans an entire subnet (e.g., 192.168.1.0/24) for active hosts
- Automatically installs Nmap if not present on the system 
- Uses Nmap for efficient and accurate host discovery
- Fallback to ping (ICMP) scan if Nmap fails
- Advanced hostname resolution using multiple methods
- Fully Qualified Domain Names (FQDN) included when available
- Exports the results to a CSV file (`hostnames.csv`)
- Supports command-line argument for specifying the subnet

## Requirements

- .NET 8.0 SDK or later
- Linux/Ubuntu system (for auto-installation of Nmap)
- Sudo privileges (for installing Nmap if not present)

## Usage

### Build

```bash
dotnet build
```

### Run

```bash
dotnet run
```

You will be prompted to enter a subnet to scan. Alternatively, you can specify the subnet as a command-line argument:

```bash
dotnet run 192.168.1
```

## CSV Output Format

The application generates a CSV file named `hostnames.csv` with the following columns:

- IP Address
- Hostname
- FQDN (Fully Qualified Domain Name)

## How It Works

1. The application first checks if Nmap is installed
2. If Nmap is not found, it attempts to install it using `apt-get`
3. It then uses Nmap to perform a host discovery scan on the specified subnet
4. For each discovered host, it attempts to resolve the hostname and FQDN
5. If Nmap fails for any reason, it falls back to a basic ping scan
6. All discovered hosts are saved to a CSV file

## Notes

- The scan operation may take some time depending on the network size
- Administrator privileges may be required for network operations and Nmap installation
- The tool works best on Linux/Ubuntu systems but can be adapted for other platforms

## License

MIT 