using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace LanScannerTool
{
    class Program
    {
        public static readonly string Version = "3.1.1";
        
        // Version update utility:
        // When making changes, update version by:
        // 1. Increment major version for breaking changes
        // 2. Increment minor version for new features
        // 3. Increment patch version for bug fixes
        // Format: MAJOR.MINOR.PATCH
        // Example: Current: 3.1, Next feature: 3.2, Bug fix: 3.1.1, Breaking change: 4.0
        
        static async Task Main(string[] args)
        {
            // Check if running in web mode
            bool webMode = args.Length > 0 && args[0].Equals("--web", StringComparison.OrdinalIgnoreCase);

            if (webMode)
            {
                await RunWebMode(args);
            }
            else
            {
                await RunConsoleMode(args);
            }
        }

        static async Task RunWebMode(string[] args)
        {
            // Check and install nmap if needed
            await NetworkScanner.EnsureNmapInstalledAsync();

            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container
            builder.Services.AddSingleton<NetworkScanner>();
            
            // Add Razor Pages
            builder.Services.AddRazorPages();

            var app = builder.Build();

            // Configure middleware
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseStaticFiles();
            app.UseRouting();

            // Define endpoints
            app.MapRazorPages();
            
            // API endpoint to scan network
            app.MapPost("/api/scan", async (HttpContext context, NetworkScanner scanner) =>
            {
                try
                {
                    var form = await context.Request.ReadFormAsync();
                    string subnet = form["subnet"].ToString();
                    bool includePortScan = form.ContainsKey("includePortScan") && form["includePortScan"] == "true";
                    
                    if (string.IsNullOrWhiteSpace(subnet))
                    {
                        return Results.BadRequest("Subnet parameter is required");
                    }

                    Console.WriteLine($"Starting scan of subnet: {subnet} with port scanning: {includePortScan}");
                    var hosts = await scanner.ScanNetworkWithNmapAsync(subnet, includePortScan);
                    
                    // Convert to a format that will properly serialize
                    var result = hosts.Select(h => new {
                        ipAddress = h.IpAddress,
                        hostname = h.Hostname,
                        fqdn = h.Fqdn,
                        osInfo = h.OsInfo,
                        openPorts = h.OpenPorts.Select(p => new {
                            port = p.Port,
                            serviceName = p.ServiceName,
                            version = p.Version
                        }).ToList(),
                        detectedServices = h.DetectedServices.Select(s => new {
                            serviceName = s.ServiceName,
                            serviceType = s.ServiceType.ToString(),
                            vendorName = s.VendorName,
                            port = s.Port,
                            accessUrl = s.AccessUrl
                        }).ToList()
                    }).ToList();
                    
                    return Results.Json(result);
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message);
                }
            });

            // API endpoint to download CSV
            app.MapGet("/api/download-csv", async (HttpContext context, NetworkScanner scanner) =>
            {
                try
                {
                    string subnet = context.Request.Query["subnet"].ToString();
                    bool includePortScan = context.Request.Query.ContainsKey("includePortScan") && 
                                           context.Request.Query["includePortScan"] == "true";
                    
                    if (string.IsNullOrWhiteSpace(subnet))
                    {
                        return Results.BadRequest("Subnet parameter is required");
                    }

                    var hosts = await scanner.ScanNetworkWithNmapAsync(subnet, includePortScan);
                    
                    // Generate CSV content
                    StringBuilder csv = new StringBuilder();
                    
                    if (includePortScan)
                    {
                        csv.AppendLine("IP Address,Hostname,FQDN,Open Ports,Detected Services,Service Types,Vendor Names,Access URLs");
                        
                        foreach (var host in hosts)
                        {
                            // Escape commas in values
                            string hostname = host.Hostname.Contains(",") ? $"\"{host.Hostname}\"" : host.Hostname;
                            string fqdn = host.Fqdn.Contains(",") ? $"\"{host.Fqdn}\"" : host.Fqdn;
                            
                            // Combine ports, services, types and vendors with semicolons
                            string ports = string.Join("; ", host.OpenPorts.Select(p => $"{p.Port}/{p.ServiceName}"));
                            string services = string.Join("; ", host.DetectedServices.Select(s => s.ServiceName));
                            string serviceTypes = string.Join("; ", host.DetectedServices.Select(s => s.ServiceType.ToString()));
                            string vendors = string.Join("; ", host.DetectedServices.Select(s => s.VendorName));
                            string accessUrls = string.Join("; ", host.DetectedServices.Select(s => s.AccessUrl));
                            
                            // Quote fields with semicolons to avoid CSV parsing issues
                            ports = ports.Contains(";") ? $"\"{ports}\"" : ports;
                            services = services.Contains(";") ? $"\"{services}\"" : services;
                            serviceTypes = serviceTypes.Contains(";") ? $"\"{serviceTypes}\"" : serviceTypes;
                            vendors = vendors.Contains(";") ? $"\"{vendors}\"" : vendors;
                            accessUrls = accessUrls.Contains(";") ? $"\"{accessUrls}\"" : accessUrls;
                            
                            csv.AppendLine($"{host.IpAddress},{hostname},{fqdn},{ports},{services},{serviceTypes},{vendors},{accessUrls}");
                        }
                    }
                    else
                    {
                        csv.AppendLine("IP Address,Hostname,FQDN");
                        
                        foreach (var host in hosts)
                        {
                            string hostname = host.Hostname.Contains(",") ? $"\"{host.Hostname}\"" : host.Hostname;
                            string fqdn = host.Fqdn.Contains(",") ? $"\"{host.Fqdn}\"" : host.Fqdn;
                            
                            csv.AppendLine($"{host.IpAddress},{hostname},{fqdn}");
                        }
                    }
                    
                    // Return CSV file
                    byte[] csvBytes = Encoding.UTF8.GetBytes(csv.ToString());
                    return Results.File(
                        fileContents: csvBytes,
                        contentType: "text/csv",
                        fileDownloadName: "hostnames.csv"
                    );
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message);
                }
            });

            // Default route
            app.MapGet("/", () => Results.Redirect("/index.html"));

            Console.WriteLine($"LAN Scanner Tool v{Version} - Web Interface");
            Console.WriteLine("Navigate to http://localhost:5000 to access the tool.");
            await app.RunAsync();
        }

        static async Task RunConsoleMode(string[] args)
        {
            Console.WriteLine($"LAN Scanner Tool v{Version}");
            Console.WriteLine("-----------------");

            // Check and install nmap if needed
            await NetworkScanner.EnsureNmapInstalledAsync();
            
            var scanner = new NetworkScanner();

            string subnet = "";
            bool includePortScan = false;

            // Parse command line arguments
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("--port-scan", StringComparison.OrdinalIgnoreCase) || 
                    args[i].Equals("-p", StringComparison.OrdinalIgnoreCase))
                {
                    includePortScan = true;
                }
                else if (!args[i].StartsWith("-"))
                {
                    subnet = args[i];
                }
            }

            if (string.IsNullOrEmpty(subnet))
            {
                Console.Write("Enter subnet to scan (e.g., 192.168.1): ");
                subnet = Console.ReadLine()?.Trim() ?? "192.168.1";
                
                Console.Write("Include port scan and service detection? (y/n): ");
                string portScanResponse = Console.ReadLine()?.Trim().ToLower() ?? "n";
                includePortScan = portScanResponse == "y" || portScanResponse == "yes";
            }

            if (!subnet.EndsWith("."))
            {
                subnet += ".";
            }

            Console.WriteLine($"Scanning subnet: {subnet}0/24...");
            Console.WriteLine($"Port scanning and service detection: {(includePortScan ? "Enabled" : "Disabled")}");
            
            List<HostInfo> hosts = await scanner.ScanNetworkWithNmapAsync($"{subnet}0/24", includePortScan);
            
            // Display results
            Console.WriteLine("\nScan Results:");
            Console.WriteLine("-------------");
            
            foreach (var host in hosts)
            {
                Console.WriteLine($"Host: {host.IpAddress} - {host.Hostname} - {host.Fqdn}");
                
                if (includePortScan && host.OpenPorts.Count > 0)
                {
                    Console.WriteLine("  Open Ports:");
                    foreach (var port in host.OpenPorts)
                    {
                        Console.WriteLine($"    {port.Port}/tcp - {port.ServiceName} {port.Version}");
                    }
                    
                    if (host.DetectedServices.Count > 0)
                    {
                        Console.WriteLine("  Detected Services:");
                        foreach (var service in host.DetectedServices)
                        {
                            Console.WriteLine($"    {service.ServiceName} ({service.VendorName}) - {service.AccessUrl}");
                        }
                    }
                    
                    Console.WriteLine();
                }
            }

            Console.WriteLine($"Found {hosts.Count} active hosts on the network.");
            
            // Save to CSV
            string csvPath = Path.Combine(Environment.CurrentDirectory, "hostnames.csv");
            NetworkScanner.SaveToCsv(hosts, csvPath);
            
            Console.WriteLine($"Results saved to: {csvPath}");
        }
    }
    
    public class NetworkScanner
    {
        // Known service ports
        private static readonly Dictionary<int, ServiceInfo> KnownServices = new Dictionary<int, ServiceInfo>
        {
            // Synology DSM
            { 5000, new ServiceInfo { Name = "Synology DSM", Type = ServiceType.AdminInterface, VendorName = "Synology" } },
            { 5001, new ServiceInfo { Name = "Synology DSM (HTTPS)", Type = ServiceType.AdminInterface, VendorName = "Synology" } },
            { 5005, new ServiceInfo { Name = "Synology DiskStation", Type = ServiceType.AdminInterface, VendorName = "Synology" } },
            { 5006, new ServiceInfo { Name = "Synology DiskStation (HTTPS)", Type = ServiceType.AdminInterface, VendorName = "Synology" } },
            
            // QNAP
            { 8080, new ServiceInfo { Name = "QNAP Web Admin", Type = ServiceType.AdminInterface, VendorName = "QNAP" } },
            { 8443, new ServiceInfo { Name = "QNAP Web Admin (HTTPS)", Type = ServiceType.AdminInterface, VendorName = "QNAP" } },
            { 8181, new ServiceInfo { Name = "QNAP QTS", Type = ServiceType.AdminInterface, VendorName = "QNAP" } },
            
            // Pi-hole
            { 80, new ServiceInfo { Name = "HTTP (Possible Pi-hole/Web UI)", Type = ServiceType.AdminInterface, VendorName = "Various" } },
            { 443, new ServiceInfo { Name = "HTTPS (Possible Pi-hole/Web UI)", Type = ServiceType.AdminInterface, VendorName = "Various" } },
            
            // NPMPlus
            { 81, new ServiceInfo { Name = "NPMPlus/Nginx Proxy Manager", Type = ServiceType.AdminInterface, VendorName = "NPMPlus" } },
            
            // UniFi
            { 8443, new ServiceInfo { Name = "UniFi Controller", Type = ServiceType.AdminInterface, VendorName = "Ubiquiti" } },
            { 8080, new ServiceInfo { Name = "UniFi Controller (Alternative)", Type = ServiceType.AdminInterface, VendorName = "Ubiquiti" } },
            { 8880, new ServiceInfo { Name = "UniFi Video", Type = ServiceType.AdminInterface, VendorName = "Ubiquiti" } },
            { 8843, new ServiceInfo { Name = "UniFi Guest Portal", Type = ServiceType.AdminInterface, VendorName = "Ubiquiti" } },
            
            // TrueNAS/FreeNAS
            { 80, new ServiceInfo { Name = "TrueNAS/FreeNAS Web UI", Type = ServiceType.AdminInterface, VendorName = "iXsystems" } },
            { 443, new ServiceInfo { Name = "TrueNAS/FreeNAS Web UI (HTTPS)", Type = ServiceType.AdminInterface, VendorName = "iXsystems" } },
            
            // OPNsense/pfSense
            { 443, new ServiceInfo { Name = "OPNsense/pfSense Web UI", Type = ServiceType.AdminInterface, VendorName = "OPNsense/pfSense" } },
            { 80, new ServiceInfo { Name = "OPNsense/pfSense Web UI (HTTP)", Type = ServiceType.AdminInterface, VendorName = "OPNsense/pfSense" } },
            
            // Home Assistant
            { 8123, new ServiceInfo { Name = "Home Assistant", Type = ServiceType.IoT, VendorName = "Home Assistant" } },
            
            // Docker
            { 2375, new ServiceInfo { Name = "Docker API", Type = ServiceType.AdminInterface, VendorName = "Docker" } },
            { 2376, new ServiceInfo { Name = "Docker API (TLS)", Type = ServiceType.AdminInterface, VendorName = "Docker" } },
            { 9000, new ServiceInfo { Name = "Portainer", Type = ServiceType.AdminInterface, VendorName = "Portainer" } },
            
            // Common Web UI ports
            { 8080, new ServiceInfo { Name = "Web UI (Alternative HTTP)", Type = ServiceType.WebServer, VendorName = "Various" } },
            { 8443, new ServiceInfo { Name = "Web UI (Alternative HTTPS)", Type = ServiceType.WebServer, VendorName = "Various" } },
            { 8000, new ServiceInfo { Name = "Web UI", Type = ServiceType.WebServer, VendorName = "Various" } },
            { 8008, new ServiceInfo { Name = "Web UI", Type = ServiceType.WebServer, VendorName = "Various" } },
            { 8888, new ServiceInfo { Name = "Web UI", Type = ServiceType.WebServer, VendorName = "Various" } },
            
            // Network hardware
            { 4443, new ServiceInfo { Name = "Router/Access Point Admin", Type = ServiceType.AdminInterface, VendorName = "Various" } },
            { 1900, new ServiceInfo { Name = "UPnP", Type = ServiceType.IoT, VendorName = "Various" } },
            
            // Common services
            { 22, new ServiceInfo { Name = "SSH", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 23, new ServiceInfo { Name = "Telnet", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 21, new ServiceInfo { Name = "FTP", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 20, new ServiceInfo { Name = "FTP Data", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 990, new ServiceInfo { Name = "FTPS", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 989, new ServiceInfo { Name = "FTPS Data", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 445, new ServiceInfo { Name = "SMB/CIFS", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 139, new ServiceInfo { Name = "NetBIOS", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 3389, new ServiceInfo { Name = "Remote Desktop", Type = ServiceType.RemoteAccess, VendorName = "Microsoft" } },
            { 5900, new ServiceInfo { Name = "VNC", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 5901, new ServiceInfo { Name = "VNC (Display 1)", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 5902, new ServiceInfo { Name = "VNC (Display 2)", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            
            // Printing
            { 9100, new ServiceInfo { Name = "Printer - RAW", Type = ServiceType.Print, VendorName = "Various" } },
            { 515, new ServiceInfo { Name = "Printer - LPD", Type = ServiceType.Print, VendorName = "Various" } },
            { 631, new ServiceInfo { Name = "IPP/CUPS", Type = ServiceType.Print, VendorName = "Various" } },
            
            // Database ports
            { 3306, new ServiceInfo { Name = "MySQL", Type = ServiceType.Database, VendorName = "Oracle" } },
            { 5432, new ServiceInfo { Name = "PostgreSQL", Type = ServiceType.Database, VendorName = "PostgreSQL" } },
            { 1433, new ServiceInfo { Name = "MS SQL Server", Type = ServiceType.Database, VendorName = "Microsoft" } },
            { 1434, new ServiceInfo { Name = "MS SQL Browser", Type = ServiceType.Database, VendorName = "Microsoft" } },
            { 27017, new ServiceInfo { Name = "MongoDB", Type = ServiceType.Database, VendorName = "MongoDB" } },
            { 6379, new ServiceInfo { Name = "Redis", Type = ServiceType.Database, VendorName = "Redis" } },
            { 9200, new ServiceInfo { Name = "Elasticsearch", Type = ServiceType.Database, VendorName = "Elastic" } },
            { 9300, new ServiceInfo { Name = "Elasticsearch Transport", Type = ServiceType.Database, VendorName = "Elastic" } },
            
            // Media servers
            { 32400, new ServiceInfo { Name = "Plex Media Server", Type = ServiceType.MediaServer, VendorName = "Plex" } },
            { 32469, new ServiceInfo { Name = "Plex DLNA Server", Type = ServiceType.MediaServer, VendorName = "Plex" } },
            { 8096, new ServiceInfo { Name = "Jellyfin", Type = ServiceType.MediaServer, VendorName = "Jellyfin" } },
            { 8200, new ServiceInfo { Name = "Jellyfin DLNA", Type = ServiceType.MediaServer, VendorName = "Jellyfin" } },
            { 8920, new ServiceInfo { Name = "Emby", Type = ServiceType.MediaServer, VendorName = "Emby" } },
            { 8060, new ServiceInfo { Name = "Roku HTTP", Type = ServiceType.MediaServer, VendorName = "Roku" } },
            { 1900, new ServiceInfo { Name = "DLNA/SSDP", Type = ServiceType.MediaServer, VendorName = "Various" } },
            
            // Email
            { 25, new ServiceInfo { Name = "SMTP", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 465, new ServiceInfo { Name = "SMTP SSL", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 587, new ServiceInfo { Name = "SMTP TLS", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 110, new ServiceInfo { Name = "POP3", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 995, new ServiceInfo { Name = "POP3 SSL", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 143, new ServiceInfo { Name = "IMAP", Type = ServiceType.EmailServer, VendorName = "Various" } },
            { 993, new ServiceInfo { Name = "IMAP SSL", Type = ServiceType.EmailServer, VendorName = "Various" } },
            
            // IoT and Smart Home
            { 1883, new ServiceInfo { Name = "MQTT", Type = ServiceType.IoT, VendorName = "Various" } },
            { 8883, new ServiceInfo { Name = "MQTT SSL", Type = ServiceType.IoT, VendorName = "Various" } },
            { 9001, new ServiceInfo { Name = "MQTT Dashboard", Type = ServiceType.IoT, VendorName = "Various" } },
            { 1880, new ServiceInfo { Name = "Node-RED", Type = ServiceType.IoT, VendorName = "Node-RED" } },
            
            // VPN
            { 1194, new ServiceInfo { Name = "OpenVPN", Type = ServiceType.RemoteAccess, VendorName = "OpenVPN" } },
            { 1723, new ServiceInfo { Name = "PPTP VPN", Type = ServiceType.RemoteAccess, VendorName = "Microsoft" } },
            { 500, new ServiceInfo { Name = "IPsec", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 4500, new ServiceInfo { Name = "IPsec NAT-T", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 51820, new ServiceInfo { Name = "WireGuard", Type = ServiceType.RemoteAccess, VendorName = "WireGuard" } },
            
            // Game Servers
            { 25565, new ServiceInfo { Name = "Minecraft", Type = ServiceType.GameServer, VendorName = "Mojang" } },
            { 27015, new ServiceInfo { Name = "Steam/Source Games", Type = ServiceType.GameServer, VendorName = "Valve" } },
            
            // Voice/Video
            { 3478, new ServiceInfo { Name = "STUN", Type = ServiceType.VOIP, VendorName = "Various" } },
            { 3479, new ServiceInfo { Name = "STUN TLS", Type = ServiceType.VOIP, VendorName = "Various" } },
            { 5060, new ServiceInfo { Name = "SIP", Type = ServiceType.VOIP, VendorName = "Various" } },
            { 5061, new ServiceInfo { Name = "SIP TLS", Type = ServiceType.VOIP, VendorName = "Various" } },
            
            // Misc
            { 53, new ServiceInfo { Name = "DNS", Type = ServiceType.Network, VendorName = "Various" } },
            { 123, new ServiceInfo { Name = "NTP", Type = ServiceType.Network, VendorName = "Various" } },
            { 161, new ServiceInfo { Name = "SNMP", Type = ServiceType.Network, VendorName = "Various" } },
            { 162, new ServiceInfo { Name = "SNMP Trap", Type = ServiceType.Network, VendorName = "Various" } },
            { 389, new ServiceInfo { Name = "LDAP", Type = ServiceType.Directory, VendorName = "Various" } },
            { 636, new ServiceInfo { Name = "LDAPS", Type = ServiceType.Directory, VendorName = "Various" } },
            { 3306, new ServiceInfo { Name = "MySQL", Type = ServiceType.Database, VendorName = "Oracle" } }
        };

        public static async Task EnsureNmapInstalledAsync()
        {
            bool nmapInstalled = false;
            
            try
            {
                // Check if nmap is installed
                var checkProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "which",
                        Arguments = "nmap",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                checkProcess.Start();
                string output = await checkProcess.StandardOutput.ReadToEndAsync();
                await checkProcess.WaitForExitAsync();
                
                nmapInstalled = checkProcess.ExitCode == 0 && !string.IsNullOrWhiteSpace(output);
            }
            catch
            {
                nmapInstalled = false;
            }
            
            if (!nmapInstalled)
            {
                Console.WriteLine("Nmap is not installed. Installing now...");
                
                try
                {
                    // Try to install nmap using apt (for Debian/Ubuntu)
                    var installProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "sudo",
                            Arguments = "apt-get install -y nmap",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    
                    installProcess.Start();
                    string installOutput = await installProcess.StandardOutput.ReadToEndAsync();
                    string errorOutput = await installProcess.StandardError.ReadToEndAsync();
                    await installProcess.WaitForExitAsync();
                    
                    if (installProcess.ExitCode == 0)
                    {
                        Console.WriteLine("Nmap installed successfully.");
                    }
                    else
                    {
                        Console.WriteLine($"Failed to install Nmap: {errorOutput}");
                        Console.WriteLine("Please install Nmap manually and try again.");
                        Environment.Exit(1);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error installing Nmap: {ex.Message}");
                    Console.WriteLine("Please install Nmap manually and try again.");
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.WriteLine("Nmap is already installed.");
            }
        }

        public async Task<List<HostInfo>> ScanNetworkWithNmapAsync(string network, bool includePortScan = false)
        {
            List<HostInfo> hosts = new List<HostInfo>();
            
            // Ensure network format includes /24 if not present
            if (!network.Contains("/"))
            {
                if (network.EndsWith("."))
                {
                    network = $"{network}0/24";
                }
                else if (network.Split('.').Length == 3)
                {
                    network = $"{network}.0/24";
                }
                else if (network.Split('.').Length == 4)
                {
                    network = $"{network}/24";
                }
            }
            
            try
            {
                Console.WriteLine("Starting Nmap scan (this may take a while)...");
                
                // Use nmap to scan the network with hostname resolution
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        // -sn: Ping scan - disable port scan (for initial discovery)
                        // --dns-servers: Use Google's DNS servers for better name resolution
                        // -oG -: Output in greppable format to stdout
                        Arguments = $"-sn --dns-servers 8.8.8.8,8.8.4.4 -oG - {network}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0)
                {
                    // Parse the nmap output
                    string[] lines = output.Split('\n');
                    
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("Host:"))
                        {
                            // Extract IP address
                            Match ipMatch = Regex.Match(line, @"Host: (\d+\.\d+\.\d+\.\d+)");
                            if (ipMatch.Success)
                            {
                                string ip = ipMatch.Groups[1].Value;
                                
                                // Extract hostname if available but explicitly filter out nmap URLs
                                string hostname = "unknown";
                                string fqdn = "";
                                
                                Match hostnameMatch = Regex.Match(line, @"Host: .+ \((.*?)\)");
                                if (hostnameMatch.Success && !string.IsNullOrEmpty(hostnameMatch.Groups[1].Value))
                                {
                                    string potential = hostnameMatch.Groups[1].Value;
                                    
                                    // Explicitly check for nmap URLs
                                    if (potential.Contains("nmap.org") || 
                                        potential.StartsWith("http://") || 
                                        potential.StartsWith("https://"))
                                    {
                                        // Skip URLs, leave hostname as unknown
                                        Console.WriteLine($"Filtered out URL from hostname for {ip}: {potential}");
                                    }
                                    else
                                    {
                                        fqdn = potential;
                                        hostname = fqdn.Split('.')[0];
                                    }
                                }
                                
                                // If hostname still unknown, try additional methods
                                if (hostname == "unknown")
                                {
                                    // Skip additional resolution attempts for known URL cases
                                    if (line.Contains("nmap.org"))
                                    {
                                        Console.WriteLine($"Skipping hostname resolution for {ip} with nmap.org reference");
                                    }
                                    else
                                    {
                                        // Try more precise nmap scan for this specific host
                                        var nmapResult = await TryNmapHostnameResolutionAsync(ip);
                                        if (!string.IsNullOrEmpty(nmapResult.hostname))
                                        {
                                            hostname = nmapResult.hostname;
                                            fqdn = nmapResult.fqdn;
                                        }
                                        
                                        // If still unknown, try DNS resolution
                                        if (hostname == "unknown")
                                        {
                                            var dnsResult = await TryDnsResolutionAsync(ip);
                                            if (!string.IsNullOrEmpty(dnsResult.hostname))
                                            {
                                                hostname = dnsResult.hostname;
                                                fqdn = dnsResult.fqdn;
                                            }
                                        }
                                        
                                        // As a last resort, try NetBIOS (nmblookup)
                                        if (hostname == "unknown")
                                        {
                                            string netbiosName = await TryNetBiosResolutionAsync(ip);
                                            if (!string.IsNullOrEmpty(netbiosName))
                                            {
                                                hostname = netbiosName;
                                            }
                                        }
                                        
                                        // If still unknown, try mDNS (Multicast DNS) for discovery of local devices
                                        if (hostname == "unknown")
                                        {
                                            string mdnsName = await TryMdnsResolutionAsync(ip);
                                            if (!string.IsNullOrEmpty(mdnsName))
                                            {
                                                hostname = mdnsName;
                                                if (string.IsNullOrEmpty(fqdn) && mdnsName.Contains(".local"))
                                                {
                                                    fqdn = mdnsName;
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                var hostInfo = new HostInfo
                                {
                                    IpAddress = ip,
                                    Hostname = hostname,
                                    Fqdn = fqdn,
                                    OpenPorts = new List<PortInfo>(),
                                    DetectedServices = new List<DetectedService>()
                                };
                                
                                hosts.Add(hostInfo);
                            }
                        }
                    }
                    
                    // If port scanning is requested, scan each host for open ports
                    if (includePortScan && hosts.Count > 0)
                    {
                        Console.WriteLine($"Found {hosts.Count} hosts. Starting port scan for common services...");
                        await ScanHostsForCommonPorts(hosts);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during Nmap scan: {ex.Message}");
                
                // Fallback to ping scan if nmap fails
                Console.WriteLine("Falling back to basic ping scan...");
                hosts = await FallbackPingScanAsync(network.Replace("/24", ""));
                
                // If port scanning is requested, scan each host for open ports
                if (includePortScan && hosts.Count > 0)
                {
                    Console.WriteLine($"Found {hosts.Count} hosts. Starting port scan for common services...");
                    await ScanHostsForCommonPorts(hosts);
                }
            }
            
            return hosts;
        }
        
        private async Task ScanHostsForCommonPorts(List<HostInfo> hosts)
        {
            foreach (var host in hosts)
            {
                await ScanHostPortsAsync(host);
                IdentifyServices(host);
            }
        }
        
        private async Task ScanHostPortsAsync(HostInfo host)
        {
            try
            {
                Console.WriteLine($"Scanning ports on {host.IpAddress}...");
                
                // First try with non-privileged TCP connect scan
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        // -sT: TCP connect scan (does not require root)
                        // -sV: Service/version detection
                        // --version-intensity 2: Quicker service detection
                        // -F: Fast mode - scan fewer ports
                        // --open: Only show open ports
                        // --host-timeout 30s: Limit scan time per host
                        // -Pn: Treat all hosts as online (skip ping check)
                        Arguments = $"-sT -sV -Pn --version-intensity 2 -F --open --host-timeout 30s {host.IpAddress}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0)
                {
                    // Try to extract hostname from nmap output as it might have additional info
                    Match hostnameMatch = Regex.Match(output, @"Nmap scan report for (.+?) \(");
                    if (hostnameMatch.Success && !string.IsNullOrEmpty(hostnameMatch.Groups[1].Value) &&
                        host.Hostname == "unknown")
                    {
                        string nmapHostname = hostnameMatch.Groups[1].Value.Trim();
                        
                        // Filter out URLs that shouldn't be treated as hostnames
                        if (!nmapHostname.StartsWith("http://") && !nmapHostname.StartsWith("https://"))
                        {
                            if (nmapHostname.Contains("."))
                            {
                                host.Fqdn = nmapHostname;
                                host.Hostname = nmapHostname.Split('.')[0];
                            }
                            else
                            {
                                host.Hostname = nmapHostname;
                            }
                        }
                    }
                    
                    // Parse port scan results
                    ParsePortScanResults(host, output);
                    
                    // Try additional scans for OS detection if we have sudo access
                    await TryOsDetectionAsync(host);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning ports on {host.IpAddress}: {ex.Message}");
            }
        }
        
        private void ParsePortScanResults(HostInfo host, string nmapOutput)
        {
            // Extract port and service information
            var portRegex = new Regex(@"(\d+)/tcp\s+open\s+(\S+)\s*(.*)");
            
            string[] lines = nmapOutput.Split('\n');
            foreach (var line in lines)
            {
                Match match = portRegex.Match(line);
                if (match.Success)
                {
                    int port = int.Parse(match.Groups[1].Value);
                    string service = match.Groups[2].Value;
                    string version = match.Groups[3].Value.Trim();
                    
                    host.OpenPorts.Add(new PortInfo
                    {
                        Port = port,
                        ServiceName = service,
                        Version = version
                    });
                    
                    // Add debug output
                    Console.WriteLine($"Found port {port} ({service}) on {host.IpAddress}");
                }
            }
            
            // Debug output
            Console.WriteLine($"Total ports found for {host.IpAddress}: {host.OpenPorts.Count}");
        }
        
        private void IdentifyServices(HostInfo host)
        {
            // Look for specific services in open ports
            foreach (var portInfo in host.OpenPorts)
            {
                // Check if it's a known service
                if (KnownServices.TryGetValue(portInfo.Port, out ServiceInfo? serviceInfo) && serviceInfo != null)
                {
                    var detectedService = new DetectedService
                    {
                        ServiceName = serviceInfo.Name ?? "Unknown Service",
                        ServiceType = serviceInfo.Type,
                        VendorName = serviceInfo.VendorName ?? "Unknown",
                        Port = portInfo.Port,
                        AccessUrl = GenerateAccessUrl(host.IpAddress, portInfo.Port, serviceInfo.Name ?? "Unknown Service")
                    };
                    
                    host.DetectedServices.Add(detectedService);
                }
                
                // Special case for HTTP with service detection to identify web interface types
                if (portInfo.ServiceName.Contains("http") || portInfo.Port == 80 || portInfo.Port == 443 || 
                    portInfo.Port == 8080 || portInfo.Port == 8443 || portInfo.Port == 5000 || portInfo.Port == 5001)
                {
                    IdentifyWebInterface(host, portInfo);
                }
            }
        }
        
        private void IdentifyWebInterface(HostInfo host, PortInfo portInfo)
        {
            // Based on provided service version info, identify web interfaces
            string serviceInfo = portInfo.ServiceName + " " + portInfo.Version;
            serviceInfo = serviceInfo.ToLower();
            
            // Detect various admin interfaces based on service info
            if (serviceInfo.Contains("synology") || 
                serviceInfo.Contains("dsm") || 
                serviceInfo.Contains("diskstation"))
            {
                AddServiceIfNotExists(host, "Synology DSM", ServiceType.AdminInterface, "Synology", portInfo.Port);
            }
            else if (serviceInfo.Contains("pihole") || 
                    serviceInfo.Contains("pi-hole") || 
                    serviceInfo.Contains("pi hole"))
            {
                AddServiceIfNotExists(host, "Pi-hole Admin", ServiceType.AdminInterface, "Pi-hole", portInfo.Port);
            }
            else if ((serviceInfo.Contains("nginx") && serviceInfo.Contains("proxy")) || 
                    serviceInfo.Contains("npmplus") || 
                    (portInfo.Port == 81 && serviceInfo.Contains("nginx")))
            {
                AddServiceIfNotExists(host, "NPMPlus/Nginx Proxy Manager", ServiceType.AdminInterface, "NPMPlus", portInfo.Port);
            }
            else if (serviceInfo.Contains("qnap") || 
                    serviceInfo.Contains("qts") || 
                    serviceInfo.Contains("nas"))
            {
                AddServiceIfNotExists(host, "QNAP NAS", ServiceType.AdminInterface, "QNAP", portInfo.Port);
            }
            else if (serviceInfo.Contains("unifi") || 
                    (portInfo.Port == 8443 && serviceInfo.Contains("ubiquiti")))
            {
                AddServiceIfNotExists(host, "UniFi Controller", ServiceType.AdminInterface, "Ubiquiti", portInfo.Port);
            }
            else if (serviceInfo.Contains("truenas") || 
                    serviceInfo.Contains("freenas") || 
                    (serviceInfo.Contains("nas") && serviceInfo.Contains("ixsystems")))
            {
                AddServiceIfNotExists(host, "TrueNAS/FreeNAS", ServiceType.AdminInterface, "iXsystems", portInfo.Port);
            }
            else if (serviceInfo.Contains("opnsense") || 
                    serviceInfo.Contains("pfsense") || 
                    (serviceInfo.Contains("firewall") && (serviceInfo.Contains("bsd") || serviceInfo.Contains("pf"))))
            {
                string vendor = serviceInfo.Contains("opnsense") ? "OPNsense" : "pfSense";
                AddServiceIfNotExists(host, vendor + " Firewall", ServiceType.AdminInterface, vendor, portInfo.Port);
            }
            else if (serviceInfo.Contains("home assistant") || 
                    serviceInfo.Contains("homeassistant") || 
                    portInfo.Port == 8123)
            {
                AddServiceIfNotExists(host, "Home Assistant", ServiceType.IoT, "Home Assistant", portInfo.Port);
            }
            else if (serviceInfo.Contains("docker") || 
                    serviceInfo.Contains("portainer") || 
                    portInfo.Port == 9000)
            {
                if (serviceInfo.Contains("portainer"))
                {
                    AddServiceIfNotExists(host, "Portainer", ServiceType.AdminInterface, "Portainer", portInfo.Port);
                }
                else
                {
                    AddServiceIfNotExists(host, "Docker API", ServiceType.AdminInterface, "Docker", portInfo.Port);
                }
            }
            else if (serviceInfo.Contains("plex") || portInfo.Port == 32400)
            {
                AddServiceIfNotExists(host, "Plex Media Server", ServiceType.MediaServer, "Plex", portInfo.Port);
            }
            else if (serviceInfo.Contains("jellyfin") || portInfo.Port == 8096)
            {
                AddServiceIfNotExists(host, "Jellyfin", ServiceType.MediaServer, "Jellyfin", portInfo.Port);
            }
            else if (serviceInfo.Contains("emby") || portInfo.Port == 8920)
            {
                AddServiceIfNotExists(host, "Emby", ServiceType.MediaServer, "Emby", portInfo.Port);
            }
            else if (serviceInfo.Contains("wordpress") || 
                    serviceInfo.Contains("wp-admin") || 
                    serviceInfo.Contains("wp-login"))
            {
                AddServiceIfNotExists(host, "WordPress", ServiceType.CMS, "WordPress", portInfo.Port);
            }
            else if (serviceInfo.Contains("joomla"))
            {
                AddServiceIfNotExists(host, "Joomla", ServiceType.CMS, "Joomla", portInfo.Port);
            }
            else if (serviceInfo.Contains("drupal"))
            {
                AddServiceIfNotExists(host, "Drupal", ServiceType.CMS, "Drupal", portInfo.Port);
            }
            else if (serviceInfo.Contains("grafana"))
            {
                AddServiceIfNotExists(host, "Grafana", ServiceType.Monitoring, "Grafana", portInfo.Port);
            }
            else if (serviceInfo.Contains("prometheus"))
            {
                AddServiceIfNotExists(host, "Prometheus", ServiceType.Monitoring, "Prometheus", portInfo.Port);
            }
            else if (serviceInfo.Contains("jenkins"))
            {
                AddServiceIfNotExists(host, "Jenkins", ServiceType.DevOps, "Jenkins", portInfo.Port);
            }
            else if (serviceInfo.Contains("gitlab"))
            {
                AddServiceIfNotExists(host, "GitLab", ServiceType.DevOps, "GitLab", portInfo.Port);
            }
            else if (serviceInfo.Contains("hikvision") || 
                    serviceInfo.Contains("dahua") || 
                    serviceInfo.Contains("axis") || 
                    serviceInfo.Contains("rtsp") || 
                    serviceInfo.Contains("camera") || 
                    portInfo.Port == 554)
            {
                string vendor = "Unknown";
                if (serviceInfo.Contains("hikvision")) vendor = "Hikvision";
                else if (serviceInfo.Contains("dahua")) vendor = "Dahua";
                else if (serviceInfo.Contains("axis")) vendor = "Axis";
                
                AddServiceIfNotExists(host, "IP Camera", ServiceType.SecurityCamera, vendor, portInfo.Port);
            }
            else if (portInfo.Port == 80 || portInfo.Port == 443 || 
                    portInfo.Port == 8080 || portInfo.Port == 8443 || 
                    portInfo.Port == 8000 || portInfo.Port == 8888)
            {
                // Generic web interface
                string protocol = (portInfo.Port == 443 || portInfo.Port == 8443) ? "HTTPS" : "HTTP";
                AddServiceIfNotExists(host, $"Web Interface ({protocol})", ServiceType.WebServer, "Unknown", portInfo.Port);
            }
        }
        
        private void AddServiceIfNotExists(HostInfo host, string serviceName, ServiceType serviceType, string vendor, int port)
        {
            if (!host.DetectedServices.Any(s => s.ServiceName == serviceName && s.Port == port))
            {
                host.DetectedServices.Add(new DetectedService
                {
                    ServiceName = serviceName,
                    ServiceType = serviceType,
                    VendorName = vendor,
                    Port = port,
                    AccessUrl = GenerateAccessUrl(host.IpAddress, port, serviceName)
                });
            }
        }
        
        private string GenerateAccessUrl(string ipAddress, int port, string serviceName)
        {
            bool isHttps = port == 443 || port == 8443 || port == 5001 || 
                          serviceName.Contains("HTTPS") || serviceName.Contains("https");
            
            string protocol = isHttps ? "https" : "http";
            
            // Standard HTTP/HTTPS ports don't need to be included in URL
            if ((port == 80 && protocol == "http") || (port == 443 && protocol == "https"))
            {
                return $"{protocol}://{ipAddress}/";
            }
            
            return $"{protocol}://{ipAddress}:{port}/";
        }

        private async Task<(string hostname, string fqdn)> TryNmapHostnameResolutionAsync(string ip)
        {
            try
            {
                var nmapProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        Arguments = $"-sL {ip}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                nmapProcess.Start();
                string nmapOutput = await nmapProcess.StandardOutput.ReadToEndAsync();
                await nmapProcess.WaitForExitAsync();
                
                Match nmapMatch = Regex.Match(nmapOutput, @"\(\s*([^\(\)]+)\s*\)");
                if (nmapMatch.Success && !string.IsNullOrEmpty(nmapMatch.Groups[1].Value))
                {
                    string fqdn = nmapMatch.Groups[1].Value.Trim();
                    string hostname = fqdn.Split('.')[0];
                    return (hostname, fqdn);
                }
            }
            catch
            {
                // Ignore errors in this attempt
            }
            
            return ("", "");
        }
        
        private async Task<(string hostname, string fqdn)> TryDnsResolutionAsync(string ip)
        {
            try
            {
                // Try nslookup with Google DNS first
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nslookup",
                        Arguments = $"{ip} 8.8.8.8",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    // Improved regex pattern to handle a wider variety of nslookup outputs
                    Match nameMatch = Regex.Match(output, @"(?:name\s*=\s*|\s*=\s*|PTR record\s*)([a-zA-Z0-9][\w\.-]+\.[a-zA-Z0-9][\w\.-]+(?:\.[a-zA-Z0-9][\w\.-]+)*)");
                    if (nameMatch.Success && !string.IsNullOrEmpty(nameMatch.Groups[1].Value))
                    {
                        string fqdn = nameMatch.Groups[1].Value.Trim();
                        string hostname = fqdn.Split('.')[0];
                        return (hostname, fqdn);
                    }
                }
                
                // Try with local DNS as fallback
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nslookup",
                        Arguments = ip,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    // Try with improved regex pattern
                    Match nameMatch = Regex.Match(output, @"(?:name\s*=\s*|\s*=\s*|PTR record\s*)([a-zA-Z0-9][\w\.-]+\.[a-zA-Z0-9][\w\.-]+(?:\.[a-zA-Z0-9][\w\.-]+)*)");
                    if (nameMatch.Success && !string.IsNullOrEmpty(nameMatch.Groups[1].Value))
                    {
                        string fqdn = nameMatch.Groups[1].Value.Trim();
                        string hostname = fqdn.Split('.')[0];
                        return (hostname, fqdn);
                    }
                }
                
                try
                {
                    // Also try the built-in .NET DNS resolution
                    IPHostEntry hostEntry = await Dns.GetHostEntryAsync(ip);
                    if (!string.IsNullOrEmpty(hostEntry.HostName))
                    {
                        string fqdn = hostEntry.HostName;
                        string hostname = fqdn.Split('.')[0];
                        return (hostname, fqdn);
                    }
                }
                catch
                {
                    // .NET DNS resolution failed, continue with other methods
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during DNS resolution: {ex.Message}");
            }
            
            return (string.Empty, string.Empty);
        }
        
        private async Task<string> TryNetBiosResolutionAsync(string ip)
        {
            try
            {
                // Check if nmblookup is installed
                var checkProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "which",
                        Arguments = "nmblookup",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                checkProcess.Start();
                await checkProcess.WaitForExitAsync();
                
                if (checkProcess.ExitCode == 0)
                {
                    var netbiosProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "nmblookup",
                            Arguments = $"-A {ip}",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    
                    netbiosProcess.Start();
                    string netbiosOutput = await netbiosProcess.StandardOutput.ReadToEndAsync();
                    await netbiosProcess.WaitForExitAsync();
                    
                    // Look for NetBIOS name in the output (typically in the format <name><00>)
                    Match netbiosMatch = Regex.Match(netbiosOutput, @"<([^>]+)><00>");
                    if (netbiosMatch.Success && !string.IsNullOrEmpty(netbiosMatch.Groups[1].Value))
                    {
                        return netbiosMatch.Groups[1].Value.Trim();
                    }
                }
            }
            catch
            {
                // NetBIOS resolution failed, keep as unknown
            }
            
            return "";
        }

        private async Task<string> TryMdnsResolutionAsync(string ip)
        {
            try
            {
                // Use avahi-resolve or similar tools for mDNS resolution
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "avahi-resolve",
                        Arguments = $"-a {ip}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    // Parse avahi output: 192.168.1.1	device.local
                    string[] parts = output.Trim().Split('\t');
                    if (parts.Length >= 2)
                    {
                        return parts[1].Trim();
                    }
                }
                
                // If avahi-resolve fails, try using dns-sd
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dns-sd",
                        Arguments = $"-G v4 {ip}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    // Try to extract hostname from dns-sd output
                    Match match = Regex.Match(output, @"can be reached at ([\w.-]+)\.local");
                    if (match.Success)
                    {
                        return match.Groups[1].Value + ".local";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during mDNS resolution: {ex.Message}");
            }
            
            return string.Empty;
        }

        private async Task TryOsDetectionAsync(HostInfo host)
        {
            try
            {
                // First try to see if we can extract OS info from the version detection
                if (string.IsNullOrEmpty(host.OsInfo) && host.OpenPorts.Count > 0)
                {
                    foreach (var port in host.OpenPorts)
                    {
                        // Service version might contain OS info
                        string versionInfo = port.Version.ToLower();
                        
                        if (versionInfo.Contains("linux") || versionInfo.Contains("ubuntu") || versionInfo.Contains("debian") || 
                            versionInfo.Contains("centos") || versionInfo.Contains("fedora") || versionInfo.Contains("redhat"))
                        {
                            host.OsInfo = "Linux";
                            break;
                        }
                        else if (versionInfo.Contains("windows") || versionInfo.Contains("microsoft") || versionInfo.Contains("win32"))
                        {
                            host.OsInfo = "Windows";
                            break;
                        }
                        else if (versionInfo.Contains("apple") || versionInfo.Contains("mac") || versionInfo.Contains("osx") || 
                                versionInfo.Contains("darwin"))
                        {
                            host.OsInfo = "Mac OS";
                            break;
                        }
                    }
                }

                // Use nmap for OS detection (requires root/admin privileges)
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        // -O: OS detection
                        // --osscan-limit: Limit OS detection to promising targets
                        // -T4: Faster timing template
                        // --max-os-tries 1: Limit OS detection attempts
                        Arguments = $"-O --osscan-limit -T4 --max-os-tries 1 {host.IpAddress}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0)
                {
                    // First check if we got a permissions error
                    if (output.Contains("You requested a scan type which requires root privileges"))
                    {
                        Console.WriteLine("OS detection requires root privileges. Skipping.");
                        // Try alternative method if no OS info yet
                        if (string.IsNullOrEmpty(host.OsInfo))
                        {
                            await TryOsDetectionFromServiceScan(host);
                        }
                        return;
                    }
                    
                    // Extract OS information
                    Match osMatch = Regex.Match(output, @"OS details: (.+)");
                    if (osMatch.Success && !string.IsNullOrEmpty(osMatch.Groups[1].Value))
                    {
                        host.OsInfo = osMatch.Groups[1].Value.Trim();
                        
                        // Try to extract device type
                        if (host.OsInfo.Contains("Linux") && (host.OsInfo.Contains("router") || host.OsInfo.Contains("WAP")))
                        {
                            AddServiceIfNotExists(host, "Router/Access Point", ServiceType.Network, "Unknown", 0);
                        }
                        else if (host.OsInfo.Contains("printer"))
                        {
                            AddServiceIfNotExists(host, "Printer", ServiceType.Print, "Unknown", 0);
                        }
                        else if (host.OsInfo.Contains("NAS"))
                        {
                            AddServiceIfNotExists(host, "Network Storage (NAS)", ServiceType.FileSharing, "Unknown", 0);
                        }
                    }
                    else
                    {
                        // If no OS found via nmap, try alternative method
                        await TryOsDetectionFromServiceScan(host);
                    }
                }
                else
                {
                    // If nmap OS detection failed, try alternative method
                    await TryOsDetectionFromServiceScan(host);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during OS detection for {host.IpAddress}: {ex.Message}");
                
                // If error occurs, try alternative method
                await TryOsDetectionFromServiceScan(host);
            }
        }
        
        private async Task TryOsDetectionFromServiceScan(HostInfo host)
        {
            if (!string.IsNullOrEmpty(host.OsInfo))
                return;
                
            try
            {
                // Use a non-privileged scan with more service detection
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        // --script banner: Try to get service banners which might reveal OS
                        Arguments = $"-sV --version-all --script banner {host.IpAddress}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0)
                {
                    // Try to determine OS from service banners
                    if (output.Contains("Windows") || output.Contains("Microsoft"))
                    {
                        host.OsInfo = "Windows";
                    }
                    else if (output.Contains("Linux") || output.Contains("Ubuntu") || output.Contains("Debian"))
                    {
                        host.OsInfo = "Linux";
                    }
                    else if (output.Contains("Apple") || output.Contains("Mac") || output.Contains("Darwin"))
                    {
                        host.OsInfo = "Mac OS";
                    }
                    
                    // Try to determine device type from port pattern
                    if (string.IsNullOrEmpty(host.OsInfo))
                    {
                        // Common patterns for device types
                        if (host.OpenPorts.Any(p => p.Port == 80) && 
                            host.OpenPorts.Any(p => p.Port == 53) && 
                            host.OpenPorts.Any(p => p.Port == 443))
                        {
                            host.OsInfo = "Router/Gateway";
                            AddServiceIfNotExists(host, "Router/Access Point", ServiceType.Network, "Unknown", 0);
                        }
                        else if (host.OpenPorts.Any(p => p.Port == 631))
                        {
                            host.OsInfo = "Printer/Print Server";
                            AddServiceIfNotExists(host, "Printer", ServiceType.Print, "Unknown", 0);
                        }
                        else if (host.OpenPorts.Any(p => p.Port == 445) && 
                                host.OpenPorts.Any(p => p.Port == 139))
                        {
                            host.OsInfo = "File Server/NAS";
                            AddServiceIfNotExists(host, "Network Storage (NAS)", ServiceType.FileSharing, "Unknown", 0);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during alternative OS detection for {host.IpAddress}: {ex.Message}");
            }
        }

        private async Task<List<HostInfo>> FallbackPingScanAsync(string subnet)
        {
            List<HostInfo> hosts = new List<HostInfo>();
            var tasks = new List<Task<HostInfo?>>();

            // Trim /24 if present
            subnet = subnet.Replace("/24", "");
            
            // Ensure subnet ends with dot
            if (!subnet.EndsWith("."))
            {
                subnet += ".";
            }

            for (int i = 1; i < 255; i++)
            {
                string ip = $"{subnet}{i}";
                tasks.Add(ScanHostAsync(ip));
            }

            var results = await Task.WhenAll(tasks);
            
            foreach (var host in results)
            {
                if (host != null)
                {
                    hosts.Add(host);
                }
            }
            
            return hosts;
        }

        private async Task<HostInfo?> ScanHostAsync(string ipAddress)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(ipAddress, 1000);
                    if (reply.Status == IPStatus.Success)
                    {
                        string hostname = "unknown";
                        string fqdn = "";
                        try
                        {
                            IPHostEntry hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                            fqdn = hostEntry.HostName;
                            hostname = fqdn.Split('.')[0];
                        }
                        catch
                        {
                            // Unable to resolve hostname
                        }

                        return new HostInfo
                        {
                            IpAddress = ipAddress,
                            Hostname = hostname,
                            Fqdn = fqdn
                        };
                    }
                }
            }
            catch
            {
                // Ignore failed pings
            }

            return null;
        }

        public static void SaveToCsv(List<HostInfo> hosts, string filePath)
        {
            StringBuilder csv = new StringBuilder();
            
            // Add header
            csv.AppendLine("IP Address,Hostname,FQDN,Open Ports,Detected Services,Service Types,Vendor Names,Access URLs");
            
            // Add each host
            foreach (var host in hosts)
            {
                // Escape commas in values
                string hostname = host.Hostname.Contains(",") ? $"\"{host.Hostname}\"" : host.Hostname;
                string fqdn = host.Fqdn.Contains(",") ? $"\"{host.Fqdn}\"" : host.Fqdn;
                
                // Combine ports, services, types and vendors with semicolons
                string ports = string.Join("; ", host.OpenPorts.Select(p => $"{p.Port}/{p.ServiceName}"));
                string services = string.Join("; ", host.DetectedServices.Select(s => s.ServiceName));
                string serviceTypes = string.Join("; ", host.DetectedServices.Select(s => s.ServiceType.ToString()));
                string vendors = string.Join("; ", host.DetectedServices.Select(s => s.VendorName));
                string accessUrls = string.Join("; ", host.DetectedServices.Select(s => s.AccessUrl));
                
                // Quote fields with semicolons to avoid CSV parsing issues
                ports = ports.Contains(";") ? $"\"{ports}\"" : ports;
                services = services.Contains(";") ? $"\"{services}\"" : services;
                serviceTypes = serviceTypes.Contains(";") ? $"\"{serviceTypes}\"" : serviceTypes;
                vendors = vendors.Contains(";") ? $"\"{vendors}\"" : vendors;
                accessUrls = accessUrls.Contains(";") ? $"\"{accessUrls}\"" : accessUrls;
                
                csv.AppendLine($"{host.IpAddress},{hostname},{fqdn},{ports},{services},{serviceTypes},{vendors},{accessUrls}");
            }
            
            // Save to file
            File.WriteAllText(filePath, csv.ToString());
        }
    }

    public class ServiceInfo
    {
        public string Name { get; set; } = "";
        public ServiceType Type { get; set; }
        public string VendorName { get; set; } = "";
    }

    public class HostInfo
    {
        public string IpAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string Fqdn { get; set; } = "";
        public List<PortInfo> OpenPorts { get; set; } = new List<PortInfo>();
        public List<DetectedService> DetectedServices { get; set; } = new List<DetectedService>();
        public string OsInfo { get; set; } = "";
    }
    
    public class PortInfo
    {
        public int Port { get; set; }
        public string ServiceName { get; set; } = "";
        public string Version { get; set; } = "";
    }
    
    public class DetectedService
    {
        public string ServiceName { get; set; } = "";
        public ServiceType ServiceType { get; set; }
        public string VendorName { get; set; } = "";
        public int Port { get; set; }
        public string AccessUrl { get; set; } = "";
    }
    
    public enum ServiceType
    {
        Unknown,
        AdminInterface,
        WebServer,
        FileSharing,
        Database,
        RemoteAccess,
        MediaServer,
        Print,
        VOIP,
        EmailServer,
        GameServer,
        IoT,
        Network,
        Directory,
        SecurityCamera,
        Monitoring,
        DevOps,
        CMS
    }
} 