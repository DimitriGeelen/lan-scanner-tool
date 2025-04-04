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
                    
                    return Results.Json(hosts);
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

            Console.WriteLine("Web interface started. Navigate to http://localhost:5000 to access the tool.");
            await app.RunAsync();
        }

        static async Task RunConsoleMode(string[] args)
        {
            Console.WriteLine("LAN Scanner Tool");
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
            
            // Pi-hole
            { 80, new ServiceInfo { Name = "HTTP (Possible Pi-hole/Web UI)", Type = ServiceType.AdminInterface, VendorName = "Various" } },
            { 443, new ServiceInfo { Name = "HTTPS (Possible Pi-hole/Web UI)", Type = ServiceType.AdminInterface, VendorName = "Various" } },
            
            // NPMPlus
            { 81, new ServiceInfo { Name = "NPMPlus/Nginx Proxy Manager", Type = ServiceType.AdminInterface, VendorName = "NPMPlus" } },
            
            // Common Web UI ports
            { 8080, new ServiceInfo { Name = "Web UI (Alternative HTTP)", Type = ServiceType.WebServer, VendorName = "Various" } },
            { 8443, new ServiceInfo { Name = "Web UI (Alternative HTTPS)", Type = ServiceType.WebServer, VendorName = "Various" } },
            
            // Common services
            { 22, new ServiceInfo { Name = "SSH", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 23, new ServiceInfo { Name = "Telnet", Type = ServiceType.RemoteAccess, VendorName = "Various" } },
            { 21, new ServiceInfo { Name = "FTP", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 445, new ServiceInfo { Name = "SMB/CIFS", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 139, new ServiceInfo { Name = "NetBIOS", Type = ServiceType.FileSharing, VendorName = "Various" } },
            { 3389, new ServiceInfo { Name = "Remote Desktop", Type = ServiceType.RemoteAccess, VendorName = "Microsoft" } },
            
            // Database ports
            { 3306, new ServiceInfo { Name = "MySQL", Type = ServiceType.Database, VendorName = "Oracle" } },
            { 5432, new ServiceInfo { Name = "PostgreSQL", Type = ServiceType.Database, VendorName = "PostgreSQL" } },
            { 1433, new ServiceInfo { Name = "MS SQL Server", Type = ServiceType.Database, VendorName = "Microsoft" } },
            { 27017, new ServiceInfo { Name = "MongoDB", Type = ServiceType.Database, VendorName = "MongoDB" } },
            
            // Media servers
            { 32400, new ServiceInfo { Name = "Plex Media Server", Type = ServiceType.MediaServer, VendorName = "Plex" } },
            { 8096, new ServiceInfo { Name = "Jellyfin", Type = ServiceType.MediaServer, VendorName = "Jellyfin" } },
            { 8920, new ServiceInfo { Name = "Emby", Type = ServiceType.MediaServer, VendorName = "Emby" } }
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
                        // -oG -: Output in greppable format to stdout
                        Arguments = $"-sn -oG - {network}",
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
                                
                                // Extract hostname if available
                                string hostname = "unknown";
                                string fqdn = "";
                                
                                Match hostnameMatch = Regex.Match(line, @"Host: .+ \((.*?)\)");
                                if (hostnameMatch.Success && !string.IsNullOrEmpty(hostnameMatch.Groups[1].Value))
                                {
                                    fqdn = hostnameMatch.Groups[1].Value;
                                    hostname = fqdn.Split('.')[0];
                                }
                                
                                // If hostname still unknown, try additional methods
                                if (hostname == "unknown")
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
                
                // Use nmap to scan common ports with service detection
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nmap",
                        // -sS: SYN scan
                        // -sV: Service/version detection
                        // --version-intensity 2: Quicker service detection
                        // -F: Fast mode - scan fewer ports
                        // --open: Only show open ports
                        Arguments = $"-sS -sV --version-intensity 2 -F --open {host.IpAddress}",
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
                    // Parse port scan results
                    ParsePortScanResults(host, output);
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
                }
            }
        }
        
        private void IdentifyServices(HostInfo host)
        {
            // Look for specific services in open ports
            foreach (var portInfo in host.OpenPorts)
            {
                // Check if it's a known service
                if (KnownServices.TryGetValue(portInfo.Port, out ServiceInfo serviceInfo))
                {
                    var detectedService = new DetectedService
                    {
                        ServiceName = serviceInfo.Name,
                        ServiceType = serviceInfo.Type,
                        VendorName = serviceInfo.VendorName,
                        Port = portInfo.Port,
                        AccessUrl = GenerateAccessUrl(host.IpAddress, portInfo.Port, serviceInfo.Name)
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
            if (serviceInfo.Contains("synology") || serviceInfo.Contains("dsm"))
            {
                AddServiceIfNotExists(host, "Synology DSM", ServiceType.AdminInterface, "Synology", portInfo.Port);
            }
            else if (serviceInfo.Contains("pihole") || serviceInfo.Contains("pi-hole"))
            {
                AddServiceIfNotExists(host, "Pi-hole Admin", ServiceType.AdminInterface, "Pi-hole", portInfo.Port);
            }
            else if (serviceInfo.Contains("nginx") && serviceInfo.Contains("proxy"))
            {
                AddServiceIfNotExists(host, "NPMPlus/Nginx Proxy Manager", ServiceType.AdminInterface, "NPMPlus", portInfo.Port);
            }
            else if (serviceInfo.Contains("plex"))
            {
                AddServiceIfNotExists(host, "Plex Media Server", ServiceType.MediaServer, "Plex", portInfo.Port);
            }
            else if (serviceInfo.Contains("jellyfin"))
            {
                AddServiceIfNotExists(host, "Jellyfin", ServiceType.MediaServer, "Jellyfin", portInfo.Port);
            }
            else if (serviceInfo.Contains("emby"))
            {
                AddServiceIfNotExists(host, "Emby", ServiceType.MediaServer, "Emby", portInfo.Port);
            }
            else if (portInfo.Port == 80 || portInfo.Port == 443 || portInfo.Port == 8080 || portInfo.Port == 8443)
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
                var dnsProcess = new Process
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
                
                dnsProcess.Start();
                string dnsOutput = await dnsProcess.StandardOutput.ReadToEndAsync();
                await dnsProcess.WaitForExitAsync();
                
                // Look for "name = example.domain.com"
                Match fqdnMatch = Regex.Match(dnsOutput, @"name\s*=\s*([^\s]+)");
                if (fqdnMatch.Success && !string.IsNullOrEmpty(fqdnMatch.Groups[1].Value))
                {
                    string fqdn = fqdnMatch.Groups[1].Value;
                    if (fqdn.EndsWith("."))
                    {
                        fqdn = fqdn.Substring(0, fqdn.Length - 1);
                    }
                    string hostname = fqdn.Split('.')[0];
                    return (hostname, fqdn);
                }
            }
            catch
            {
                // DNS resolution failed, keep as unknown
            }
            
            return ("", "");
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
        IoT
    }
} 