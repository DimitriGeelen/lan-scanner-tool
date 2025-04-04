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
                    
                    if (string.IsNullOrWhiteSpace(subnet))
                    {
                        return Results.BadRequest("Subnet parameter is required");
                    }

                    Console.WriteLine($"Starting scan of subnet: {subnet}");
                    var hosts = await scanner.ScanNetworkWithNmapAsync(subnet);
                    
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
                    
                    if (string.IsNullOrWhiteSpace(subnet))
                    {
                        return Results.BadRequest("Subnet parameter is required");
                    }

                    var hosts = await scanner.ScanNetworkWithNmapAsync(subnet);
                    
                    // Generate CSV content
                    StringBuilder csv = new StringBuilder();
                    csv.AppendLine("IP Address,Hostname,FQDN");
                    
                    foreach (var host in hosts)
                    {
                        string hostname = host.Hostname.Contains(",") ? $"\"{host.Hostname}\"" : host.Hostname;
                        string fqdn = host.Fqdn.Contains(",") ? $"\"{host.Fqdn}\"" : host.Fqdn;
                        
                        csv.AppendLine($"{host.IpAddress},{hostname},{fqdn}");
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

            if (args.Length > 0)
            {
                subnet = args[0];
            }
            else
            {
                Console.Write("Enter subnet to scan (e.g., 192.168.1): ");
                subnet = Console.ReadLine()?.Trim() ?? "192.168.1";
            }

            if (!subnet.EndsWith("."))
            {
                subnet += ".";
            }

            Console.WriteLine($"Scanning subnet: {subnet}0/24...");
            
            List<HostInfo> hosts = await scanner.ScanNetworkWithNmapAsync($"{subnet}0/24");
            
            foreach (var host in hosts)
            {
                Console.WriteLine($"Found host: {host.IpAddress} - {host.Hostname} - {host.Fqdn}");
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

        public async Task<List<HostInfo>> ScanNetworkWithNmapAsync(string network)
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
                        // -sn: Ping scan - disable port scan
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
                                
                                hosts.Add(new HostInfo
                                {
                                    IpAddress = ip,
                                    Hostname = hostname,
                                    Fqdn = fqdn
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during Nmap scan: {ex.Message}");
                
                // Fallback to ping scan if nmap fails
                Console.WriteLine("Falling back to basic ping scan...");
                hosts = await FallbackPingScanAsync(network.Replace("/24", ""));
            }
            
            return hosts;
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
            csv.AppendLine("IP Address,Hostname,FQDN");
            
            // Add each host
            foreach (var host in hosts)
            {
                // Escape commas in values
                string hostname = host.Hostname.Contains(",") ? $"\"{host.Hostname}\"" : host.Hostname;
                string fqdn = host.Fqdn.Contains(",") ? $"\"{host.Fqdn}\"" : host.Fqdn;
                
                csv.AppendLine($"{host.IpAddress},{hostname},{fqdn}");
            }
            
            // Save to file
            File.WriteAllText(filePath, csv.ToString());
        }
    }

    public class HostInfo
    {
        public string IpAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string Fqdn { get; set; } = "";
    }
} 