using System;
using System.Net;
using System.Text.RegularExpressions;

/* Hlavní zdroj, který mi pomohl vše pochopit */
/* https://www.samuraj-cz.com/clanek/tcpip-adresy-masky-subnety-a-vypocty/ */

namespace IP_Masking_app
{
    internal class Program
    {
        // Regex validace formátů
        private const string IP_REGEX_PATTERN = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        private const string CIDR_REGEX_PATTERN = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(\d|[1-2][0-9]|3[0-2])$";

        static void Main(string[] args)
        {
            try
            {
                // Načteme síťové informace
                var networkInfo = GetValidNetwork();
                if (networkInfo == null) return;

                // Umožní ověřování IP adres proti načtené síti
                ProcessIpAddresses(networkInfo.Value.baseIp, networkInfo.Value.subnetMask);
            }
            catch (Exception ex)
            {
                WriteColored($"Došlo k neočekávané chybě: {ex.Message}", ConsoleColor.Red);
            }
        }

        // Získání platné sítě od uživatele
        static (string baseIp, int subnetMask)? GetValidNetwork()
        {
            Console.WriteLine("Vítejte v programu pro validaci IP adres a podsítí!");
            while (true)
            {
                Console.Write("Zadejte síť (např. 192.168.15.0/24) nebo prázdný vstup pro ukončení: ");
                string input = Console.ReadLine();

                // Ukončí program pokud není zadaný vstup
                if (string.IsNullOrEmpty(input))
                {
                    WriteColored("Ukončuji program...", ConsoleColor.Cyan);
                    return null;
                }
                // Check formátu
                if (!ValidateCIDR(input))
                {
                    WriteColored("Neplatný formát! Použijte formát: xxx.xxx.xxx.xxx/xx", ConsoleColor.Yellow);
                    continue;
                }
                // Rozdělení IP adresy a masky
                var parts = input.Split('/');
                return (parts[0], int.Parse(parts[1]));
            }
        }

        // Ověření IP adres proti zadané síti
        static void ProcessIpAddresses(string baseIp, int subnetMask)
        {
            Console.WriteLine("Zadejte IP adresy k ověření, nebo prázdný vstup pro ukončení programu.");
            while (true)
            {
                Console.Write("\nZadejte IP adresu: ");
                string ip = Console.ReadLine();

                // Ukončí program pokud není zadaný vstup
                if (string.IsNullOrEmpty(ip))
                {
                    WriteColored("Ukončuji program...", ConsoleColor.Cyan);
                    break;
                }

                // Check zadané IP adresy
                if (!ValidateIP(ip))
                {
                    WriteColored("Neplatná IP adresa. Zkuste to znovu.", ConsoleColor.Yellow);
                    continue;
                }

                // Ověření IP adresy zda je ve stejné podsíti
                bool isInSameSubnet = IsSameSubnet(ip, baseIp, subnetMask);
                WriteColored($"IP adresa {ip} {(isInSameSubnet ? "JE" : "NENÍ")} ve stejné podsíti.", isInSameSubnet ? ConsoleColor.Green : ConsoleColor.Red);
            }
        }

        // Check formátu CIDR
        static bool ValidateCIDR(string input)
        {
            return Regex.IsMatch(input, CIDR_REGEX_PATTERN);
        }

        // Check formátu IP
        static bool ValidateIP(string ip)
        {
            return Regex.IsMatch(ip, IP_REGEX_PATTERN);
        }

        // Ověření IP adresy zda je ve stejné podsíti
        static bool IsSameSubnet(string ip, string baseIp, int subnetMask)
        {
            try
            {
                IPAddress ipAddr = IPAddress.Parse(ip);
                IPAddress baseIpAddr = IPAddress.Parse(baseIp);

                byte[] ipBytes = ipAddr.GetAddressBytes();
                byte[] baseIpBytes = baseIpAddr.GetAddressBytes();
                byte[] maskBytes = CalculateSubnetMask(subnetMask);

                for (int i = 0; i < maskBytes.Length; i++)
                {
                    if ((ipBytes[i] & maskBytes[i]) != (baseIpBytes[i] & maskBytes[i]))
                        return false;
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Výpočet masky podsítě
        static byte[] CalculateSubnetMask(int subnetMask)
        {
            byte[] mask = new byte[4];
            for (int i = 0; i < subnetMask / 8; i++)
            {
                mask[i] = 255;
            }
            if (subnetMask % 8 > 0)
            {
                mask[subnetMask / 8] = (byte)(~(255 >> (subnetMask % 8)));
            }
            return mask;
        }

        // Výpis výsledku s barvou
        static void WriteColored(string message, ConsoleColor color)
        {
            ConsoleColor originalColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ForegroundColor = originalColor;
        }
    }

}
