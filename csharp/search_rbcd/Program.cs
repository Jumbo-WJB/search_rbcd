using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using CommandLine;
using System.Net;
using System.DirectoryServices;

namespace AddMachineAccount
{
    public class Options
    {
        [Option("a", "DomainController", Required = false, HelpText = "Set the domain controller to use.")]
        public string DomainController { get; set; }

        [Option("d", "Domain", Required = false, HelpText = "Set the target domain.")]
        public string Domain { get; set; }

        [Option("u", "LdapUsername", Required = false, HelpText = "Set the Ldap Username.")]
        public string LdapUsername { get; set; }

        [Option("p", "LdapPassword", Required = false, HelpText = "Set the Ldap Password.")]
        public string LdapPassword { get; set; }
        public string Cleanup { get; set; }

    }

    class Program
    {

        public static void PrintHelp()
        {
            string HelpText = "\nUsage: SharpAllowedToAct.exe --LdapUsername username --LdapPassword passwordn" +
                "\nOptions:\n" +
                "-u, --LdapUsername\n" +
                "\tSet the Ldap Username.\n" +
                "\n" +
                 "-p, --LdapPassword\n" +
                "\tSet the Ldap Password.\n" +
                "\n" +
                "-a, --DomainController\n" +
                "\tSet the domain controller to use.\n" +
                "\n" +
                "-d, --Domain\n" +
                "\tSet the target domain.\n" +
                "\n";
            Console.WriteLine(HelpText);
        }

        public static void get_sid_info(String Domain, String DomainController, String ldapuser, String ldappass,String sid)
        {
            String LDAP_URL = "LDAP://" + DomainController;
            System.DirectoryServices.DirectoryEntry myldapConnection = new System.DirectoryServices.DirectoryEntry(LDAP_URL, ldapuser, ldappass);
            System.DirectoryServices.DirectorySearcher search2 = new System.DirectoryServices.DirectorySearcher(myldapConnection);
            search2.Filter = String.Format("(objectSid={0})",sid);
            string[] requiredProperties = new string[] { "samaccountname" };
            foreach (String property in requiredProperties)
                search2.PropertiesToLoad.Add(property);
            var results2 = search2.FindOne();
            Console.WriteLine("    |_ sam              : " + results2.Properties["samaccountname"][0]);
        }

        public static void get_computer_AllowedToActOnBehalfOfOtherIdentity(String Domain, String DomainController, String ldapuser, String ldappass)
        {
            // get the domain object of the victim computer and update its securty descriptor 
            String LDAP_URL = "LDAP://" + DomainController;
            System.DirectoryServices.DirectoryEntry myldapConnection = new System.DirectoryServices.DirectoryEntry(LDAP_URL, ldapuser, ldappass);
            System.DirectoryServices.DirectorySearcher search = new System.DirectoryServices.DirectorySearcher(myldapConnection);

            search.Filter = "(&(objectCategory=computer)(objectClass=computer))";
            string[] requiredProperties = new string[] { "cn", "msds-allowedtoactonbehalfofotheridentity" };

            foreach (String property in requiredProperties)
                search.PropertiesToLoad.Add(property);

            var results = search.FindAll();
            foreach (SearchResult result in results)
            {

                if (result.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                {
                    Console.WriteLine(result.Properties["cn"][0]);
                    var rsd = new RawSecurityDescriptor((byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0], 0);
                    foreach (CommonAce ace in rsd.DiscretionaryAcl)
                    {
                        String AllowedToActOnBehalfOfOtherIdentitySID = ace.SecurityIdentifier.ToString();
                        Console.WriteLine("    |_ SID              : " + AllowedToActOnBehalfOfOtherIdentitySID); // https://github.com/FuzzySecurity/StandIn/blob/469d3e5991a8964f798496e0aa7af595d8350f8c/StandIn/StandIn/Program.cs#L118
                        get_sid_info(Domain, DomainController, ldapuser, ldappass, AllowedToActOnBehalfOfOtherIdentitySID);
                    }


                }


            }
        }

        static void Main(string[] args)
        {
            if (args == null)
            {
                PrintHelp();
                return;
            }

            String DomainController = "";
            String Domain = "";
            String ldapuser = "";
            String ldappass = "";
            String distinguished_name = "";

            var Options = new Options();


            if (CommandLineParser.Default.ParseArguments(args, Options))
            {
                if ((!string.IsNullOrEmpty(Options.LdapPassword)))
                {
                    if (!string.IsNullOrEmpty(Options.DomainController))
                    {
                        DomainController = Options.DomainController;
                    }
                    if (!string.IsNullOrEmpty(Options.Domain))
                    {
                        Domain = Options.Domain;
                    }
                    if (!string.IsNullOrEmpty(Options.LdapUsername))
                    {
                        ldapuser = Options.LdapUsername;
                    }
                    if (!string.IsNullOrEmpty(Options.LdapPassword))
                    {
                        ldappass = Options.LdapPassword;
                    }
                }
                else
                {
                    Console.Write("[!] Missing required arguments! Exiting...\n");
                    //PrintHelp();
                    return;
                }
            }
            else
            {
                Console.Write("[!] Missing required arguments! Exiting...\n");
                PrintHelp();
                return;
            }

            // If a domain controller and domain were not provide try to find them automatically
            System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
            if (DomainController == String.Empty || Domain == String.Empty)
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch
                {
                    Console.WriteLine("[!] Cannot enumerate domain.\n");
                    return;
                }

            }

            if (DomainController == String.Empty)
            {
                DomainController = current_domain.PdcRoleOwner.Name;
            }

            if (Domain == String.Empty)
            {
                Domain = current_domain.Name;
            }

            Domain = Domain.ToLower();

            String[] DC_array = null;
            DC_array = Domain.Split('.');
            foreach (String DC in DC_array)
            {

                distinguished_name += ",DC=" + DC;

            }
            distinguished_name = distinguished_name.TrimStart(',');
            Console.WriteLine("[+] Domain = " + Domain);
            Console.WriteLine("[+] Domain Controller = " + DomainController);
            Console.WriteLine("[+] Distinguished Name = " + distinguished_name);
            Console.WriteLine("[+] Try login.");
            try
            {


                get_computer_AllowedToActOnBehalfOfOtherIdentity(Domain, DomainController, ldapuser, ldappass);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return;
            }
        }

    }
}

