using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Configuration;

namespace CertificateUpdater

{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {

                Console.WriteLine("Reading configuration file... \n");
                string FinalThumbprint;
                string Issuer = ConfigurationManager.AppSettings["Certificate.Issuer"];
                int ServicePort = int.Parse(ConfigurationManager.AppSettings["Service.Port"]);
                string ServiceAppGUID = ConfigurationManager.AppSettings["Program.GUID"];
                bool AutoClose = bool.Parse(ConfigurationManager.AppSettings["Auto.Close"]);
                bool DebugMode = bool.Parse(ConfigurationManager.AppSettings["Debug.Mode"]);

                X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fCollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection apoCollection = fCollection.Find(X509FindType.FindBySubjectName, Issuer, true);

                var apoCountCollection = apoCollection.Count;

                if (0 == apoCountCollection)
                {
                    Console.WriteLine("Error: No certificate found containing the specified requirements. ");
                    Console.ReadLine();
                }
                else
                {
                    Console.WriteLine("Found a total of {0:D} certificates...\n ", apoCountCollection);
                    X509Certificate2 lastCert = apoCollection[0];
                    FinalThumbprint = lastCert.Thumbprint;

                    foreach (var certificatecolection in apoCollection)
                    {

                        var dateCert = Convert.ToDateTime(certificatecolection.GetExpirationDateString());
                        var compareDate = Convert.ToDateTime(lastCert.GetExpirationDateString());
                        if ((apoCollection.Count == 1) || (dateCert > compareDate))
                        {
                            lastCert = certificatecolection;
                            compareDate = Convert.ToDateTime(lastCert.GetExpirationDateString());
                            Console.WriteLine("The newest cert is " + lastCert.FriendlyName + "\nand has the expiration date: " + compareDate);
                            Console.WriteLine("The thumbprint is: \n" + lastCert.Thumbprint + "\n");
                            FinalThumbprint = lastCert.Thumbprint;

                        }
                        else
                            FinalThumbprint = lastCert.Thumbprint;

                        Console.WriteLine();
                    }

                    if (DebugMode)
                    {
                        string strCmdText = "netsh http delete sslcert ipport=0.0.0.0:" + ServicePort;
                        Console.WriteLine(strCmdText);
                        strCmdText = "netsh http add sslcert ipport=0.0.0.0:" + ServicePort + " certhash=" + FinalThumbprint.Trim() + " appid={" + ServiceAppGUID + "}";
                        Console.WriteLine(strCmdText);
                    }
                    else
                    {
                        Process cmd = new Process();
                        cmd.StartInfo.FileName = "cmd.exe";
                        cmd.StartInfo.RedirectStandardInput = true;
                        cmd.StartInfo.RedirectStandardOutput = true;
                        cmd.StartInfo.CreateNoWindow = true;
                        cmd.StartInfo.UseShellExecute = false;
                        cmd.Start();

                        cmd.StandardInput.WriteLine("netsh http delete sslcert ipport=0.0.0.0:" + ServicePort);
                        cmd.StandardInput.WriteLine("netsh http add sslcert ipport=0.0.0.0:" + ServicePort + " certhash=" + FinalThumbprint.Trim() + " appid={" + ServiceAppGUID + "}");
                        cmd.StandardInput.Flush();
                        cmd.StandardInput.Close();
                        cmd.WaitForExit();
                        Console.WriteLine(cmd.StandardOutput.ReadToEnd());
                        store.Close();
                    }
                    if (AutoClose != true)
                        Console.ReadLine();

                }
            }
            catch (global::System.Exception e)
            {
                Console.WriteLine("Information could not be written out for this certificate. The error code is: \n" + e);
                Console.ReadLine();
            }
        }
    }
}
