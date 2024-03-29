﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Configuration;
using System.IO;

namespace CertificateUpdater

{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                #region Loading config file

                Console.WriteLine("Reading configuration file... \n");
                string FinalThumbprint;
                string Issuer = ConfigurationManager.AppSettings["Certificate.Issuer"];
                int ServicePort = int.Parse(ConfigurationManager.AppSettings["Service.Port"]);
                string ServiceAppGUID = ConfigurationManager.AppSettings["Program.GUID"];
                bool AutoClose = bool.Parse(ConfigurationManager.AppSettings["Auto.Close"]);
                bool DebugMode = bool.Parse(ConfigurationManager.AppSettings["Debug.Mode"]);
                bool ExportCert = bool.Parse(ConfigurationManager.AppSettings["Export.Cert"]);
                string ExportPath = ConfigurationManager.AppSettings["Export.Path"];
                string ExportPassword = ConfigurationManager.AppSettings["Export.Password"];

                #endregion Loading config file
                #region Get certificate and prepare to use

                Console.WriteLine("Opening the Certificates Store...");
                X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                Console.WriteLine("Looking for the Issued to...");
                X509Certificate2Collection fCollection = (X509Certificate2Collection)collection.Find(X509FindType.FindBySubjectName, Issuer, true);
                Console.WriteLine("Looking for the newest cert...");
                X509Certificate2Collection apoCollection = fCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
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
                            Console.WriteLine("The newest certificate is " + lastCert.FriendlyName + "\nand has the expiration date: " + compareDate);
                            Console.WriteLine("The thumbprint is: \n" + lastCert.Thumbprint + "\n");
                            FinalThumbprint = lastCert.Thumbprint;

                        }
                        else
                            FinalThumbprint = lastCert.Thumbprint;

                        #endregion Get certificate and prepare to use
                        Console.WriteLine();
                    }

                    #region Export cert
                    if (ExportCert)
                    {
                        //export cert
                        byte[] certData = lastCert.Export(X509ContentType.Pfx, ExportPassword);
                        Console.WriteLine("Got the cert: " + lastCert.FriendlyName);
                        File.WriteAllBytes(@"" + ExportPath, certData);
                        Console.WriteLine("Should be writed at folder: " + ExportPath);
                    }
                    #endregion Export cert


                    #region Apply cert
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
                        #endregion Apply cert
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
