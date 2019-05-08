using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace CertificateUpdater

{

    class Constants
    {
        public const string Issuer = "METRISHOTFIX";
        public const int ServicePort = 9000;
        public const string ServiceAppGUID ="3a487f59-fcb7-4213-b7ff-871456ae7b70";
    }
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //Future must be read from a config file.
                string FinalThumbprint;

                X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fCollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection apoCollection = fCollection.Find(X509FindType.FindBySubjectName, Constants.Issuer, true);


                if (0 == apoCollection.Count)
                {
                    Console.WriteLine("Error: No certificate found containing the specified requirements. ");
                    Console.ReadLine();
                }
                else
                {

                    X509Certificate2 lastCert = apoCollection[0];
                    FinalThumbprint = lastCert.Thumbprint;

                    foreach (var certificatecolection in apoCollection)
                    {

                        var dateCert = Convert.ToDateTime(certificatecolection.GetExpirationDateString());
                        var compareDate = Convert.ToDateTime(lastCert.GetExpirationDateString());
                        if ((apoCollection.Count == 1) || (dateCert > compareDate))
                        {
                            lastCert = certificatecolection;
                            Console.WriteLine("Certs is date : " + dateCert);
                            Console.WriteLine("The newest date is:" + compareDate);
                            Console.WriteLine("The newest cert thumb is:" + lastCert.Thumbprint);
                            FinalThumbprint = lastCert.Thumbprint;

                        }
                        else
                            FinalThumbprint = lastCert.Thumbprint;

                        Console.WriteLine();
                    }

                    string strCmdText = "netsh http delete sslcert ipport=0.0.0.0:" +Constants.ServicePort;
                    Console.WriteLine(strCmdText);
                    strCmdText = "netsh http add sslcert ipport=0.0.0.0:"+ Constants.ServicePort + " certhash=" + FinalThumbprint.Trim() + " appid={"+ Constants.ServiceAppGUID +"}";
                    Console.WriteLine(strCmdText);

                    Process cmd = new Process();
                    cmd.StartInfo.FileName = "cmd.exe";
                    cmd.StartInfo.RedirectStandardInput = true;
                    cmd.StartInfo.RedirectStandardOutput = true;
                    cmd.StartInfo.CreateNoWindow = true;
                    cmd.StartInfo.UseShellExecute = false;
                    cmd.Start();

                    cmd.StandardInput.WriteLine("netsh http delete sslcert ipport=0.0.0.0:" + Constants.ServicePort);
                    cmd.StandardInput.WriteLine("netsh http add sslcert ipport=0.0.0.0:"+ Constants.ServicePort + " certhash=" + FinalThumbprint.Trim() + " appid={" + Constants.ServiceAppGUID + "}";
                    cmd.StandardInput.Flush();
                    cmd.StandardInput.Close();
                    cmd.WaitForExit();
                    Console.WriteLine(cmd.StandardOutput.ReadToEnd());

                    store.Close();
                    Console.ReadLine();
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Information could not be written out for this certificate. The error code is:  " + e);
            }
        }
    }
}
