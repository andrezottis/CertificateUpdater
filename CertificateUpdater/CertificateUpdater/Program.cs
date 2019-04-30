using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;


namespace CertificateUpdater
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string ISSUER = "SRVMETRIS";
                string FINALTHUMBPRINT;
                X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection apocollection = fcollection.Find(X509FindType.FindBySubjectName, ISSUER, true);

                X509Certificate2 lastCert = apocollection[0];
                FINALTHUMBPRINT = lastCert.Thumbprint;
                foreach (var certificatecolection in apocollection)
                {

                    var dateCert = Convert.ToDateTime(certificatecolection.GetExpirationDateString());
                    var compareDate = Convert.ToDateTime(lastCert.GetExpirationDateString());
                    if ((apocollection.Count == 1) || (dateCert > compareDate))
                    {
                        lastCert = certificatecolection;
                        Console.WriteLine("Certs is date : " + dateCert);
                        Console.WriteLine("The older date is:" + compareDate);
                        Console.WriteLine("The older cert thumb is:" + lastCert.Thumbprint);
                        FINALTHUMBPRINT = lastCert.Thumbprint;
                        //string strCmdText = "netsh http delete sslcert ipport=0.0.0.0:9000";
                        //Console.WriteLine(strCmdText);
                        //strCmdText = "netsh http add sslcert ipport=0.0.0.0:9000 certhash=" + FINALTHUMBPRINT.Trim() + " appid={3a487f59-fcb7-4213-b7ff-871456ae7b70}";
                        //Console.WriteLine(strCmdText);
                    }else
                        FINALTHUMBPRINT = lastCert.Thumbprint;

                    Console.WriteLine();
                }

                string strCmdText = "netsh http delete sslcert ipport=0.0.0.0:9000";
                Console.WriteLine(strCmdText);
                strCmdText = "netsh http add sslcert ipport=0.0.0.0:9000 certhash=" + FINALTHUMBPRINT.Trim() + " appid={3a487f59-fcb7-4213-b7ff-871456ae7b70}";
                Console.WriteLine(strCmdText);

                //X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(apocollection, "Test Certificate Select", "Select a certificate from the following list to get information on that certificate", X509SelectionFlag.MultiSelection);
                //Console.WriteLine("Number of certificates: {0}{1}", scollection.Count, Environment.NewLine);

                //foreach (X509Certificate2 x509 in scollection)
                //{
                //    try
                //    {
                //        byte[] rawdata = x509.RawData;
                //        Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                //        Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                //        Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                //        Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                //        Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                //        Console.WriteLine("Private Key: {0}{1}", x509.PrivateKey.ToXmlString(false), Environment.NewLine);
                //        Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                //        Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                //        Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                //        //X509Certificate2UI.DisplayCertificate(x509);
                //        x509.Reset();
                //    }
                //    catch (CryptographicException)
                //    {
                //        Console.WriteLine("Information could not be written out for this certificate.");
                //    }
                //}
                store.Close();
                Console.ReadLine();
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Information could not be written out for this certificate.");
            }
        }
    }
}
