using System;
using System.Security.Cryptography.X509Certificates;

namespace CertificateUpdater
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
        public static void CheckCertificate()
        {
            // create a default certificate id none specified.
            CertificateIdentifier id = configuration.SecurityConfiguration.ApplicationCertificate;

            X509Certificate2
            if (id == null)
            {
                CertificateFactory
                id = new CertificateIdentifier();
                id.StoreType = CertificateStoreType.Windows;
                id.StorePath = "LocalMachine\\My";
                id.SubjectName = configuration.ApplicationName;
            }

            IList<string> serverDomainNames = configuration.GetServerDomainNames();

            // check for private key.
            X509Certificate2 certificate = id.Find(true);

            if (certificate != null)
            {
                return;
            }

            certificate = id.Find(false);

            if (certificate != null)
            {
                Utils.Trace(Utils.TraceMasks.Error, "Certificate found. But private ket is not accessible: '{0}' {1}", certificate.Subject, certificate.Thumbprint);
                certificate = null;
            }

            // add the host.
            if (serverDomainNames.Count == 0)
            {
                serverDomainNames.Add(System.Net.Dns.GetHostName());

            }
    }
}
