# Certificate Updater
Automated tool to update an aplication certificate that runs on Windows.
Compatible with .NetFrameWork 4.6.1

## Details
This App has a AppSettings.config file that must be placed with the binary .exe.
  > At this config file you can set some options related with the Certificate and your App.

### Requirementes: 
 - App ID: The unique identifier of your Self Hosting app. 
 - Certificate Issuer (for Who this certificate is signed). 
 - The server where it will runs needs a Store (maybe a IIS Server installation).
 
 ### Features:
 - Get the certificate with the higher Expiration Date that is stored at Windows Server certificate store. 
 - Update automatically the Netsh service with your new Thumbprint.
 - Allow you to run in Debug mode, where no changes are made in your Netsh service.
 - Export the certificate to defined folder.
 - Allow to run with auto close, perfect to runs with schedule tasks or Certify app (made by community). Check [here](https://certifytheweb.com).

## Authors

* **André Zottis** - *Initial work* - [AndreZottis](https://github.com/andrezottis)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

