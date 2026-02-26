
using CA_Services.Model;
using CA_Services.Services.Interfaces;

namespace CA_Services.Services
{
    public class GetRootCertificate : IGetRootCertificate
    {
        public string GetRootCert(GetRootCertRequest request)
        {
            string encryptionAlgorithm = request.EncryptionAlgorithm;

            if (string.IsNullOrEmpty(encryptionAlgorithm))
            {
                return "Encryption algorithm is not specified.";
            }

            var certPath = "";

            switch (encryptionAlgorithm)
            {
                case "RSA":
                    certPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\rootCARSA.crt");
                    break;
                case "ECC":
                    certPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\rootCAECC.crt");
                    break;
                default:
                    break;
            }

            try
            {
                if (!File.Exists(certPath))
                {
                    return "Certificate file not found.";
                }
                return File.ReadAllText(certPath);
            } catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return ex.Message;
            }

            
        }
    }
}
