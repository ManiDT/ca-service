using CA_Services.Data;
using CA_Services.Model;
using CA_Services.Services.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace CA_Services.Services
{
    public class GetIssuerCertificate : IGetIssuerCertificate
    {
        private readonly ApplicationDBContext _dbcontext;

        public GetIssuerCertificate(ApplicationDBContext dbcontext)
        {
            _dbcontext = dbcontext;
        }

        public string GetIssuerCert(GetIssuerCertRequest request)
        {
            if (string.IsNullOrEmpty(request.EncryptionAlgorithm))
            {
                return "Encryption algorithm is not specified.";
            }

            if (!request.isPublicKey && !request.isPrivateKey)
            {
                return "Client must request either public key or private key (set isPublicKey or iPrivateKey to true)";
            }

            var alg = request.EncryptionAlgorithm.Trim();

            var issuer = _dbcontext.Issuers
                .FirstOrDefault(ele => ele.KeyType == alg);

            if (issuer == null)
            {
                return $"Issuer with encryption algorithm {request.EncryptionAlgorithm} not found.";
            }

            if (request.isPrivateKey && !request.isPublicKey)
            {
                return issuer.PrivateKeyEncrypted;
            }

            if (request.isPublicKey && !request.isPrivateKey)
            {
                return issuer.CertificatePem;
            }

            return "Invalid request Parameters";
        }




        //public string GetIssuerCert(GetIssuerCertRequest request)
        //{
        //    string encryptionAlgorithm = request.EncryptionAlgorithm;
        //    if (string.IsNullOrEmpty(encryptionAlgorithm))
        //    {
        //        return "Encryption algorithm is not specified.";
        //    }
        //    var certPath = "";
        //    switch (encryptionAlgorithm)
        //    {
        //        case "RSA":
        //            certPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\issuerRSA.crt");
        //            break;
        //        case "ECC":
        //            certPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\issuerECC.crt");
        //            break;
        //        default:
        //            break;
        //    }
        //    try
        //    {
        //        if (!File.Exists(certPath))
        //        {
        //            return "Certificate file not found.";
        //        }
        //        return File.ReadAllText(certPath);
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine(ex.Message);
        //        return ex.Message;
        //    }
        //}
    }
}
