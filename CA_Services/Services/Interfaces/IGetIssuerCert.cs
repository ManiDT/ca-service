using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IGetIssuerCertificate
    {
        public string GetIssuerCert(GetIssuerCertRequest request);
    }
}
