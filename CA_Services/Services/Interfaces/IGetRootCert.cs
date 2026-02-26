using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IGetRootCertificate
    {
        public string GetRootCert(GetRootCertRequest request);
    }
}
