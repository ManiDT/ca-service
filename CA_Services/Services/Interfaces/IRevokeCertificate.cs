using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IRevokeCertificate
    {
        public string RevokeCertificate(RevokeCertificateRequest request);
    }
}
