using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IGenerateEndCertificateCSR
    {
        public GenerateEndUserCertCSRResponse GenerateEndCertCSR(GenerateEndCertCSRRequest request);

    }
}
