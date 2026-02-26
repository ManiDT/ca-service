using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface ICheckCertificateDetails
    {
        
        CertificateDetails CheckCertificateDetailsByRequest(CheckCertificateDetailsRequest request);

    }
}
