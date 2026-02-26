using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IGenerateEndCertificate
    {
        public byte[] GenerateEndCert(GenerateEndCertRequest request);
    }
}
