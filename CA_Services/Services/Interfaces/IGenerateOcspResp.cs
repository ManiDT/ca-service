using CA_Services.Model;

namespace CA_Services.Services.Interfaces
{
    public interface IGenerateOcspResp
    {
        public OcspResponseModel GenerateOcspResponse(GenerateOcspRespRequest request);
    }
}
