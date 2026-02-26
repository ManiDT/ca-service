using System.Net.Mime;
using CA_Services.Model;
using CA_Services.Services;
using CA_Services.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace CA_Services.Controllers
{

    [ApiController]
    public class CA_ServicesController : ControllerBase
    {
        private readonly IGetRootCertificate _getRootCertificate;
        private readonly IGetIssuerCertificate _getIssuerCertificate;
        private readonly IGenerateEndCertificate _generateEndCertificate;
        private readonly IGenerateEndCertificateCSR _generateEndCertificateCSR;
        private readonly IGenerateOcspResp _generateOcspResp;
        private readonly IRevokeCertificate _revokeCertificate;
        private readonly ICheckCertificateDetails _checkCertificateDetails ;

        public CA_ServicesController(
            IGetRootCertificate getRootCertificate,
            IGetIssuerCertificate getIssuerCertificate,
            IGenerateEndCertificate generateEndCertificate,
            IGenerateEndCertificateCSR generateEndCertificateCSR,
            IGenerateOcspResp generateOcspResp,
            IRevokeCertificate revokeCertificate,
            ICheckCertificateDetails checkCertificateDetails)
        {
            _getRootCertificate = getRootCertificate;
            _getIssuerCertificate = getIssuerCertificate;
            _generateEndCertificate = generateEndCertificate;
            _generateEndCertificateCSR = generateEndCertificateCSR;
            _generateOcspResp = generateOcspResp;
            _revokeCertificate = revokeCertificate;
            _checkCertificateDetails = checkCertificateDetails;
        }


        [HttpGet]
        [Route("GetRootCert")]
        public string GetRootCert([FromBody] GetRootCertRequest request)
        {
            var response = _getRootCertificate.GetRootCert(request);
            return response;

        }

        [HttpPost]
        [Route("GetIssuerCert")]
        public string GetIssuerCert([FromBody] GetIssuerCertRequest request)
        {
            var response = _getIssuerCertificate.GetIssuerCert(request);
            return response;
        }



        [HttpPost]
        [Route("GenerateEndCert")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces(MediaTypeNames.Application.Octet, Type=typeof(byte[]))]
        public IActionResult GenerateEndUserCertificate([FromBody] GenerateEndCertRequest request)
        {
            try
            {
                byte[] pfxBytes = _generateEndCertificate.GenerateEndCert(request);

                if (pfxBytes == null || pfxBytes.Length == 0)
                {
                    return StatusCode(500, "Failed to generate end user certificate");
                }

                var fileName = $"endUserCertificate_{request.EncryptionAlgorithm}";

                return File(pfxBytes, "application/x-pkcs12", fileName);


            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error generating end user certificate: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpPost]
        [Route("ca1/ejbca/api/cert-generate")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces(MediaTypeNames.Application.Json, Type = typeof(GenerateEndUserCertCSRResponse))]
        public IActionResult GenerateEndUserCertificateCSR([FromBody] GenerateEndCertCSRRequest request)
        {
            try
            {
                var response = _generateEndCertificateCSR.GenerateEndCertCSR(request);
                if (response == null)
                {
                    return StatusCode(500, "Failed to generate end user certificate from CSR");
                }
                return Ok(response);
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error generating end user certificate from CSR: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }


        [HttpPost]
        [Route("GenerateOcspResponse")]
        public OcspResponseModel GenerateOcspResponse([FromBody] GenerateOcspRespRequest request)
        {
            try
            {
                var ocspResponse = _generateOcspResp.GenerateOcspResponse(request);

                return ocspResponse;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating OCSP response: {ex.Message}", ex);
            }
        }

        [HttpPost]
        [Route("RevokeCertificate")]
        public string RevokeCertificate([FromBody] RevokeCertificateRequest request)
        {
            try
            {
                return _revokeCertificate.RevokeCertificate(request);
            }
            catch (Exception ex)
            {
                return $"An error occurred while revoking the certificate: {ex.Message}";
            }
        }

        [HttpGet]
        [Route("CheckCertificateDetails")]
        public CertificateDetails CheckCertificateDetails([FromBody] CheckCertificateDetailsRequest request)
        {
            try
            {
                return _checkCertificateDetails.CheckCertificateDetailsByRequest(request);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error checking certificate details: {ex.Message}", ex);
            }
        }
        
    }
}
