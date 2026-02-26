using CA_Services.Data;
using CA_Services.Model;
using CA_Services.Services.Interfaces;

namespace CA_Services.Services
{
    public class CheckCertificateDetails : ICheckCertificateDetails
    {
        private readonly ApplicationDBContext _dbcontext;

        public CheckCertificateDetails(ApplicationDBContext dBContext)
        {
            _dbcontext = dBContext;
        }

        public CertificateDetails CheckCertificateDetailsByRequest(CheckCertificateDetailsRequest request)
        {
            string serialNumber = request.serialNumber;

            if (string.IsNullOrEmpty(serialNumber))
            {
                throw new ArgumentException("Serial number cannot be null or empty.", nameof(serialNumber));
            }
            
            var certificate = _dbcontext.EndUserCertificates
                .SingleOrDefault(c => c.SerialNumber == serialNumber);


            if (certificate == null)
            {
                throw new InvalidOperationException($"Certificate with serial number {serialNumber} not found.");
            }

            return new CertificateDetails
            {
                SerialNumber = certificate.SerialNumber,
                SubjectName = certificate.SubjectName,
                IssuerId = certificate.IssuerId, 
                KeyType = certificate.KeyType,
                ValidFrom = DateTime.UtcNow, 
                ValidTo = DateTime.UtcNow.AddYears(1), 
                CertificatePem = certificate.CertificatePem,
                PrivateKeyPem = certificate.PrivateKeyPem,
                Status = certificate.Status,
                RevocationDate = certificate.RevocationDate,
                RevocationReason = certificate.RevocationReason
            };
        }
    }
}
