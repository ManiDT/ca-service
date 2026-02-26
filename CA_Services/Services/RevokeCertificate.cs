using CA_Services.Data;
using CA_Services.Model;
using CA_Services.Services.Interfaces;

namespace CA_Services.Services
{
    public class RevokeCertificateByRequest : IRevokeCertificate
    {
        private readonly ApplicationDBContext _dbcontext;

        public RevokeCertificateByRequest(ApplicationDBContext dbcontext)
        {
            _dbcontext = dbcontext;
        }


        public string RevokeCertificate(RevokeCertificateRequest request)
        {
            string serialNumber = request.certificateSerialNumber;
            string revokReason = request.reason;

            if (string.IsNullOrEmpty(serialNumber))
            {
                return "Certificate serial number is not specified.";
            }
            if (string.IsNullOrEmpty(revokReason))
            {
                return "Reason for revocation is not specified.";
            }

            try
            {
                var certificateToRevoke = _dbcontext.EndUserCertificates
                    .SingleOrDefault(c => c.SerialNumber == serialNumber);

                if (certificateToRevoke == null)
                {
                    return $"Certificate with serial number {serialNumber} not found.";
                }

                if (certificateToRevoke.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase))
                {
                    return $"Certificate with serial number {serialNumber} is already revoked.";
                }

                certificateToRevoke.Status = "revoked";
                certificateToRevoke.RevocationReason = MapRevocationReasonToInt(revokReason);
                certificateToRevoke.RevocationDate = DateTime.UtcNow;

                _dbcontext.SaveChanges();

                return $"Certificate with serial number {serialNumber} has been successfully revoked for the reason: {revokReason}.";
            }
            catch (Exception ex)
            {
                return $"An error occurred while revoking the certificate: {ex.Message}";
            }

            //return "Certificate Revoked";
        }

        private static int MapRevocationReasonToInt(string revokReason)
        {
            if (string.IsNullOrWhiteSpace(revokReason))
                return 0; // Default to 'unspecified'

            // Normalize input
            string norm = revokReason.Trim().Replace(" ", "").Replace("-", "").Replace("_", "").ToLowerInvariant();

            // Standard mapping
            var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                { "unspecified", 0 },
                { "keycompromise", 1 },
                { "cacompromise", 2 },
                { "affiliationchanged", 3 },
                { "superseded", 4 },
                { "cessationofoperation", 5 },
                { "certificatehold", 6 },
                { "removefromcrl", 8 },
                { "privilegewithdrawn", 9 },
                { "aacompromise", 10 }
            };

            // Try direct match
            if (map.TryGetValue(norm, out int code))
                return code;

            // Try partial match (for user typos or similar)
            foreach (var kvp in map)
            {
                if (norm.Contains(kvp.Key))
                    return kvp.Value;
            }

            // Default to 'unspecified'
            return 0;
        }
    }
}
