namespace CA_Services.Model
{
    public class CertificateDetails
    {
        public string SerialNumber { get; set; } = null!;
        public string SubjectName { get; set; } = null!;
        public int IssuerId { get; set; }
        public string KeyType { get; set; } = null!;
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string CertificatePem { get; set; } = null!;
        public string PrivateKeyPem { get; set; } = null!;
        public string Status { get; set; } = "unknown";
        public DateTime? RevocationDate { get; set; }
        public int? RevocationReason { get; set; }
    }
}
