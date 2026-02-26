namespace CA_Services.Model
{
    public class GenerateEndCertRequest
    {
        public string EncryptionAlgorithm { get; set; }
    }

    public class GenerateEndCertCSRRequest
    {
        public string CsrBase64 { get; set; }
        public string User { get; set; }
        public string KeyId { get; set; }
        public string CommonName { get; set; }
        public string CountryName { get; set; }
    }
}
