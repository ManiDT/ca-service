namespace CA_Services.Model
{
    public class GetRootCertRequest
    {
        public string EncryptionAlgorithm { get; set; }

    }

    public class GetIssuerCertRequest
    {
        public string EncryptionAlgorithm { get; set; }
        public bool isPublicKey { get; set; } = false;
        public bool isPrivateKey { get; set; } = false;
    }


}