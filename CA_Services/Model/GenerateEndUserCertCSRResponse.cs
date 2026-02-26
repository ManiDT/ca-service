namespace CA_Services.Model
{
    public class GenerateEndUserCertCSRResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public GenerateEndUserCertCSRResult Result { get; set; }
    }

    public class GenerateEndUserCertCSRResult
    {
        public string Cert { get; set; }
    }
}
