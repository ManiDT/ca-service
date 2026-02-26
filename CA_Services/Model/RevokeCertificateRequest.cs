namespace CA_Services.Model
{
    public class RevokeCertificateRequest
    {
        public string certificateSerialNumber { get; set; }

        public string reason { get; set; }
    }
}
