using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Asn1.X509;
//using Org.BouncyCastle.Asn1.Ocsp;


namespace CA_Services.Model
{
    public class GenerateOcspRespRequest
    {
        [JsonPropertyName("tbsRequest")]
        public TbsRequest TbsRequest { get; set; }
    }

    public class TbsRequest
    {
        [JsonPropertyName("version")]
        public string Version { get; set; }

        [JsonPropertyName("requestList")]
        public List<Request> RequestList { get; set; } = new List<Request>();

        [JsonPropertyName("requestExtensions")]
        public List<Extension> RequestExtensions { get; set; } = new List<Extension>();
    }

    public class Request
    {
        [JsonPropertyName("reqCert")]
        public CertID ReqCert { get; set; }

        // singleRequestExtensions: absent if no per‐request extensions
        [JsonPropertyName("singleRequestExtensions")]
        public List<Extension> SingleRequestExtensions { get; set; } = null;
    }

    public class CertID
    {
        [JsonPropertyName("hashAlgorithm")]
        public AlgorithmIdentifier HashAlgorithm { get; set; }

        [JsonPropertyName("keyType")]
        public string KeyType { get; set; }

        [JsonPropertyName("issuerNameHash")]
        public byte[] IssuerNameHash { get; set; }

        [JsonPropertyName("issuerKeyHash")]
        public byte[] IssuerKeyHash { get; set; }

        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; set; }
    }

    public class AlgorithmIdentifier
    {
        [JsonPropertyName("algorithm")]
        public Oid Algorithm { get; set; }

        [JsonPropertyName("parameters")]
        public byte[] Parameters { get; set; }
    }

    public class Extension
    {
        [JsonPropertyName("extnID")]
        public Oid ExtnID { get; set; }

        [JsonPropertyName("critical")]
        public bool Critical { get; set; }

        [JsonPropertyName("extnValue")]
        public byte[] ExtnValue { get; set; }
    }


}
