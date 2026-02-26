using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace CA_Services.Model
{
    public class OcspResponseModel
    {
        [JsonPropertyName("responseStatus")]
        public int ResponseStatus { get; set; }

        [JsonPropertyName("responseBytes")]
        public ResponseBytes ResponseBytes { get; set; }
    }

    public class ResponseBytes
    {
        [JsonPropertyName("responseType")]
        public Oid ResponseType { get; set; }

        [JsonPropertyName("response")]
        public BasicOcspResponse BasicResponse { get; set; }
    }

    public class BasicOcspResponse
    {
        [JsonPropertyName("tbsResponseData")]
        public TbsResponseData TbsResponseData { get; set; }

        [JsonPropertyName("signatureAlgorithm")]
        public AlgorithmIdentifierResp SignatureAlgorithm { get; set; }

        [JsonPropertyName("signature")]
        public byte[] Signature { get; set; }

        [JsonPropertyName("certs")]
        public List<byte[]> Certs { get; set; } = new List<byte[]>();
    }

    public class TbsResponseData
    {
        [JsonPropertyName("version")]
        public string Version { get; set; }  // v1

        [JsonPropertyName("responderID")]
        public ResponderID ResponderID { get; set; }

        [JsonPropertyName("producedAt")]
        public DateTime ProducedAt { get; set; }

        [JsonPropertyName("responses")]
        public List<SingleResponse> Responses { get; set; } = new List<SingleResponse>();

        [JsonPropertyName("responseExtensions")]
        public List<ExtensionResp> ResponseExtensions { get; set; } = new List<ExtensionResp>();
    }

    public class ResponderID
    {
        [JsonPropertyName("byKey")]
        public byte[] ByKey { get; set; }
    }

    public class SingleResponse
    {
        [JsonPropertyName("certID")]
        public CertIDResp CertID { get; set; }

        [JsonPropertyName("certStatus")]
        public CertStatus CertStatus { get; set; }

        [JsonPropertyName("thisUpdate")]
        public DateTime ThisUpdate { get; set; }

        [JsonPropertyName("nextUpdate")]
        public DateTime NextUpdate { get; set; }

        [JsonPropertyName("singleExtensions")]
        public List<ExtensionResp> SingleExtensions { get; set; } = null;

    }

    public class CertIDResp
    {
        [JsonPropertyName("hashAlgorithm")]
        public AlgorithmIdentifierResp HashAlgorithm { get; set; }

        [JsonPropertyName("issuerNameHash")]
        public byte[] IssuerNameHash { get; set; }

        [JsonPropertyName("issuerKeyHash")]
        public byte[] IssuerKeyHash { get; set; }

        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; set; }
    }

    public class ExtensionResp
    {
        [JsonPropertyName("extnID")]
        public Oid ExtnID { get; set; }

        [JsonPropertyName("critical")]
        public bool Critical { get; set; }

        [JsonPropertyName("extnValue")]
        public byte[] ExtnValue { get; set; }
    }

    public class AlgorithmIdentifierResp
    {
        [JsonPropertyName("algorithm")]
        public Oid Algorithm { get; set; }

        [JsonPropertyName("parameters")]
        public byte[] Parameters { get; set; }
    }

    public class CertStatus
    {
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("revocationTime")]
        public DateTime? RevocationTime { get; set; }

        [JsonPropertyName("revocationReason")]
        public int? RevocationReason { get; set; }

    }

}
