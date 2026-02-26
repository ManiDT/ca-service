
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CA_Services.Data;
using CA_Services.Data.Entities;
using CA_Services.Model;
using CA_Services.Services.Interfaces;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;





namespace CA_Services.Services
{
    public class GenerateOcspResp : IGenerateOcspResp
    {
        private readonly ApplicationDBContext _dbcontext;

        public GenerateOcspResp(ApplicationDBContext dBContext)
        {
            _dbcontext = dBContext;
        }

        public OcspResponseModel GenerateOcspResponse(GenerateOcspRespRequest request)
        {
            // Extracting the first certId from the request
            var certId = request.TbsRequest.RequestList.FirstOrDefault()?.ReqCert
                ?? throw new InvalidOperationException("No CertId in OCSP request");

            var incomingNonceExt = request
                .TbsRequest
                .RequestExtensions
                .FirstOrDefault(e => e.ExtnID.Value == "1.3.6.1.5.5.7.48.1.2");

            byte[] issuerNameHash = certId.IssuerNameHash;
            byte[] issuerKeyHash = certId.IssuerKeyHash;
            string hashOid = certId.HashAlgorithm.Algorithm.Value;
            string requestedSerial = certId.SerialNumber;

            string keyType = certId.KeyType;

            var certIssuer = _dbcontext.Issuers
                .AsEnumerable() 
                .FirstOrDefault(i => i.KeyType.Equals(keyType, StringComparison.OrdinalIgnoreCase)
            );


            //var certIssuer = _dbcontext.Issuers
            //    .AsEnumerable()
            //    .Select(i => new
            //    {
            //        Issuer = i,
            //        IssuerHash = ComputeNameHash(i.IssuerName, hashOid)
            //    })
            //    .FirstOrDefault(ele => ele.IssuerHash.SequenceEqual(issuerNameHash))
            //    ?.Issuer;

            if (certIssuer == null)
                throw new InvalidOperationException("No Issuer matched with the provided name hash.");

            var endUserCert = _dbcontext.EndUserCertificates
                .SingleOrDefault(c =>
                    c.IssuerId == certIssuer.IssuerId &&
                    c.SerialNumber == requestedSerial
                );

            if (endUserCert == null)
                throw new InvalidOperationException("Certificate not found or not issued by this issuer");

            // --------------------------------------------

            var responderCertX509Net = new X509Certificate2(Encoding.ASCII.GetBytes(certIssuer.CertificatePem));
            //var responderCertX509Net = new X509Certificate2(Convert.FromBase64String(certIssuer.CertificatePem));
            Org.BouncyCastle.X509.X509Certificate bcResponderCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(responderCertX509Net.RawData);

            Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier bcHashAlgo = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                new Org.BouncyCastle.Asn1.DerObjectIdentifier(certId.HashAlgorithm.Algorithm.Value)
            );

            if (certId.HashAlgorithm.Parameters != null && certId.HashAlgorithm.Parameters.Length > 0)
            {
                bcHashAlgo = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                    new Org.BouncyCastle.Asn1.DerObjectIdentifier(certId.HashAlgorithm.Algorithm.Value),
                    Org.BouncyCastle.Asn1.DerNull.Instance // Defaulting to DerNull instance
                );
            }

            Org.BouncyCastle.Asn1.DerOctetString bcIssuerNameHash = new Org.BouncyCastle.Asn1.DerOctetString(issuerNameHash);
            Org.BouncyCastle.Asn1.DerOctetString bcIssuerKeyHash = new Org.BouncyCastle.Asn1.DerOctetString(issuerKeyHash);

            Org.BouncyCastle.Math.BigInteger serialBigInt = new Org.BouncyCastle.Math.BigInteger(requestedSerial, 16);
            Org.BouncyCastle.Asn1.DerInteger bcSerialNumber = new Org.BouncyCastle.Asn1.DerInteger(serialBigInt);

            Org.BouncyCastle.Asn1.Ocsp.CertID asn1CertId = new Org.BouncyCastle.Asn1.Ocsp.CertID(
                bcHashAlgo,
                bcIssuerNameHash,
                bcIssuerKeyHash,
                bcSerialNumber
            );

            Org.BouncyCastle.Ocsp.CertificateID certificateId = new Org.BouncyCastle.Ocsp.CertificateID(asn1CertId);

            Org.BouncyCastle.Ocsp.CertificateStatus certificateStatus;
            switch (endUserCert.Status.ToLower())
            {
                case "good":
                    certificateStatus = Org.BouncyCastle.Ocsp.CertificateStatus.Good; 
                    break;
                case "revoked":
                    certificateStatus = new Org.BouncyCastle.Ocsp.RevokedStatus(
                        endUserCert.RevocationDate ?? DateTime.UtcNow,
                        (int)(endUserCert.RevocationReason ?? 0)
                    );
                    break;
                case "unknown":
                    certificateStatus = new Org.BouncyCastle.Ocsp.UnknownStatus(); 
                    break;
                default:
                    throw new NotSupportedException($"Certificate status '{endUserCert.Status}' is not supported.");
            }

            Org.BouncyCastle.Crypto.AsymmetricKeyParameter bcPublicKey = bcResponderCert.GetPublicKey();
            Org.BouncyCastle.Ocsp.RespID bcResponderId = new Org.BouncyCastle.Ocsp.RespID(bcPublicKey);

            Org.BouncyCastle.Ocsp.BasicOcspRespGenerator basicOcspRespGenerator = new Org.BouncyCastle.Ocsp.BasicOcspRespGenerator(bcResponderId);

            basicOcspRespGenerator.AddResponse(certificateId, certificateStatus);
            

            if (incomingNonceExt != null)
            {
                var nonceOid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(incomingNonceExt.ExtnID.Value);
                var nonceValue = new Org.BouncyCastle.Asn1.DerOctetString(incomingNonceExt.ExtnValue);

                var responseNonceExtension = new Org.BouncyCastle.Asn1.X509.X509Extension(
                    false,
                    nonceValue
                );

                var extensions = new System.Collections.Generic.Dictionary<Org.BouncyCastle.Asn1.DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>
                {
                    { nonceOid, responseNonceExtension }
                };

                var responseExtensions = new Org.BouncyCastle.Asn1.X509.X509Extensions(extensions);

                basicOcspRespGenerator.SetResponseExtensions(responseExtensions);

            }

            AsymmetricKeyParameter signingKey;
            string signingAlgorithmOid; 

            using (var curKey = PrivateKeyLoader(certIssuer, "digital"))
            {
                if (curKey is RSA rsaKey)
                {
                    RSAParameters rsaParams = rsaKey.ExportParameters(true);

                    // Manually create the Bouncy Castle RsaPrivateCrtKeyParameters object.
                    signingKey = new Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters(
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.Modulus),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.Exponent),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.D),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.P),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.Q),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.DP),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.DQ),
                        new Org.BouncyCastle.Math.BigInteger(1, rsaParams.InverseQ)
                    );
                    signingAlgorithmOid = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;

                    //signingAlgorithmOid = "1.2.840.113549.1.1.11"; // SHA256 with RSA encryption
                }
                else if (curKey is ECDsa ecdsa)
                {
                    ECParameters ecParams = ecdsa.ExportParameters(true);
                    var oid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(ecParams.Curve.Oid.Value);

                    var x9Params = Org.BouncyCastle.Asn1.X9.X962NamedCurves.GetByOid(oid);
                    var domainParams = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(x9Params);
                    var d = new Org.BouncyCastle.Math.BigInteger(1, ecParams.D);

                    signingKey = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domainParams);

                    //byte[] ecPkcs8PrivateBytes = ecdsa.ExportECPrivateKey();

                    //signingKey = PrivateKeyFactory.CreateKey(ecPkcs8PrivateBytes);
                    signingAlgorithmOid = Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.ECDsaWithSha256.Id;

                    //signingAlgorithmOid = "1.2.840.10045.4.3.2"; // SHA256 with ECDSA
                }
                else
                {
                    throw new NotSupportedException("Unsupported key type for signing.");
                }

            }


            Org.BouncyCastle.Ocsp.BasicOcspResp basicOcspResponseBC = basicOcspRespGenerator.Generate(
                signingAlgorithmOid,
                signingKey,
                new Org.BouncyCastle.X509.X509Certificate[] { bcResponderCert },
                DateTime.UtcNow
            );

            return MapToResponseModel(basicOcspResponseBC, bcResponderCert);

            




        }


        private OcspResponseModel MapToResponseModel(Org.BouncyCastle.Ocsp.BasicOcspResp bcoResp, Org.BouncyCastle.X509.X509Certificate responderCert)
        {
            // 1. Map Certificates
            var certsList = bcoResp.GetCerts()?
                .Select(c => c.GetEncoded())
                .ToList() ?? new List<byte[]>();

            // 2. Map Single Responses
            var singleResponsesList = new List<Model.SingleResponse>();
            foreach (var singleResp in bcoResp.Responses)
            {
                var modelCertStatus = new Model.CertStatus();
                var bcStatus = singleResp.GetCertStatus();

                if (bcStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                {
                    modelCertStatus.Status = "good";
                }
                else if (bcStatus is Org.BouncyCastle.Ocsp.RevokedStatus revStatus)
                {
                    modelCertStatus.Status = "revoked";
                    modelCertStatus.RevocationTime = revStatus.RevocationTime;
                    if (revStatus.HasRevocationReason)
                    {
                        modelCertStatus.RevocationReason = revStatus.RevocationReason;
                    }
                }
                else
                {
                    modelCertStatus.Status = "unknown";
                }

                var certId = singleResp.GetCertID();

                singleResponsesList.Add(new Model.SingleResponse
                {
                    CertID = new Model.CertIDResp
                    {
                        HashAlgorithm = new Model.AlgorithmIdentifierResp { Algorithm = new Oid(certId.HashAlgOid) },
                        IssuerNameHash = singleResp.GetCertID().GetIssuerNameHash(),
                        IssuerKeyHash = singleResp.GetCertID().GetIssuerKeyHash(),
                        SerialNumber = singleResp.GetCertID().SerialNumber.ToString(16)
                    },
                    CertStatus = modelCertStatus,
                    ThisUpdate = singleResp.ThisUpdate,
                    NextUpdate = singleResp.ThisUpdate.AddHours(1), // Defaulting to 1 hour later
                });
            }

            // 3. Map ResponderID (extracting the key hash)
            byte[] responderKeyHash;
            using (var sha1 = System.Security.Cryptography.SHA1.Create())
            {
                //var spki = responderCert.GetSubjectPublicKeyInfo();

                //var publicKeyParams = responderCert.GetPublicKey();
                //var spki = Org.BouncyCastle.Security.PublicKeyFactory.CreateSubjectPublicKeyInfo(publicKeyParams);

                var spki = responderCert.SubjectPublicKeyInfo;
                responderKeyHash = sha1.ComputeHash(spki.PublicKeyData.GetBytes());
            }

            // 4. Build the final model
            return new OcspResponseModel
            {
                ResponseStatus = (int)Org.BouncyCastle.Asn1.Ocsp.OcspResponseStatus.Successful,
                ResponseBytes = new Model.ResponseBytes
                {
                    ResponseType = new Oid("1.3.6.1.5.5.7.48.1.1"), // id-pkix-ocsp-basic
                    BasicResponse = new Model.BasicOcspResponse
                    {
                        Signature = bcoResp.GetSignature(),
                        SignatureAlgorithm = new Model.AlgorithmIdentifierResp { Algorithm = new Oid(bcoResp.SignatureAlgOid) },
                        Certs = certsList,
                        TbsResponseData = new Model.TbsResponseData
                        {
                            Version = "v1",
                            ProducedAt = bcoResp.ProducedAt,
                            ResponderID = new Model.ResponderID { ByKey = responderKeyHash },
                            Responses = singleResponsesList,
                        }
                    }
                }
            };
        }




        private AsymmetricAlgorithm PrivateKeyLoader(Issuer issuer, string password)
        {
            byte[] encryptedPkcs8 = DecodePem(issuer.PrivateKeyEncrypted, "ENCRYPTED PRIVATE KEY");

            if (issuer.KeyType.Equals("RSA", StringComparison.OrdinalIgnoreCase))
            {
                var rsa = RSA.Create();
                rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out _);
                return rsa;
            }
            else if (issuer.KeyType.Equals("ECC", StringComparison.OrdinalIgnoreCase) ||
                    issuer.KeyType.Equals("EC", StringComparison.OrdinalIgnoreCase))
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out _);
                return ecdsa;
            }
            else
            {
                throw new NotSupportedException($"Key type {issuer.KeyType} is not supported.");
            }
        }

        private byte[] DecodePem(string pem, string label)
        {
            string header = $"-----BEGIN {label}-----";
            string footer = $"-----END {label}-----";

            int start = pem.IndexOf(header, StringComparison.Ordinal);
            if (start < 0) throw new FormatException($"PEM does not contain {header} header.");
            start += header.Length;

            int end = pem.IndexOf(footer, start, StringComparison.Ordinal);
            if (end < 0) throw new FormatException($"PEM does not contain {footer} footer.");

            string base64 = pem.Substring(start, end - start)
                .Replace("\r", string.Empty)
                .Replace("\n", string.Empty)
                .Trim();

            return Convert.FromBase64String(base64);
        }


        private byte[] ComputeNameHash(string issuerName, string hashAlgorithmOid)
        {
            var x500 = new X500DistinguishedName(issuerName);

            using HashAlgorithm hasher = hashAlgorithmOid switch
            {
                "SHA1" or "1.3.14.3.2.26" => SHA1.Create(),

                "SHA256" or "2.16.840.1.101.3.4.2.1" => SHA256.Create(),

                "SHA384" or "2.16.840.1.101.3.4.2.2" => SHA384.Create(),
                "SHA512" or "2.16.840.1.101.3.4.2.3" => SHA512.Create(),

                _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithmOid} is not supported.")
            };

            return hasher.ComputeHash(x500.RawData);
        }




    }
}


