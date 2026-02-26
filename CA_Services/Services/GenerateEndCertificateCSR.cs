using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CA_Services.Data;
using CA_Services.Data.Entities;
using CA_Services.Model;
using CA_Services.Services.Interfaces;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace CA_Services.Services
{
    public class GenerateEndCertificateCSR : IGenerateEndCertificateCSR
    {
        private readonly ApplicationDBContext _dbcontext;
        public ILogger<GenerateEndCertificateCSR> _logger { get; set; }

        private readonly string issuerPrivateKeyPassword = "digital";   // hard coded

        private const string crlBaseUrlRSA = "https://localhost:8443/rsa_ca/crl/issuerRSA.crl";
        private const string crlBaseUrlECC = "https://localhost:8443/ecc_ca/crl/issuerECC.crl";

        public GenerateEndCertificateCSR(ApplicationDBContext dbcontext, ILogger<GenerateEndCertificateCSR> logger)
        {
            _dbcontext = dbcontext;
            _logger = logger;
        }

        public GenerateEndUserCertCSRResponse GenerateEndCertCSR(GenerateEndCertCSRRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request?.CsrBase64))
                {
                    _logger.LogError("Invalid CSR");
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = "CSR data is missing." };
                }
                Console.WriteLine("Request : " + JsonSerializer.Serialize(request));
                // --- 1. Decode and Parse the CSR ---
                CertificateRequest certRequest;
                string encryptionAlgorithm;

                try
                {
                    string pemString = Encoding.UTF8.GetString(Convert.FromBase64String(request.CsrBase64));

                    byte[] csrDer = DecodePem(pemString, "CERTIFICATE REQUEST");

                    var pkcs10Req = new Pkcs10CertificationRequest(csrDer);

                    if (!pkcs10Req.Verify())
                    {
                        _logger.LogError("CSR signature validation failed.");
                        return new GenerateEndUserCertCSRResponse { Success = false, Message = "CSR signature validation failed." };
                    }

                    var subjectNameBouncy = pkcs10Req.GetCertificationRequestInfo().Subject;
                    var publicKeyBouncy = pkcs10Req.GetPublicKey();

                    var subjectNameNet = new X500DistinguishedName(subjectNameBouncy.ToString());

                    if (publicKeyBouncy is RsaKeyParameters)
                    {
                        _logger.LogInformation("RSA Cert Request : true");
                        encryptionAlgorithm = "RSA";
                        var rsa = RSA.Create(DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyBouncy));
                        certRequest = new CertificateRequest(subjectNameNet, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                    else if (publicKeyBouncy is ECPublicKeyParameters)
                    {
                        encryptionAlgorithm = "ECC";
                        _logger.LogInformation("RSA Cert Request : false");
                        var ecParams = ToECParameters((ECPublicKeyParameters)publicKeyBouncy);
                        var ecdsa = ECDsa.Create(ecParams);

                        certRequest = new CertificateRequest(subjectNameNet, ecdsa, HashAlgorithmName.SHA256);
                    }
                    else
                    {
                        _logger.LogError("Unsupported public key algorithm in CSR.");
                        return new GenerateEndUserCertCSRResponse { Success = false, Message = "Unsupported public key algorithm in CSR." };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Invalid CSR format or content : " + ex.Message);
                    Console.WriteLine($"Error parsing CSR: {ex.Message}");
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = "Invalid CSR format or content." };
                }



                var isRsa = encryptionAlgorithm == "RSA";

                // --- 3. Fetch the Correct Issuer from DB ---
                Issuer issuer;
                try
                {
                    issuer = _dbcontext.Issuers.FirstOrDefault(ele => ele.KeyType == encryptionAlgorithm);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error retrieving issuer: {ex.Message}.");
                    Console.WriteLine($"Error retrieving issuer: {ex.Message}");
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = "Could not connect to the database to find an issuer." };
                }

                if (issuer == null)
                {
                    _logger.LogError($"No issuer found for {encryptionAlgorithm}.");
                    Console.WriteLine($"No issuer found for {encryptionAlgorithm}.");
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = $"No active issuer found for key type {encryptionAlgorithm}." };
                }

                // --- 4. Load Issuer Certificate and Private Key ---
                byte[] issuerCertDer = DecodePem(issuer.CertificatePem, "CERTIFICATE");
                byte[] issuerKeyDer = DecodePem(issuer.PrivateKeyEncrypted, $"{(isRsa ? "ENCRYPTED " : "")}PRIVATE KEY");

                _logger.LogInformation("Issuer Cert and Key Decoded");

                AsymmetricAlgorithm issuerKey = isRsa
                    ? ImportRsaPrivateKey(issuerKeyDer, issuerPrivateKeyPassword)
                    : ImportEccPrivateKey(issuerKeyDer, null);

                var issuerCertOnly = new X509Certificate2(issuerCertDer);
                var issuerCertWithKey = isRsa
                    ? issuerCertOnly.CopyWithPrivateKey((RSA)issuerKey)
                    : issuerCertOnly.CopyWithPrivateKey((ECDsa)issuerKey);

                _logger.LogInformation("Issuer Cert Loaded");

                // --- 5. Add Required Extensions to the Certificate Request ---
                // Basic Constraints: End-entity certificate
                /*certRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));*/

                // Key Usage: (Digital Signature, Non-Repudiation, Key Encipherment, Key Agreement)
                var keyUsages = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyAgreement;
                certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages, true)); // Marked as critical

                _logger.LogInformation("Key Usages Added");

                // Enhanced Key Usage (Example: Client Authentication)
                certRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));

                // CRL Distribution Point
                /*string crlBaseUrl = isRsa ? crlBaseUrlRSA : crlBaseUrlECC;
                if (!string.IsNullOrEmpty(crlBaseUrl))
                {
                    certRequest.CertificateExtensions.Add(CreateCrlDistributionPoint(crlBaseUrl));
                }*/

                // --- 6. Create and Sign the Certificate ---

                // byte[] serialNumber = Guid.NewGuid().ToByteArray();
                if (string.IsNullOrEmpty(request.KeyId))
                {
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = "Invalid KeyId format for serial number." };
                }

                _logger.LogInformation("Serial Number : " + request.KeyId);

                byte[] serialNumber = Encoding.UTF8.GetBytes(request.KeyId.ToString());
                DateTime notBefore = DateTime.UtcNow.AddHours(-3.5); // Adding a small buffer for clock skew
                DateTime notAfter = DateTime.UtcNow.AddYears(1);

                X509Certificate2 endUserCert = certRequest.Create(
                    issuerCertWithKey,
                    notBefore,
                    notAfter,
                    serialNumber
                );

                _logger.LogInformation("End User Cert Created");

                // --- 7. Save Certificate Metadata to Database ---
                var endUserEntity = new EndUserCertificate
                {
                    IssuerId = issuer.IssuerId,
                    SerialNumber = BitConverter.ToString(serialNumber).Replace("-", ""),
                    SubjectName = endUserCert.Subject,
                    CertificatePem = Convert.ToBase64String(endUserCert.Export(X509ContentType.Cert)),
                    PrivateKeyPem = null, // The private key is not available as it was part of the CSR
                    KeyType = encryptionAlgorithm,
                    Status = "good"
                };

                try
                {
                    //_dbcontext.EndUserCertificates.Add(endUserEntity);
                    //_dbcontext.SaveChanges();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error saving end user certificate: {ex.Message}.");
                    Console.WriteLine($"Error saving end user certificate: {ex.Message}");
                    return new GenerateEndUserCertCSRResponse { Success = false, Message = "Failed to save certificate record." };
                }
                Console.WriteLine("Before exporting cert true");
                try
                {
                    var rawCert = endUserCert.Export(X509ContentType.Cert);
                    var pemCert = new StringBuilder();
                    pemCert.AppendLine("-----BEGIN CERTIFICATE-----");
                    pemCert.AppendLine(Convert.ToBase64String(rawCert, Base64FormattingOptions.InsertLineBreaks));
                    pemCert.AppendLine("-----END CERTIFICATE-----");
                    var response = new GenerateEndUserCertCSRResponse
                    {
                        Success = true,
                        Message = "Certificate generated successfully.",
                        Result = new GenerateEndUserCertCSRResult
                        {
                            // Export the raw certificate in Base64 format
                            //Cert = Convert.ToBase64String(endUserCert.Export(X509ContentType.Cert))                    
                            Cert = pemCert.ToString()
                        }
                    };
                    Console.WriteLine(response.ToString());
                    _logger.LogInformation("Response : " + response.ToString());
                    Console.WriteLine("Response : " + JsonSerializer.Serialize(response));
                    return response;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex.Message);
                    Console.WriteLine(ex.Message);
                    return new GenerateEndUserCertCSRResponse
                    {
                        Success = false,
                        Message = ex.Message,
                        Result = null
                    };
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("Error : " + e.Message);
                _logger.LogError(e.Message);
                return null;
            }

        }


        private static ECParameters ToECParameters(ECPublicKeyParameters ecPublicKey)
        {
            var q = ecPublicKey.Q.Normalize();
            var curve = ecPublicKey.Parameters.Curve;

            // Use the curve OID directly from the parameters
            var oid = ecPublicKey.PublicKeyParamSet;
            if (oid == null)
                throw new NotSupportedException("Unsupported or unknown curve");

            string curveOid = oid.Id;

            var parameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = q.AffineXCoord.GetEncoded(),
                    Y = q.AffineYCoord.GetEncoded()
                },
                Curve = ECCurve.CreateFromOid(new Oid(curveOid))
            };

            return parameters;
        }


        private static byte[] DecodePem(string pem, string label)
        {
            string header = $"-----BEGIN {label}-----";
            string footer = $"-----END {label}-----";

            int start = pem.IndexOf(header, StringComparison.Ordinal);
            if (start < 0) throw new ArgumentException($"Missing header for {label}");
            start += header.Length;

            int end = pem.IndexOf(footer, start, StringComparison.Ordinal);
            if (end < 0) throw new ArgumentException($"Missing footer for {label}");

            var base64Lines = pem.Substring(start, end - start)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(line =>
                    !line.StartsWith("Proc-Type:", StringComparison.OrdinalIgnoreCase) &&
                    !line.StartsWith("DEK-Info:", StringComparison.OrdinalIgnoreCase))
                .ToArray();

            string base64 = string.Concat(base64Lines);
            return Convert.FromBase64String(base64);

        }


        // Import RSA Private Key from DER format
        private static RSA ImportRsaPrivateKey(byte[] keyDer, string password)
        {
            var rsa = RSA.Create();

            if (!string.IsNullOrEmpty(password))
            {
                rsa.ImportEncryptedPkcs8PrivateKey(password, keyDer, out _);
            }
            else
            {
                rsa.ImportPkcs8PrivateKey(keyDer, out _);
            }

            return rsa;
        }

        // Import ECC Private Key from DER format
        private static ECDsa ImportEccPrivateKey(byte[] keyDer, string password)
        {
            ECDsa ecdsa = ECDsa.Create();

            if (!string.IsNullOrEmpty(password))
            {
                ecdsa.ImportEncryptedPkcs8PrivateKey(
                    password: "digital".AsSpan(),
                    keyDer,
                    out _
                );
            }
            else
            {
                ecdsa.ImportPkcs8PrivateKey(keyDer, out _);
            }
            return ecdsa;
        }


        // CRL Distribution Point Extension
        private static X509Extension CreateCrlDistributionPoint(string crlUrl)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();  // CRLDistributionPoints SEQUENCE
            {
                writer.PushSequence();  // DistributionPoint SEQUENCE
                {

                    writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                    {
                        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        {
                            writer.PushSequence();
                            {
                                writer.WriteCharacterString(UniversalTagNumber.IA5String, crlUrl, new Asn1Tag(TagClass.ContextSpecific, 6));
                            }
                            writer.PopSequence();
                        }
                        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                    }
                    writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                }
                writer.PopSequence();
            }
            writer.PopSequence();

            byte[] crlDpRawData = writer.Encode();

            X509Extension crlDistPointExtension = new X509Extension(
                oid: "2.5.29.31",
                rawData: crlDpRawData,
                critical: false
            );

            return crlDistPointExtension;
        }


    }
}
