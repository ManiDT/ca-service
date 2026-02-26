using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CA_Services.Data;
using CA_Services.Data.Entities;
using CA_Services.Model;
using CA_Services.Services.Interfaces;

namespace CA_Services.Services
{

    public class GenerateEndCertificate : IGenerateEndCertificate
    {
        private readonly ApplicationDBContext _dbcontext;
        
        private readonly string issuerRSAPfxPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\issuerRSA.pfx");
        private readonly string issuerECCPfxPath = Path.Combine(Directory.GetCurrentDirectory(), ".\\Resources\\Certificates\\issuerECC.pfx");

        private readonly string issuerPfxPassword = "issuer";        // hard coded
        private readonly string endUserPfxPassword = "enduser";        // hard coded
        private readonly string issuerPrivateKeyPassword = "digital";   // hard coded

        private const string crlBaseUrlRSA = "https://localhost:8443/rsa_ca/crl/issuerRSA.crl";
        private const string crlBaseUrlECC = "https://localhost:8443/ecc_ca/crl/issuerECC.crl";
    
        public GenerateEndCertificate(ApplicationDBContext dbcontext)
        {
            _dbcontext = dbcontext;
        }

        public byte[] GenerateEndCert(GenerateEndCertRequest request)
        {
            string encryptionAlgorithm = request.EncryptionAlgorithm;
            
            bool isRsa = encryptionAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase);
            bool isEcc = encryptionAlgorithm.Equals("ECC", StringComparison.OrdinalIgnoreCase);

            if (!isRsa && !isEcc)
            {
                Console.WriteLine("Invalid encryption algorithm specified.");
                return null;
            }

            string crlBaseUrl = isRsa ? crlBaseUrlRSA : crlBaseUrlECC;

            // Move issuer declaration outside the try-catch block
            Issuer issuer = null;
            try
            {
                issuer = _dbcontext.Issuers
                    .FirstOrDefault(ele => ele.KeyType == encryptionAlgorithm);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving issuer: {ex.Message}");
                return null;
            }

            if (issuer == null)
            {
                Console.WriteLine($"No issuer found for {encryptionAlgorithm}.");
                return null;
            }

            byte[] issuerCertDer = DecodePem(issuer.CertificatePem, "CERTIFICATE");
            byte[] issuerKeyDer = DecodePem(issuer.PrivateKeyEncrypted, $"{(isRsa ? "ENCRYPTED " : "")}PRIVATE KEY");

            AsymmetricAlgorithm issuerKey = isRsa 
                ? ImportRsaPrivateKey(issuerKeyDer, issuerPrivateKeyPassword) 
                : ImportEccPrivateKey(issuerKeyDer, issuerPrivateKeyPassword);

            var issuerCertOnly = new X509Certificate2(issuerCertDer);
            var issuerCert = isRsa 
                ? issuerCertOnly.CopyWithPrivateKey((RSA)issuerKey) 
                : issuerCertOnly.CopyWithPrivateKey((ECDsa)issuerKey);

            AsymmetricAlgorithm endUserKey = isRsa 
                ? RSA.Create(2048) 
                : ECDsa.Create(ECCurve.NamedCurves.nistP256);

            string endUserSubject = isRsa 
                ? "CN=EndUserRSA O=RSAOrganization C=IN" 
                : "CN=EndUserECC O=ECCOrganization C=IN";

            CertificateRequest certRequest = isRsa 
                ? new CertificateRequest(new X500DistinguishedName(endUserSubject), (RSA)endUserKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) 
                : new CertificateRequest(new X500DistinguishedName(endUserSubject), (ECDsa)endUserKey, HashAlgorithmName.SHA256);


            // Add extensions
            certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            certRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false )
            );

            if (!string.IsNullOrEmpty(crlBaseUrl))
            {
                certRequest.CertificateExtensions.Add(CreateCrlDistributionPoint(crlBaseUrl));
            }

            byte[] serialNumber = Guid.NewGuid().ToByteArray();
            DateTime notBefore = DateTime.UtcNow.AddMinutes(-5);
            DateTime notAfter = DateTime.UtcNow.AddYears(1);

            var endUserCert = certRequest.Create(
                issuerCert,
                notBefore,
                notAfter,
                serialNumber
            );

            X509Certificate2 endUserWithKey = isRsa 
                ? endUserCert.CopyWithPrivateKey((RSA)endUserKey) 
                : endUserCert.CopyWithPrivateKey((ECDsa)endUserKey);

            var endUserEntity = new EndUserCertificate
            {
                IssuerId = issuer.IssuerId,
                SerialNumber = BitConverter.ToString(serialNumber).Replace("-", ""),
                SubjectName = endUserSubject,
                CertificatePem = Convert.ToBase64String(endUserWithKey.Export(X509ContentType.Cert)),
                PrivateKeyPem = Convert.ToBase64String(endUserKey.ExportPkcs8PrivateKey()),
                KeyType = encryptionAlgorithm,
                Status = "good"
            };

            try
            {
                _dbcontext.EndUserCertificates.Add(endUserEntity);
                _dbcontext.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving end user certificate: {ex.Message}");
                return null;
            }

            byte[] endUserPfxBytes = endUserWithKey.Export(X509ContentType.Pkcs12, endUserPfxPassword);
            return endUserPfxBytes;



        }










        //public byte[] GenerateEndCert (GenerateEndCertRequest request)
        //{
        //    string encryptionAlgorithm = request.EncryptionAlgorithm;

        //    DateTime notBefore = DateTime.UtcNow.AddMinutes(-5);
        //    DateTime notAfter = DateTime.UtcNow.AddYears(1);

        //    //string selectedIssuerPfxPath;
        //    //string selectedIssuerPfxPassword;

        //    X509Certificate2 issuerCert = null;
        //    AsymmetricAlgorithm endUserKeyPair = null;
        //    string endUserCertSubject = "CN=EndUser O=Organization C=IN";
        //    HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
        //    string selectedCrlUrl = "";

        //    var issuer = _dbcontext.Issuers
        //        .FirstOrDefault(ele => ele.KeyType == encryptionAlgorithm);

        //    //issuerCert = new X509Certificate2(Convert.FromBase64String(issuer.CertificatePem)) ;
        //    byte[] certDer = DecodePem(issuer.CertificatePem, "CERTIFICATE");
        //    byte[] keyDer = DecodePem(issuer.PrivateKeyEncrypted, "PRIVATE");

        //    RSA issuerRsa = RSA.Create();


        //    try
        //    {
        //        if (encryptionAlgorithm == "RSA")
        //        {
        //            //selectedIssuerPfxPath = issuerRSAPfxPath;
        //            //selectedIssuerPfxPassword = issuerPfxPassword;
        //            endUserCertSubject = "CN=EndUserRSA O=RSAOrganization C=IN";
        //            selectedCrlUrl = crlBaseUrlRSA;



        //            //issuerCert = new X509Certificate2(selectedIssuerPfxPath, 
        //            //                selectedIssuerPfxPassword, 
        //            //                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        //            endUserKeyPair = RSA.Create(2048);

        //        } 
        //        else if (encryptionAlgorithm == "ECC")
        //        {
        //            //selectedIssuerPfxPath = issuerECCPfxPath;
        //            //selectedIssuerPfxPassword = issuerPfxPassword;
        //            endUserCertSubject = "CN=EndUserECC O=ECCOrganization C=IN";
        //            selectedCrlUrl = crlBaseUrlECC;


        //            //issuerCert = new X509Certificate2(selectedIssuerPfxPath,
        //            //                selectedIssuerPfxPassword,
        //            //                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        //            endUserKeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        //        } 
        //        else
        //        {
        //            Console.WriteLine("Invalid encryption algorithm specified.");
        //            //return "Invalid encryption algorithm specified.";
        //            return null;
        //        }

        //        if (issuerCert == null)
        //        {
        //            Console.WriteLine($"Failed to load issuer certificate for {encryptionAlgorithm}");
        //            return null;
        //        }

        //        if (!issuerCert.HasPrivateKey)
        //        {
        //            Console.WriteLine($"{encryptionAlgorithm}Issuer certificate does not have a private key.");
        //            return null;
        //        }

        //        RSASignaturePadding rSASignaturePadding = null;
        //        if (encryptionAlgorithm == "RSA")
        //        {
        //            rSASignaturePadding = RSASignaturePadding.Pkcs1;
        //        }

        //        CertificateRequest certRequest;

        //        if (encryptionAlgorithm == "RSA")
        //        {
        //            certRequest = new CertificateRequest(
        //                new X500DistinguishedName(endUserCertSubject),
        //                (RSA)endUserKeyPair,
        //                hashAlgorithmName,
        //                RSASignaturePadding.Pkcs1
        //            );
        //        }
        //        else 
        //        {
        //            certRequest = new CertificateRequest(
        //                new X500DistinguishedName(endUserCertSubject),
        //                (ECDsa)endUserKeyPair,
        //                hashAlgorithmName
        //            );
        //        }

        //        // Basic Constraints
        //        certRequest.CertificateExtensions.Add(
        //            new X509BasicConstraintsExtension(
        //                certificateAuthority: false,
        //                hasPathLengthConstraint: false,
        //                pathLengthConstraint: 0,
        //                critical: true
        //            )
        //        );

        //        // Key Usage
        //        certRequest.CertificateExtensions.Add(
        //            new X509KeyUsageExtension(
        //                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
        //                critical: true
        //            )
        //        );

        //        // Enhanced Key Usage (Client Authentication OID: 1.3.6.1.5.5.7.3.2)
        //        certRequest.CertificateExtensions.Add(
        //            new X509EnhancedKeyUsageExtension(
        //                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },     // Client Authentication
        //                critical: false)
        //        );

        //        // Add CRL Distribution Point Extension
        //        if (!string.IsNullOrEmpty(selectedCrlUrl))
        //        {
        //            certRequest.CertificateExtensions.Add(
        //                CreateCrlDistributionPoint(selectedCrlUrl)
        //            );
        //        }

        //        byte[] serialNumber = Guid.NewGuid().ToByteArray();

        //        X509Certificate2 endUserCert = certRequest.Create(
        //            issuerCert,
        //            notBefore,
        //            notAfter,
        //            serialNumber
        //        );


        //        // Insert into database

        //        EndUserCertificate endUserEntity = new EndUserCertificate
        //        {
        //            IssuerId = issuer.IssuerId,
        //            SerialNumber = BitConverter.ToString(serialNumber).Replace("-", ""),
        //            SubjectName = endUserCertSubject,
        //            CertificatePem = Convert.ToBase64String(endUserCert.Export(X509ContentType.Cert)),
        //            PrivateKeyPem = Convert.ToBase64String(endUserKeyPair.ExportPkcs8PrivateKey()),
        //            KeyType = encryptionAlgorithm,
        //            Status = "good"
        //        };

        //        _dbcontext.EndUserCertificates.Add(endUserEntity);
        //        _dbcontext.SaveChanges();












        //        X509Certificate2 endUserCertWithPrivateKey;

        //        if (encryptionAlgorithm == "RSA")
        //        {
        //            endUserCertWithPrivateKey = endUserCert.CopyWithPrivateKey((RSA)endUserKeyPair);
        //        }
        //        else
        //        {
        //            endUserCertWithPrivateKey = endUserCert.CopyWithPrivateKey((ECDsa)endUserKeyPair);
        //            //endUserCertWithPrivateKey = endUserCert.CopyWithPrivateKey(endUserKeyPair);
        //        }

        //        byte[] endUserPfxBytes = endUserCertWithPrivateKey.Export(X509ContentType.Pkcs12, endUserPfxPassword);

        //        return endUserPfxBytes;








        //    }
        //    catch (FileNotFoundException ex)
        //    {
        //        Console.WriteLine($"Error: Issuer PFX file not found. Details: {ex.Message}");
        //        return null;
        //    }
        //    catch (CryptographicException ex)
        //    {
        //        Console.WriteLine($"A cryptographic error occurred: {ex.Message}");
        //        if (ex.InnerException != null) Console.WriteLine($"Inner: {ex.InnerException.Message}");
        //        Console.WriteLine("Ensure the PFX password is correct and the PFX file is valid.");
        //        return null;
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"An unexpected error occurred: {ex.Message}");
        //        return null;
        //    }
        //    finally
        //    {
        //        // Dispose of cryptographic objects to release resources
        //        issuerCert?.Dispose();
        //        endUserKeyPair?.Dispose();

        //    }

        //}











        // Convert PEM to raw DER bytes
        
        private static byte[] DecodePem(string pem, string label)
        {
            string header = $"-----BEGIN {label}-----";
            string footer = $"-----END {label}-----";

            int start = pem.IndexOf(header, StringComparison.Ordinal);
            if (start < 0) throw new ArgumentException($"Missing header for {label}");
            start += header.Length;

            int end = pem.IndexOf(footer, start, StringComparison.Ordinal);
            if (end < 0) throw new ArgumentException($"Missing footer for {label}");

            // Grab the inner block, split into lines, drop empty lines and any
            // line that isn’t pure Base‑64 (i.e. the Proc‑Type/DEK‑Info lines).
            var base64Lines = pem.Substring(start, end - start)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(line =>
                    // skip any metadata lines
                    !line.StartsWith("Proc-Type:", StringComparison.OrdinalIgnoreCase) &&
                    !line.StartsWith("DEK-Info:", StringComparison.OrdinalIgnoreCase))
                .ToArray();

            string base64 = string.Concat(base64Lines);
            return Convert.FromBase64String(base64);



            //string header = $"-----BEGIN {beginLabel}-----";
            //string footer = $"-----END {beginLabel}-----";
            //int start = pem.IndexOf(header, StringComparison.Ordinal) + header.Length;
            //int end = pem.IndexOf(footer, start, StringComparison.Ordinal);

            //string base64 = pem.Substring(start, end - start).Replace("\r", "").Replace("\n", "").Trim();
            //return Convert.FromBase64String(base64);
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
