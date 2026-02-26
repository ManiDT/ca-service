using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CA_Services.Data.Entities
{
    [Table("issuers")]
    public class Issuer
    {
        [Key]
        [Column("issuer_id")]
        public int IssuerId { get; set; }

        [Required]
        [Column("issuer_name")]
        [StringLength(255)]
        public string IssuerName { get; set; } = null!;

        [Required]
        [Column("key_type")]
        public string KeyType { get; set; } = null!;

        [Required]
        [Column("certificate_pem", TypeName="mediumtext")]
        public string CertificatePem { get; set; } = null!;

        [Required]
        [Column("private_key_encrypted", TypeName="mediumtext")]
        public string PrivateKeyEncrypted { get; set; } = null!;

        [Required]
        [Column("valid_from")]
        public DateTime ValidFrom { get; set; }

        [Required]
        [Column("valid_to")]
        public DateTime ValidTo { get; set; }

        [Required]
        [Column("ocsp_responder_name")]
        [StringLength(255)]
        public string OcspResponderName { get; set; } = null!;

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime UpdatedAt { get; set; }

        public virtual ICollection<EndUserCertificate> EndUserCertificates { get; set; } = new List<EndUserCertificate>();

    }
}
