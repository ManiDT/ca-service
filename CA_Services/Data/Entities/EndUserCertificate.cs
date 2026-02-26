using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace CA_Services.Data.Entities
{
    [Table("end_user_certificates")]
    public class EndUserCertificate
    {
        [Key]
        [Column("cert_id")]
        public long CertId { get; set; }

        [Required]
        [Column("issuer_id")]
        public int IssuerId { get; set; }

        [Required]
        [Column("serial_number")]
        [StringLength(64)]
        public string SerialNumber { get; set; } = null!;

        [Required]
        [Column("subject_name")]
        [StringLength(255)]
        public string SubjectName { get; set; } = null!;

        [Required]
        [Column("certificate_pem", TypeName = "mediumtext")]
        public string CertificatePem { get; set; } = null!;

        [Required]
        [Column("private_key_pem", TypeName = "mediumtext")]
        public string PrivateKeyPem { get; set; } = null!;

        [Required]
        [Column("key_type")]
        public string KeyType { get; set; } = null!;

        [Required]
        [Column("status")]
        public string Status { get; set; } = "unknown";

        [Column("revocation_date")]
        public DateTime? RevocationDate { get; set; }

        [Column("revocation_reason")]
        [StringLength(64)]
        public int? RevocationReason { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime UpdatedAt { get; set; }

        [ForeignKey(nameof(IssuerId))]
        public virtual Issuer Issuer { get; set; } = null!;


    }
}
