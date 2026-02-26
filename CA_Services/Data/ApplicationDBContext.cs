using Microsoft.EntityFrameworkCore;
using CA_Services.Data.Entities;

namespace CA_Services.Data
{
    public class ApplicationDBContext : DbContext
    {
        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options) : base(options)
        {
        }
        public DbSet<Issuer> Issuers { get; set; } = null!;
        public DbSet<EndUserCertificate> EndUserCertificates { get; set; } = null!;
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<EndUserCertificate>()
                .HasIndex(e => new { e.IssuerId, e.SerialNumber })
                .IsUnique();

            modelBuilder.Entity<Issuer>()
                .Property(i => i.CreatedAt)
                .ValueGeneratedOnAdd()
                .HasDefaultValueSql("CURRENT_TIMESTAMP");

            modelBuilder.Entity<Issuer>()
                .Property(i => i.UpdatedAt)
                .ValueGeneratedOnAddOrUpdate()
                .HasDefaultValueSql("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");

            modelBuilder.Entity<EndUserCertificate>()
                .Property(e => e.CreatedAt)
                .ValueGeneratedOnAdd()
                .HasDefaultValueSql("CURRENT_TIMESTAMP");

            modelBuilder.Entity<EndUserCertificate>()
                .Property(e => e.UpdatedAt)
                .ValueGeneratedOnAddOrUpdate()
                .HasDefaultValueSql("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");

            modelBuilder.Entity<EndUserCertificate>()
                .HasOne(e => e.Issuer)
                .WithMany(i => i.EndUserCertificates)
                .HasForeignKey(e => e.IssuerId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
