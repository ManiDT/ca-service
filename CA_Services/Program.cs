using CA_Services.Services;
using CA_Services.Services.Interfaces;
using CA_Services.Data;
using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using NLog.Web;
using DSS.Infrastructure.Services;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var dbType = builder.Configuration.GetConnectionString("dbType");

//var enc = SecureStringHelper.Encrypt(connectionString);
SecureStringHelper.Initialize(builder.Configuration);
var enc = SecureStringHelper.Decrypt("yo2AOjazHGsU+5uGmyxqbrfDubtqXP6Pl3qGWHvvAww=");
var enc2 = SecureStringHelper.Decrypt("LXSwiDd3IrecgdXfkPAdPRT5S4Sqe06R9u/f6WuapnI=");

// Add services to the container.

if (dbType == "sql")
{
    builder.Services.AddDbContext<ApplicationDBContext>(async options =>
        options.UseMySql(
            await SecureStringHelper.Decrypt(connectionString),
            //connectionString,
            new MySqlServerVersion("8.0.31-mysql")
        )
    );
}
else if (dbType == "postgres")
{

    builder.Services.AddDbContext<ApplicationDBContext>(async options =>
        options.UseNpgsql(
            await SecureStringHelper.Decrypt(connectionString)
        )
    );
}

builder.Services.AddControllers();
builder.Host.UseNLog();
builder.Services.AddScoped<IGetRootCertificate, GetRootCertificate>();
builder.Services.AddScoped<IGetIssuerCertificate, GetIssuerCertificate>();
builder.Services.AddScoped<IGenerateEndCertificate, GenerateEndCertificate>();
builder.Services.AddScoped<IGenerateEndCertificateCSR, GenerateEndCertificateCSR>();
builder.Services.AddScoped<IGenerateOcspResp, GenerateOcspResp>();
builder.Services.AddScoped<IRevokeCertificate, RevokeCertificateByRequest>();
builder.Services.AddScoped<ICheckCertificateDetails, CheckCertificateDetails>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddLogging();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
