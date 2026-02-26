# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER root
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

# Install required libraries
RUN apt-get update && apt-get install -y \
    libxrender1 libfontconfig1 libxext6 libjpeg62-turbo libpng16-16 \
    && rm -rf /var/lib/apt/lists/*

# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["/CA_Services/CA_Services.csproj", "CA_Services/"]
RUN dotnet restore "./CA_Services/CA_Services.csproj"
COPY . .
WORKDIR "/src/CA_Services"
RUN dotnet build "./CA_Services.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./CA_Services.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Copy necessary shared libraries
COPY ./libs/* ./

# Set ASP.NET Core environment variables
ENV ASPNETCORE_ENVIRONMENT=Staging
ENV ASPNETCORE_URLS="http://+:3000"

ENTRYPOINT ["dotnet", "CA_Services.dll"]