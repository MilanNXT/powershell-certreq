class venafi_apikey {
    [string]$APIKey
    [Datetime]$ValidUntil
}
class venafi_cred {
    hidden [byte[]]$key = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    hidden [string]$encUsername = '76492d1116743f0423413b16050*'
    hidden [string]$encPassword = '76492d1116743f0423413b16050*'
    venafi_cred() {}
    [string] username() {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $this.EncUsername -Key $this.key)))
    }
    [string] password() {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $this.EncPassword -Key $this.key)))
    }
}

class venafi_cert {
    hidden [int]$MaxRetry = 3
    hidden [int]$RetryTimeout = 10
    hidden [string]$VenafiUri = "https://chome.cz/vedsdk"
    hidden [string]$MandatorySubject = "OU=Test,O=Home,L=Prague,S=Prg,C=cz,E=devops@musec.sk"
    hidden [string]$Policy = "\VED\Policy\SDKTest"
    hidden [int]$KeySize = 2048
    hidden [string[]]$SanNames
    hidden [string]$FriendlyName
    hidden [venafi_cred]$Cred = [venafi_cred]::new()
    hidden [venafi_apikey]$Api = [venafi_apikey]::new()
    hidden [string]$CertificateDN
    hidden [System.Security.Cryptography.RSACryptoServiceProvider]$KeyPair
    hidden [System.Security.Cryptography.X509Certificates.X509Certificate2]$SelfSignedCert
    hidden [string]$SelfSignedCsr
    hidden [byte[]]$SignedCsr

    hidden init() {
        $this.FriendlyName = "azs-$((New-Guid).Guid.Replace('-','').toUpperInvariant())"
    }
    hidden init([string]$FriendlyName){
        $this.init()
        if (![string]::IsNullOrEmpty($FriendlyName)) {
            $this.FriendlyName = "azs-$FriendlyName"
        }
    }
    venafi_cert(){
        $this.init()
    }
    venafi_cert([string]$FriendlyName) {
        $this.init($FriendlyName)
    }
    [bool] authenticate() {
        $resp = $false
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # login
        $header = @{ "content-type" = "application/json" }
        $body = @{ Username = "$($this.Cred.username())"; Password = "$($this.Cred.password())" } | ConvertTo-Json -Compress
        try {
            $response = Invoke-WebRequest -Method POST -Uri "$($this.venafiuri)/Authorize/" -Headers $header -Body $body
            $this.api = ConvertFrom-Json -InputObject $response.Content
            $resp = ($response.StatusCode -eq 200)
        } catch {
        }
        return $resp
    }

    [bool] validate() {
        $resp = $false
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $header = @{
            "content-type" = "application/json" ;
            "X-Venafi-Api-Key" = $($this.api.ApiKey)
        }
        try {
            $response = Invoke-WebRequest -Method GET -Uri "$($this.venafiuri)/Authorize/checkvalid" -Headers $header
            $this.api = ConvertFrom-Json -InputObject $response.Content
            $resp = ($response.StatusCode -eq 200)
        } catch {}
        return $resp
    }
    [void] generate_keypair() {
        $cspParams = [System.Security.Cryptography.CspParameters]::new()
        $cspParams.ProviderType = 12 # Microsoft RSA SChannel Cryptographic Provider
        $cspParams.KeyNumber = 1     # AT_KEYEXCHANGE
        $cspParams.KeyContainerName = [System.Guid]::NewGuid().Guid.toUpperInvariant()
        $cspParams.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
        $this.KeyPair = [System.Security.Cryptography.RSACryptoServiceProvider]::new($this.KeySize,$cspParams)
        $this.KeyPair.PersistKeyInCsp = $true
        Write-Host "new Keypair generated..."
    }
    [bool] request_casigned_csr() {
        $resp = $false
        if (!$this.validate()) {
            if (!$this.authenticate()) { write-host "authentication error" }
        }
        $header = @{
            "content-type" = "application/json" ;
            "X-Venafi-Api-Key" = $($this.api.ApiKey)
        }
        $body = @{
            ObjectName = "$($this.FriendlyName)"
            PolicyDN = "$($this.Policy)"
            PKCS10 = "$($this.SelfSignedCsr)"
        } | ConvertTo-Json -Compress
        $retry = 1
        Write-Host "Submitting selfsigned certificate [$($this.SelfSignedCert.Thumbprint)] to CA"
        while (($retry -le $this.maxRetry) -and (!$resp)) {
            try {
                $response = Invoke-WebRequest -Method POST -Uri "$($this.VenafiUri)/Certificates/Request" -Headers $header -Body $body
                $this.CertificateDN = (ConvertFrom-Json -InputObject $response.Content).CertificateDN
                $resp = ($response.StatusCode -eq 200)
            } catch { Write-Host $_ }
            if (!$resp) { Start-Sleep -Seconds $this.RetryTimeout }
            $retry += 1
        }
        if (!$resp) { write-host "error submitting CSR" } else { Write-Host "Certificate submitted to CA"}
        return $resp
    }
    [bool] download_casigned_csr() {
        if (!$this.validate()) {
            $this.authenticate()
        }
        $header = @{
            "content-type" = "application/json"
            "X-Venafi-Api-Key" = $($this.api.APIKey)
        }
        $param = "?CertificateDN=$($this.CertificateDN)&Format=Base64"
        $retry = 0
        $resp = $false
        Write-Host "downloading signed certificate..."
        $s_csr = [System.String]::Empty
        while (($retry -le $this.maxRetry) -and (!$resp)) {
            try {
                if (!$this.validate()) {
                    if (!$this.authenticate()) { write-host "authentication error" }
                }
                $response = Invoke-WebRequest -Method GET -Uri "$($this.venafiuri)/Certificates/Retrieve$param" -Headers $header
                $this.SignedCsr = $response.Content
                $resp = $response.StatusCode -eq 200
            }
            catch {}
            if (!$resp) { Start-Sleep -Seconds $this.RetryTimeout }
            $retry += 1
        }
        if (!$resp) {  
            Write-Host "can not retrieve signed CSR" 
        } else {
            Write-Host "Signed certificate [$($this.SelfSignedCert.Thumbprint)] downloaded from CA"
        }
        return $resp
    }
    [void] generate_selfsigned_csr() {
        $this.generate_keypair()
        $subject = "CN=$($this.SanNames[0]),$($this.MandatorySubject)"
        # create RSA from KeyPair
        $rsa = [System.Security.Cryptography.RSA]::Create($this.KeyPair.ExportParameters($true))
        # Key Usage
        $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new( `
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor `
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, `
            $true `
        )
        # Enhanced Key Usage
        $oid = [System.Security.Cryptography.OidCollection]::new()
        [void]$oid.add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1","Server Authentication"))
        [void]$oid.add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2","Client Authentication"))
        # SAN
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        foreach ($dnsname in $this.SanNames) { $san.AddDnsName($dnsname) }
        # Generate Certificate Request string
        $certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new( `
            $subject, `
            $rsa, `
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, `
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 `
         )
        $certReq.CertificateExtensions.Add($keyUsage)
        $certReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oid,$false))
        $certReq.CertificateExtensions.Add($san.Build())
        $this.SelfSignedCert = $certReq.CreateSelfSigned([System.DateTimeOffset]::Now, [System.DateTimeOffset]::Now.AddYears(1))
        $this.SelfSignedCert.PrivateKey = $this.KeyPair
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('REQUEST',[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($this.SelfSignedCert)
            $store.Close()
        } else {
            Write-Warning "Session is not elevated. Can not store CSR in LocalComputer certificate store"
        }
        $pkcs10req = $certReq.CreateSigningRequest()
        $this.SelfSignedCsr  = "-----BEGIN CERTIFICATE REQUEST-----"
        $this.SelfSignedCsr += $([System.Convert]::ToBase64String($pkcs10req))
        $this.SelfSignedCsr += "-----END CERTIFICATE REQUEST-----"
        Write-Host "Selfsigned certificate and CSR [$($this.SelfSignedCert.Thumbprint)] generated and stored to cert:\LocalMachine\Request"
    }
    [bool] accept_casigned_csr() {
        $resp = $false
        $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($this.SignedCsr)
        $pfx.PrivateKey = $this.KeyPair
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            try {
                $store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My,[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($pfx)
                $store.Close()
                $resp = $true
            } catch {}
            # delete SelfSigned CSR
            if ($resp) {
                $resp = $false
                try {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('REQUEST',[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $store.Remove($this.SelfSignedCert)
                    $store.Close()
                    $resp = $true
                } catch {
                    Write-Warning "Unable to delete CSR from LocalMachine CertStore"
                }
            }
        } else {
            Write-Warning "Session is not elevated. Can not store CSR in LocalComputer certificate store"
        }
        #$pfx.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,$PfxPassword) | Out-File -FilePath "c:\azstools\logs\test.pfx"
        if ($resp) {
            Write-Host "Signed certificate accepted and moved to cert:\LocalMachine\My"
        }
        return $resp
    }
    [bool] create_casigned_certificate([string[]]$SanNames) {
        Write-Host "Creating new certificate"
        $hostname = ([System.Net.Dns]::GetHostByName($env:computerName).HostName).toLowerInvariant()
        $resp = $false
        $hostexist = $false
        foreach ($dns in $SanNames){
            $dns = $dns.toLowerInvariant()
            $hostexist = ($hostexist -or ($dns -eq $hostname))
        }
        if (!$hostexist) {
            $this.SanNames = $hostname + $SanNames
            Write-Host "Local hostanem [$hostname] added to SAN names"
        }
        if ($SanNames.Length -ge 1) {
            $this.SanNames = $SanNames
            $this.FriendlyName += "-$($this.SanNames[0])"
            $resp = $false
            $resp = $this.generate_selfsigned_csr()
            $resp = $this.request_casigned_csr()
            $resp = $this.download_casigned_csr()
            $resp = $this.accept_casigned_csr()
        }
        if ($resp) {
            Write-Host "Certificate created..."
        }
        return $resp
    }
}

[venafi_cert]$crt = [venafi_cert]::new('test')
$crt.create_casigned_certificate(@('test1.home.com','test2.home.com'))


