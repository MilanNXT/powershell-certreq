#
# custom object to Generate CSR and submit to internal Venafi CA
#

class venafi_apikey {
    [string]$APIKey
    [Datetime]$ValidUntil
}
class venafi_cred {
    venafi_cred() {}
    [string] username() {
        return "<venafi username>"
    }
    [string] password() {
        return "<venafi password>"
    }
}

class venafi_env {
    hidden [string]$def = 'nprod'
    hidden [System.Collections.Hashtable]$cred = @{
        'prod' = @{
            'encusername' = '<username>'
            'encpassword' = '<password>'
            'venafiuri' = '<prod CA uri>'
            'mandatorysubject' = 'OU=<Org identity> (PROD),O=Contoso,L=Seatle,S=Washington,C=US,E=contoso@company.com'
            'policy' = '\VED\Policy\Prod'
        }
        'nprod' = @{
            'encusername' = '<username>'
            'encpassword' = '<password>'
            'venafiuri' = '<nprod CA uri>'
            'mandatorysubject' = 'OU=<Org identity> (NPROD),O=Contoso,L=Seatle,S=Washington,C=US,E=contoso@company.com'
            'policy' = '\VED\Policy\SDKTest'
        }
    }
    venafi_env() {}
    [string] UserName() {
        return $this.UserName($this.def)
    }
    [string] UserName([string]$Environment) {
        return $this.cred[$Environment]['encusername']
    }
    [string] Password() {
        return $this.Password($this.def)
    }
    [string] Password([string]$Environment) {
        return $this.cred[$Environment]['encpassword']
    }
    [string] VenafiUri() {
        return $this.VenafiUri($this.def)
    }
    [string] VenafiUri([string]$Environment) {
        return $this.cred[$Environment]['venafiuri']
    }
    [string] MandatorySubject() {
        return $this.MandatorySubject($this.def)
    }
    [string] MandatorySubject([string]$Environment) {
        return $this.cred[$Environment]['mandatorysubject']
    }
    [string] Policy() {
        return $this.Policy($this.def)
    }
    [string] Policy([string]$Environment) {
        return $this.cred[$Environment]['policy']
    }
}

class venafi_cert {
    hidden [string]$NicNamePref = '<your certificate nicname prefix>'
    hidden [string]$Environment = 'nprod'
    hidden [bool]$LocalhostCertificate = $false
    hidden [int]$MaxRetry = 3
    hidden [int]$RetryTimeout = 10
    hidden [int]$KeySize = 2048
    hidden [string[]]$SanNames
    hidden [string]$FriendlyName
    hidden [venafi_env]$env = [venafi_env]::new()
    [venafi_apikey]$Api = [venafi_apikey]::new()
    [string]$CertificateDN
    hidden [System.Security.Cryptography.RSACryptoServiceProvider]$KeyPair
    hidden [System.Security.Cryptography.X509Certificates.X509Certificate2]$SelfSignedCert
    hidden [byte[]]$SignedCsr
    [string]$SelfSignedCsr

    hidden init() {
        #$this.FriendlyName = "$($this.NicNamePref)-$((New-Guid).Guid.Replace('-','').toUpperInvariant())"
        $this.FriendlyName = ''
        $this.Environment = 'nprod'
        $this.LocalhostCertificate = $false
    }
    hidden init([string]$FriendlyName){
        $this.init()
        if (![string]::IsNullOrEmpty($FriendlyName)) {
            if ($FriendlyName.Substring(1,4).ToLower() -ne "$($this.NicNamePref)-") {
                $this.FriendlyName = "$($this.NicNamePref)-$FriendlyName".ToLowerInvariant()
            } else {
                $this.FriendlyName = $FriendlyName.ToLowerInvariant()
            }
        }
    }
    hidden init([string]$FriendlyName,[string]$Environment){
        $this.init($FriendlyName)
        if (![string]::IsNullOrEmpty($Environment)) {
            $this.Environment = $Environment.ToLowerInvariant()
        }
    }
    venafi_cert(){
        $this.init()
    }
    venafi_cert([string]$FriendlyName) {
        $this.init($FriendlyName)
        $this.LocalhostCertificate = $false
    }
    venafi_cert([string]$FriendlyName,[string]$Environment) {
        $this.init($FriendlyName,$Environment)
    }
    venafi_cert([string]$FriendlyName,[string]$Environment,[string]$LocalhostCertificate) {
        $this.init($FriendlyName,$Environment)
        $this.LocalhostCertificate = ($LocalhostCertificate -eq 'true')
    }

    [bool] authenticate() {
        Write-Host "Authenticating to $($this.Environment) ..." 
        $resp = $false
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # login
        $header = @{ "content-type" = "application/json" }
        $body = @{
            'Username' = "$($this.env.UserName($this.Environment))"
            'Password' = "$($this.env.Password($this.Environment))"
        } | ConvertTo-Json -Compress
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$($this.env.venafiuri($this.Environment))/Authorize/" -Headers $header -Body $body
            $this.api = ConvertFrom-Json -InputObject $response.Content
            $resp = ($response.StatusCode -eq 200)
            Write-Host "...successfully authenticated"
        } catch {}
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
            $response = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "$($this.env.venafiuri($this.Environment))/Authorize/checkvalid" -Headers $header
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
            if (!$this.authenticate()) { Write-Host  "authentication error" }
        }
        $header = @{
            "content-type" = "application/json" ;
            "X-Venafi-Api-Key" = $($this.api.ApiKey)
        }
        $body = @{
            ObjectName = "$($this.FriendlyName)"
            PolicyDN = "$($this.env.policy($this.Environment))"
            PKCS10 = "$($this.SelfSignedCsr)"
        } | ConvertTo-Json -Compress
        $retry = 1
        Write-Host  "Submitting selfsigned certificate [$($this.SelfSignedCert.Thumbprint)] to CA"
        while (($retry -le $this.maxRetry) -and (!$resp)) {
            if ($retry -ge 1) { Write-Host  "Retry: $retry" }
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$($this.env.venafiuri($this.Environment))/Certificates/Request" -Headers $header -Body $body
                $this.CertificateDN = (ConvertFrom-Json -InputObject $response.Content).CertificateDN
                Write-Host  "CertificateDN: $($this.CertificateDN)"
                $resp = ($response.StatusCode -eq 200)
            } catch { Write-Host  $_ }
            if (!$resp) { Start-Sleep -Seconds $this.RetryTimeout }
            $retry += 1
        }
        if (!$resp) { Write-Host  "error submitting CSR" } else { Write-Host "Certificate submitted to CA"}
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
        Write-Host "Downloading signed certificate..."
        $s_csr = [System.String]::Empty
        while (($retry -le $this.maxRetry) -and (!$resp)) {
            if ($retry -ge 1) { Write-Host "Retry: $retry" }
            try {
                if (!$this.validate()) {
                    if (!$this.authenticate()) { Write-Host "authentication error" }
                }
                $response = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "$($this.env.venafiuri($this.Environment))/Certificates/Retrieve$param" -Headers $header
                $this.SignedCsr = $response.Content
                $resp = $response.StatusCode -eq 200
            }
            catch {}
            if (!$resp) { Start-Sleep -Seconds $this.RetryTimeout }
            $retry += 1
        }
        if (!$resp) {
            Write-Host "Can not retrieve signed CSR" 
        } else {
            Write-Host "Signed certificate [$($this.SelfSignedCert.Thumbprint)] downloaded from CA"
        }
        return $resp
    }
    [bool] generate_selfsigned_csr() {
        $this.generate_keypair()
        $resp = $false
        $subject = "CN=$($this.SanNames[0]),$($this.env.mandatorysubject($this.Environment))"
        try {
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
            $this.SelfSignedCsr  = "-----BEGIN CERTIFICATE REQUEST-----`n"
            #$this.SelfSignedCsr += [regex]::split( [System.Convert]::ToBase64String($pkcs10req), "(.{64})") | ? {$_}
            $this.SelfSignedCsr += [Regex]::Replace([System.Convert]::ToBase64String($pkcs10req), ".{64}", "$&`n")
            $this.SelfSignedCsr += "`n-----END CERTIFICATE REQUEST-----"
            $resp = $true
        } catch {}
        return $resp
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
            Write-Host "Signed certificate accepted and moved to cert:\LocalMachine\My thumbprint: $($pfx.Thumbprint)"
        }
        return $resp
    }
    [bool] create_casigned_certificate([string[]]$SanNames) {
        Write-Host  "Creating new certificate"
        Write-Host  "Venafi environment: $($this.Environment)"
        $this.SanNames = @()
        $resp = $false
        if ($this.LocalhostCertificate) {
            $hostname = ([System.Net.Dns]::GetHostByName($env:computerName).HostName).toLowerInvariant()
            $hostexist = $false
            foreach ($dns in $SanNames){
                $dns = $dns.toLowerInvariant()
                $hostexist = ($hostexist -or ($dns -eq $hostname))
            }
            if (!$hostexist) {
                $this.SanNames += $hostname
                Write-Host "Local hostname [$hostname] added to SAN names"
            }
        }
        # make all FQDN lowercase
        foreach ($san in $SanNames) {
            $this.SanNames += $san.toLowerInvariant()
        }
        if ($this.SanNames.Count -ge 1) {
            $resp = $this.generate_selfsigned_csr()
            if ([string]::IsNullOrEmpty($this.FriendlyName)) {
                $this.FriendlyName = "$($this.NicNamePref)-$($this.SanNames[0].split('.')[0])-$($this.SelfSignedCert.SerialNumber)"
            } else {
                $this.FriendlyName += "-$($this.SanNames[0].split('.')[0])-$($this.SelfSignedCert.SerialNumber)"
            }
            $this.FriendlyName = $this.FriendlyName.ToLowerInvariant()
            if ($resp) { $resp = $this.request_casigned_csr() }
            if ($resp) { $resp = $this.download_casigned_csr() }
            if ($resp) { $resp = $this.accept_casigned_csr() }
        } else {
            Write-Host "at least 1  SAN name must be provided..." 
        }
        if ($resp) {
            Write-Host "Certificate created..."
        } else {
            Write-Host "Certificate ceation process failed..." 
        }
        return $resp
    }
}

# Call custom object Venafi to request and store certificate
$crt = [venafi_cert]::new('friednly_name','nprod','true')

# By default computer hostmname is used as SAN, optionally list of other DNS could be added to SAN
$crt.create_casigned_certificate(@('test.home.cz','test2.home.cz'))
