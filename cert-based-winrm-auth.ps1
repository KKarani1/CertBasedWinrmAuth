#Website Source: https://adamtheautomator.com/winrm-for-ansible/#Create_the_Server_Certificate
#Gitub Source: https://gist.github.com/adbertram/808268363fbaa1ef8e1be25cde249e09

#region Ensure the WinRm service is running
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"
#endregion

#region Enable PS remoting
if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
    ## Use Force to not be prompted if we're sure or not.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}
#endregion

#region Enable cert-based auth
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
#endregion

$UserAccountName = 'ansibleuser'
$UserAccountPassword = (ConvertTo-SecureString -String 'p@$$w0rd12' -AsPlainText -Force)
if (-not (Get-LocalUser -Name $UserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $UserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $UserAccountPassword
    }
    $null = New-LocalUser @newUserParams
}

## This is the public key generated from the Ansible server using:
<# 
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:ansibleuser@localhost
EOL
export OPENSSL_CONF=openssl.conf
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out cert.pem -outform PEM -keyout cert_key.pem -subj "/CN=ansibleuser" -extensions v3_req_client
rm openssl.conf 
#>

$pubKeyFilePath = "C:\cert.pem" 

## Import the public key into Trusted Root Certification Authorities and Trusted People
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\Root'
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'


#region Create the "server" cert for the Windows server and listener
# $hostName = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$hostname = hostname
$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'

#region Find all HTTPS listners
$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }

## If not listeners are defined at all or no listener is configured to work with
## the server cert created, create a new one with a Subject of the computer's host name
## and bound to the server certificate.
if ((-not $httpsListeners) -or -not (@($httpsListeners).where( { $_.CertificateThumbprint -ne $serverCert.Thumbprint }))) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTPS"; Address = "*" }
        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}
#endregion

$ansibleCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | ? {$_.Subject -eq 'CN=ansibleuser'}

#endregion

#region Map the client cert
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccountName, $UserAccountPassword

New-Item -Path WSMan:\localhost\ClientCertificate `
    -Subject "$UserAccountName@localhost" `
    -URI * `
    -Issuer $ansibleCert.Thumbprint `
    -Credential $credential `
    -Force

#endregion

#region Ensure LocalAccountTokenFilterPolicy is set to 1
$newItemParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
$null = New-ItemProperty @newItemParams
#endregion

 #region Ensure WinRM 5986 is open on the firewall
 $ruleDisplayName = 'Windows Remote Management (HTTPS-In)'
 if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
     $newRuleParams = @{
         DisplayName   = $ruleDisplayName
         Direction     = 'Inbound'
         LocalPort     = 5986
         RemoteAddress = 'Any'
         Protocol      = 'TCP'
         Action        = 'Allow'
         Enabled       = 'True'
         Group         = 'Windows Remote Management'
     }
     $null = New-NetFirewallRule @newRuleParams
 }
 #endregion

## Add the local user to the administrators group. If this step isn't doing, Ansible sees an "AccessDenied" error
Get-LocalUser -Name $UserAccountName | Add-LocalGroupMember -Group 'Administrators'
