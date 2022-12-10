#region Ensure the WinRm service is running
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"
#endregion

#region Enable PS remoting
if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}
#endregion

#region Enable cert-based auth
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
#endregion

$output_path = 'D:\EPV_APPS\Deployment\winrm_setup'

$UserAccountName = 'ansibleuser'
$testUserAccountPassword = (ConvertTo-SecureString -String 'p@$$w0rd12' -AsPlainText -Force)
if (-not (Get-LocalUser -Name $UserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $UserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
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
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$USERNAME@localhost
EOL
export OPENSSL_CONF=openssl.conf
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out cert.pem -outform PEM -keyout cert_key.pem -subj "/CN=$USERNAME" -extensions v3_req_client
rm openssl.conf 
#>

$pubKeyFilePath = "$output_path\pubkey.txt" 

## Import the public key into Trusted Root Certification Authorities and Trusted People
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\Root'
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

$ansibleCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | ? {$_.Subject -eq 'CN=ansibletestuser'}

#endregion

#region Create the "server" cert for the Windows server and listener
# $hostName = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$hostname = hostname
$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'

#region Create an SSL listener with the server cert
$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }

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

#region Map the client cert
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccountName, $testUserAccountPassword

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
