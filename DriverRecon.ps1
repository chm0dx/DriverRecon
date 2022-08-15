
function Invoke-DriverRecon{
    <#
    
    .SYNOPSIS

    Enumerate drivers registered on a machine and return back useful info such as certificate subject, certificate issue date, whether IoCreateDevice or IoCreateDeviceSecure are found, and string matches which may represent SDDLs, devices, or symlinks. Designed to make your life a little easier in deciding which drivers to target.

    .DESCRIPTION

    Get driver-related information to target driver-exploit opportunities.

    .NOTES

    Author: Jason Nickola, jason@pulsarsecurity.com

    .PARAMETER IgnoreSubjects

    A comma-separated list of cert subjects to ignore when reporting driver file details, IE "Microsoft, Intel". A good way to filter out well-known drivers and focus on targets that don't get as much attention.

    .EXAMPLE

    Invoke-DriverRecon

    .EXAMPLE

    Invoke-DriverRecon -IgnoreSubjects "Microsoft, Intel"
    

    #>
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]
        $IgnoreSubjects = ""
    )

    $drivers = Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services | Get-ItemProperty | Where-Object {($_.Type -eq 1 -or $_.Type -eq 2) -and ($_.ImagePath -ne $null)} | select -Property ImagePath -ExpandProperty ImagePath
    :driversLoop foreach ($driverFile in $drivers)
    {
        try
        {
            $driverFile = Out-String -InputObject $driverFile
            $driverFile = $driverFile.ToLower().replace("\systemroot\","").replace("system32",$env:SystemRoot + "\system32").replace("syswow64",$env:SystemRoot + "\syswow64").Trim()
            $driverCert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($driverFile)

            if ($IgnoreSubjects)
            {
                $certLower = $driverCert.Subject.ToLower()
                $IgnoreSubjects = $IgnoreSubjects.ToLower()
                $IgnoreList = $IgnoreSubjects.Split(",")
                foreach ($ignore in $IgnoreList)
                {
                    if($certLower.Contains($ignore))
                    {
                        continue driversLoop
                    }
                }
            }

            Write-Host($driverFile)
            Write-Host("`tIssuer: " + $driverCert.Issuer)
            Write-Host("`tSubject: " + $driverCert.Subject)
            Write-Host("`tDateSigned: " + $driverCert.GetEffectiveDateString())
    
            $driverFileContent = Get-Content $driverFile -Encoding Unicode
            $iocreatedeviceMatch = [Regex]::Matches($driverFileContent,"IoCreateDevice")
            $iocreatedevicesecureMatch = [Regex]::Matches($driverFileContent,"IoCreateDeviceSecure")
            $deviceLinkMatches = [Regex]::Matches($driverFileContent,"\\Device\\[a-zA-z]+")
            $symLinkmatches = [Regex]::Matches($driverFileContent,"\\\?\?\\[a-zA-z]+")
            $sddlMatches = [Regex]::Matches($driverFileContent,"D:[P(][\w;() \.\\%`"/:-]+")
            if ($iocreatedeviceMatch.Count -gt 0)
            {
                Write-Host("`tIoCreateDevice found.");
            }
            if ($iocreatedevicesecureMatch.Count -gt 0)
            {
                Write-Host("`tIoCreateDeviceSecure found.");
            }
            if ($deviceLinkMatches.Count -gt 0)
            {
                Write-Host("`tDevice Links: " + ($deviceLinkMatches -join ","));
            }
            if ($symLinkMatches.Count -gt 0)
            {
                Write-Host("`tSym Links: " + ($symLinkMatches -join ","));
            }
            if ($sddlMatches.Count -gt 0)
            {
                Write-Host("`tSDs: " + ($sddlMatches -join ","))
            }
            Write-Host("");
        }
        catch {
            continue
        }
    }
}