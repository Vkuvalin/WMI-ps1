$Password = ConvertTo-SecureString "Passwd321" –AsPlainText –Force
$user = "test_user"
New-LocalUser -Name $user -Description "test user for probe" -Password $Password
Add-LocalGroupMember -Group "Пользователи удаленного управления" -Member $user

$Namespace = "root\cimv2"
$systemSecurity = Get-CimInstance -Namespace $Namespace -ClassName __SystemSecurity   
$oDacl = Invoke-CimMethod -InputObject $systemSecurity -MethodName GetSecurityDescriptor 

$sd = $oDacl.Descriptor

$trustee = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Trustee -ClientOnly -Property @{
	Name = $user
	SidString = (new-object security.principal.NtAccount($user)).translate([security.principal.securityidentifier]).Value
} 

# AceType Allow = 0 Deny = 1
# AccessMask 35 = Execute Methods,Enable Account,Remote Enable

$ace = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Ace -ClientOnly -Property @{
	AceType=[uint32]0
	Trustee=$trustee
	AccessMask=[uint32]35
	AceFlags=[uint32]0
} 

[CIMInstance[]] $nDacl = $null 
foreach ($iAce in $sd.DACL) { 
	$nDacl += $iAce
}
 
$newDacl += $ace 
$sd.DACL = $newDacl 
               
Invoke-CimMethod -InputObject $systemSecurity -MethodName SetSecurityDescriptor -Arguments @{ 
	Descriptor = $sd 
}
