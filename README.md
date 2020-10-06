# How to create an OpenSSH Server with Rsync support on Windows 10

## Adding OpenSSH Server optional feature on Windows

Reference: [Enable OpenSSH Server on Windows 10 1809](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)

### Installation

Follow the above mentioned guide and verify that also the OpenSSH Client features is available.

The software of both features is installed in the Windows folder `C:/Windows/system32/OpenSSH:
```
322.560 scp.exe
322.048 sftp-server.exe
390.144 sftp.exe
491.520 ssh-add.exe
384.512 ssh-agent.exe
637.952 ssh-keygen.exe
530.432 ssh-keyscan.exe
149.504 ssh-shellhost.exe
882.688 ssh.exe
974.848 sshd.exe
  2.253 sshd_config_default
  11 Files, 5.088.461 Bytes
```

### Configuration

Follow these guidelines, then use an SSH connection using password authentication.

It's possible to provide another shell to the user and to activate public key authentication.

Reference: [OpenSSH server configuration](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration)

### Activate Public Key authentication

To authenticate with an SSH key instead of a password create a ssh key pair, for example:
```bash
ssh-keygen -t rsa -b 4096
```

Use the private key for the SSH command and copy the public key to the `authorized_keys` file server-side.

For Windows there are two different ways to achieve successful login by public key authentication

1. For a regular user, add the public key to `C:/Users/<user>/.ssh/authorized_keys`
1. For a user in the Administrator group, add the public key to `%ProgramData%/ssh/authorized_keys`
   The folder is the working space for OpenSSH and you need administrative access rights

See working examples for this in the Test section below,

#### Change the shell executable

By default, the Windows command shell is available for connected users.
To change this to `PowerShell` support create a registry entry on the Windows host:
```
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

Review this setting with:
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH"  
```

### OpenSSH's limitations on Windows

- Authentication methods are limited to `password` and `publickey`.
- Not all cipher suites may be supported yet.
- Maybe no connection from legacy *ix machines (lack of support for SHA1 and related encryption methods)
- [Not supported OpenSSH configuration options](
https://docs.microsoft.com/de-de/windows-server/administration/openssh/openssh_server_configuration#not-supported)

## Adding Rsync support to Windows

There is no built-in support for `rsync` as an optional feature.

To provide this tool for proper external `rsync over ssh` connections to the windows host,
download the free [cwrsync tool](https://www.itefix.net/cwrsync).
The tool comes as a zip file that simply needs to be extracted to a directory in the
Windows PATH environment variable (e.g. the OpenSSH tool folder itself).

>**Note**: For rsync itself this portable solution just needs the files
>`rsync.exe, cygwin1.dll, cygz.dll` 
>in order to synchronize local files in the network.

Because this is Cygwin based, Windows path notations like `C:/Users`
cannot be used here (in contrast to Secure Copy), instead a Cygwin
path like `/cygdrive/c/Users` is required.

## Test SSH and Rsync

With or without a user public key added to the Windows OpenSSH Authorized Keys list, 
connect from any machine and try some scenarios:

- Use SSH with user credentials and get a default Windows command shell
- Use SSH as usual with an authorized key and get a default Windows command shell
- Try a rsync command without rsync executable on Windows and see the error:
  ```bash
  $ rsync -azvhr --rsh="ssh" <user>@<windows-host>:/cygdrive/c/Windows/system32/OpenSSH .
  rsync --server --sender -vlogDtprz . /cygdrive/c/Windows/system32/Ope ...
  ...
    + ~~~~~
        + CategoryInfo          : ObjectNotFound: (rsync:String) [], CommandNotFoundException
        + FullyQualifiedErrorId : CommandNotFoundException
  ...
  ```
- Secure Copy the cwrsync files to the Windows OpenSSH folder:
  ```
  scp {rsync,d2u,u2d}.exe <user>@<windows-host>:C:/Windows/system32/OpenSSH
  scp cyg* <user>@<windows-host>:C:/Windows/system32/OpenSSH
  ```
- Use Rsync locally on windows with some specific options
  ```
  rsync -r -v --size-only --chmod=ugo=rwX "D:/projects" "E:/backup"
  ```
- Use Rsync over SSH for some test data and password authentication:
  ```bash
  rsync -azvhr --rsh="ssh" <user>@<windows-host>:/cygdrive/c/Windows/system32/OpenSSH local-sync
  ```
- Use Rsync over SSH for some test data and public key authentication for a regular user:
    1. Create the regular user by using Powershell on the host:
       ```bash
       > $Password = Read-Host -AsSecureString
       > New-LocalUser -Name "TestSSH" -Description "Open SSH Test Account" -Password $Password
       ```
    2. Copy the public ssh-key into the authorized_keys list:
       ```bash
       scp public-key-file TestSSH@evolux:C:/Users/TestSSH/.ssh/authorized_keys
       ```
    1. Connect with private key:
       ```bash
       rsync -azvhr --rsh="ssh -i ./private-key-file" TestSSH@<windows-host>:/cygdrive/c/Windows/system32/OpenSSH local-sync
       ```
- Use Rsync over SSH for some test data and public key authentication for a user in the Administrator group:
    1. Copy the public ssh-key into the administrators_authorized_keys list in the ProgramData folder:
       ```bash
       scp public-key-file <user>@evolux:C:/ProgramData/ssh/administrators_authorized_keys
       ```
    1. Configure access rules by using Powershell on the host (otherwise a password is requested):
       ```bash
       $acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
       $acl.SetAccessRuleProtection($true, $false)
       $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
       $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
       $acl.SetAccessRule($administratorsRule)
       $acl.SetAccessRule($systemRule)
       $acl | Set-Acl
       ```      
    1. Connect with private key:
       ```bash
       rsync -azvhr --rsh="ssh -i ./private-key-file" <user>>@<windows-host>:/cygdrive/c/Windows/system32/OpenSSH local-sync
       ```
         
### Recommendations for Rsync on Windows

- Use Options:
  - `--size-only` is recommended, because the date of last file modification is not always reliable information in Windows
  - `--chmod=ugo=rwX` could be important, target files could not be read (NTFS-permissions possibly denied)
- Use regular ASCII names for folders and filenames with a maximum path length of 255 characters (Unicode characters can cause issues)


