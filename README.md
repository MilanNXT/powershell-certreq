# powershell-certreq
create, submit and accept CA signed certificate in powershell

I needed to automate creation of signed certificate for windows machine using Venafi API.
Previously I was using [CertReq.Exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1 "Microsoft Documentation") util to create,request and accept certificates, but for this task I want to avoid using CerReg.
As first version I created powershell class. I basicaly copied processe followed by CertReq.

1. Generate Public and Private key
2. Create selfsigned certificate using generated keypair and store in Local Machine certificate store under "Request" (including private key)
3. Generate CSR and submit to CA
4. Download signed CSR from CA
5. Create signed certificate from CA signed (by adding private key) and store it in LocalMachine certificate store under "My" (remove selfsigned one from Request store)

_(this is still work in progrees)_
