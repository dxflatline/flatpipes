using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace flatpipesns
{
    // Defines the data protocol for reading and writing strings on our stream
    public class StreamString
    {
        private Stream ioStream;
        private UnicodeEncoding streamEncoding;

        public StreamString(Stream ioStream)
        {
            this.ioStream = ioStream;
            streamEncoding = new UnicodeEncoding();
        }

        public string ReadString()
        {
            int len = 0;

            len = ioStream.ReadByte() * 256;
            len += ioStream.ReadByte();
            byte[] inBuffer = new byte[len];
            ioStream.Read(inBuffer, 0, len);

            return streamEncoding.GetString(inBuffer);
        }

        public int WriteString(string outString)
        {
            byte[] outBuffer = streamEncoding.GetBytes(outString);
            int len = outBuffer.Length;
            if (len > UInt16.MaxValue)
            {
                len = (int)UInt16.MaxValue;
            }
            ioStream.WriteByte((byte)(len / 256));
            ioStream.WriteByte((byte)(len & 255));
            ioStream.Write(outBuffer, 0, len);
            ioStream.Flush();

            return outBuffer.Length + 2;
        }
    }


    class flatpipes
    {
        static void Main(string[] args)
        {
            if (args.Length!=6)
            {
                Console.WriteLine("\nUsage: flatpipes [pipemode] [socketmode] [pipename] [pipeaddr] [ip] [port]\n");
                Console.WriteLine("  pipemode\tTo connect to or create locally a pipe (pserver|pclient)");
                Console.WriteLine("  pipeaddr\tIP for pipe connection (for local or server use '.')");
                Console.WriteLine("  socketmode\tAfter piping, TCP listen or connect (sserver|sclient)");
                Console.WriteLine("  pipename\tPrefix of the two pipes created");
                Console.WriteLine("  ip/port\tSocket info to listen on or connect to");
                Environment.Exit(1);
            }
            String pmode = args[0];
            String smode = args[1];
            String pipename = args[2];
            String pipeaddr = args[3];
            String ip = args[4];
            String port = args[5];
            if (String.Compare(pmode, "pserver") ==0)
            {
                // Handle pipes
                Console.WriteLine("[!] Waiting for pipe connections");
                var pipe_s2c = new NamedPipeServerStream(pipename + "_s2c", PipeDirection.Out); // Writing to client
                var pipe_c2s = new NamedPipeServerStream(pipename + "_c2s", PipeDirection.In); // Reading from client
                pipe_s2c.WaitForConnection();
                Console.WriteLine("[!] Client connected on downstream pipe");
                pipe_c2s.WaitForConnection();
                Console.WriteLine("[!] Client Connected on upstream pipe");
                StreamString ss_s2c = new StreamString(pipe_s2c);
                StreamString ss_c2s = new StreamString(pipe_c2s);

                // Handle socket communication
                NetworkStream networkStream = null;
                if (String.Compare(smode, "sclient") == 0)
                {
                    TcpClient tcpClient = new TcpClient(ip, Convert.ToInt32(port));
                    networkStream = tcpClient.GetStream();
                    Console.WriteLine("[!] Connected to " + ip + ":" + port);
                }
                else if (String.Compare(smode, "sserver") == 0)
                {
                    TcpListener tcpServer = new TcpListener(IPAddress.Parse(ip), Convert.ToInt32(port));
                    // Try to start socket listener until no problem occurs
                    bool ok = false;
                    while (!ok)
                    {
                        try
                        {
                            tcpServer.Start();
                            ok = true;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("[---] Error while listening. Check if port is used. Trying again in a while..");
                            Task.Delay(1000).Wait();
                        }
                    }
                    Console.WriteLine("[!] Started listener on " + ip + ":" + port);
                    TcpClient tcpClient = tcpServer.AcceptTcpClient();
                    Console.WriteLine("[!] Client Connected to socket");
                    networkStream = tcpClient.GetStream();
                }

                // Start the upstream/downstream handling tasks
                Server_SocketToWritePipe(networkStream, ss_s2c);
                Server_ReadPipeToSocket(networkStream, ss_c2s);

                // loop
                while (true) { }

            }
            else if (String.Compare(pmode, "pclient") == 0)//Client
            {
                // Handle pipes
                // Even if pserver is not online, it will block until it opens (seems to wait forever)
                var pipe_s2c = new NamedPipeClientStream(pipeaddr, pipename + "_s2c", PipeDirection.In, PipeOptions.None); // Reading from server
                var pipe_c2s = new NamedPipeClientStream(pipeaddr, pipename + "_c2s", PipeDirection.Out, PipeOptions.None); // Writing to server
                pipe_s2c.Connect();
                Console.WriteLine("[!] Connected to downstream pipe");
                pipe_c2s.Connect();
                Console.WriteLine("[!] Connected to upstream pipe");
                StreamString ss_s2c = new StreamString(pipe_s2c);
                StreamString ss_c2s = new StreamString(pipe_c2s);

                // Handle socket communication
                NetworkStream networkStream = null;
                if (String.Compare(smode, "sclient") == 0)
                {
                    TcpClient tcpClient = new TcpClient(ip, Convert.ToInt32(port));
                    networkStream = tcpClient.GetStream();
                    Console.WriteLine("[!] Connected to " + ip + ":" + port);
                }
                else if (String.Compare(smode, "sserver") == 0)
                {
                    TcpListener tcpServer = new TcpListener(IPAddress.Parse(ip), Convert.ToInt32(port));
                    // Try to start socket listener until no problem occurs
                    bool ok = false;
                    while (!ok)
                    {
                        try
                        {
                            tcpServer.Start();
                            ok = true;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("[---] Error while listening. Check if port is used. Trying again in a while..");
                            Task.Delay(1000).Wait();
                        }
                    }
                    Console.WriteLine("[!] Started listener on " + ip + ":" + port);
                    TcpClient tcpClient = tcpServer.AcceptTcpClient();
                    Console.WriteLine("[!] Client Connected to socket");
                    networkStream = tcpClient.GetStream();
                }

                // Start the upstream/downstream handling tasks
                Client_ReadPipeToSocket(networkStream, ss_s2c);
                Client_SocketToWritePipe(networkStream, ss_c2s);

                // loop
                while (true) { }

            }
        }

        static async void Client_ReadPipeToSocket(System.Net.Sockets.NetworkStream networkStream, StreamString ss)
        {
            Task.Factory.StartNew(() =>
            {
                String dataEncoded;
                byte[] dataDecoded;
                while (true)
                {
                    dataEncoded = ss.ReadString();
                    dataDecoded = Convert.FromBase64String(dataEncoded);
                    if (dataDecoded.Length > 0)
                    {
                        Console.WriteLine("Client_ReadPipeToConsole: Encoded Length " + dataEncoded.Length);
                        Console.WriteLine("Client_ReadPipeToConsole: Decoded Length " + dataDecoded.Length);
                        networkStream.Write(dataDecoded, 0, dataDecoded.Length);
                    }
                }

            });
        }

        static void Client_SocketToWritePipe(System.Net.Sockets.NetworkStream networkStream, StreamString ss)
        {
            Task.Factory.StartNew(() =>
            {
                byte[] netReadBuffer = new byte[1024];
                int charsread = 0;
                while (true)
                {
                    if (networkStream.CanRead)
                    {
                        charsread = networkStream.Read(netReadBuffer, 0, 250);
                        String s = Convert.ToBase64String(netReadBuffer, 0, charsread);
                        if (charsread > 0)
                        {
                            Console.WriteLine("Client_SocketToWritePipe: Decoded Length " + charsread);
                            Console.WriteLine("Client_SocketToWritePipe: Encoded Length " + s.Length);
                            ss.WriteString(s);
                        }
                    }

                }
            });
        }



        static void Server_ReadPipeToSocket(System.Net.Sockets.NetworkStream networkStream, StreamString ss)
        {
            Task.Factory.StartNew(() =>
            {
                String dataEncoded;
                byte[] dataDecoded;
                while (true)
                {
                    dataEncoded = ss.ReadString();
                    dataDecoded = Convert.FromBase64String(dataEncoded);
                    if (dataDecoded.Length > 0)
                    { 
                        Console.WriteLine("Server_PipeToSocket: Encoded Length " + dataEncoded.Length);
                        Console.WriteLine("Server_PipeToSocket: Decoded Length " + dataDecoded.Length);
                        networkStream.Write(dataDecoded, 0, dataDecoded.Length);
                    }
                }

            });
        }

        static void Server_SocketToWritePipe(System.Net.Sockets.NetworkStream networkStream, StreamString ss)
        {
            Task.Factory.StartNew(() =>
            {
                byte[] netReadBuffer = new byte[1024];
                int charsread = 0;
                while (true)
                {
                    if (networkStream.CanRead)
                    {
                        charsread = networkStream.Read(netReadBuffer, 0, 250);
                        String s = Convert.ToBase64String(netReadBuffer, 0, charsread);
                        if (charsread > 0)
                        {
                            Console.WriteLine("Server_SocketToWritePipe: Decoded Length " + charsread);
                            Console.WriteLine("Server_SocketToWritePipe: Encoded Length " + s.Length);
                            ss.WriteString(s);
                        }
                    }

                }
            });
        }
        


    }
}

