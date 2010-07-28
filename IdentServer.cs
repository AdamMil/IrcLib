/*
IrcLib is a simple IRC client for .NET.

http://www.adammil.net/
Copyright (C) 2009-2010 Adam Milazzo

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace IrcLib
{

public class IdentServer
{
  public void Listen()
  {
    Listen(IPAddress.Any, 113);
  }

  public void Listen(int port)
  {
    Listen(IPAddress.Any, port);
  }

  public void Listen(IPAddress localAddress, int port)
  {
    if(listener != null) Shutdown();
    listener = new TcpListener(localAddress, port);
    listener.Start();
  }

  public bool ProcessRequests(int waitMs)
  {
    if(listener == null) throw new InvalidOperationException("Listen() has not been called.");

    if(listener.Server.Poll(waitMs == -1 ? -1 : waitMs*1000, SelectMode.SelectRead))
    {
      Socket socket = listener.AcceptSocket();
      try
      {
        socket.ReceiveTimeout = 10000;
        byte[] buffer = new byte[32]; // not many bytes are needed for a request
        int bytesRead = 0;
        while(bytesRead != buffer.Length)
        {
          int read = socket.Receive(buffer, bytesRead, buffer.Length - bytesRead, SocketFlags.None);
          if(read == 0) break;
        }

        string[] ports = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Split(',');
        int serverPort, clientPort;
        int.TryParse(ports[0].Trim(), out serverPort);
        int.TryParse(ports[1].Trim(), out clientPort);

        socket.Send(System.Text.Encoding.ASCII.GetBytes(GetResponse(serverPort, clientPort)));
        return true;
      }
      finally
      {
        socket.Shutdown(SocketShutdown.Both);
        socket.Close();
      }
    }
    else
    {
      return false;
    }
  }

  public void Shutdown()
  {
    if(listener != null)
    {
      listener.Stop();
      listener = null;
    }
  }

  protected virtual string GetResponse(int serverPort, int clientPort)
  {
    string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name, platform;

    switch(Environment.OSVersion.Platform)
    {
      case PlatformID.Win32NT: case PlatformID.Win32S: case PlatformID.Win32Windows: case PlatformID.WinCE:
        platform = "WIN32";
        break;
      default:
        platform = "UNIX";
        break;
    }

    return serverPort.ToString(CultureInfo.InvariantCulture) + ", " +
           clientPort.ToString(CultureInfo.InvariantCulture) + " : USERID : " + platform + " : " + userName;
  }

  TcpListener listener;
}

} // namespace IrcLib