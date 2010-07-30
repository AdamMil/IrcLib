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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

// TODO: don't keep users and channels around forever

namespace IrcLib
{

public delegate void ReplyHandler<ReplyType>(ReplyType reply);

#region UserFlags
/// <summary>Represents flags that apply to a user globally.</summary>
[Flags]
public enum UserFlags
{
  None=0, Invisible=1, ReceivesServerNotices=2, ReceivesWallops=4, IsServerOperator=8,
}
#endregion

#region ChannelUserFlags
/// <summary>Represents flags that apply to a user within a channel.</summary>
[Flags]
public enum ChannelUserFlags
{
  None=0, IsOperator=1, CanSpeak=2
}
#endregion

#region ChannelFlags
/// <summary>Represents flags that apply to a channel.</summary>
[Flags]
public enum ChannelFlags
{
  None=0, IsPrivate=1, IsSecret=2, IsInviteOnly=4, RestrictedTopic=8, NoExternalMessages=16, Moderated=32,
  HasUserLimit=64, HasPassword=128,
}
#endregion

#region IrcResponseCodes
/// <summary>Represents IRC numeric response codes.</summary>
public enum IrcResponseCodes
{
  None=0,

  // messages
  Welcome=1, YourHostIs=2, ServerWasCreatedOn=3, ServerInfo=4, TryAnotherServer=5, YourModeIs=221, TryAgain=263,
  UserIsAway=301, UserHost=302, UserIsOn=303, YouAreUnaway=305, YouAreAway=306, WhoisUser=311, WhoisServer=312,
  WhoisOperator=313, WhoWasUser=314, EndOfWho=315, WhoisIdle=317, EndOfWhoisList=318, WhoisChannels=319,
  StartChannelList=321, Channel=322, EndChannelList=323, ChannelModeIs=324, ChannelCreatedAt=329,
  NoTopic=331, Topic=332, TopicInfo=333,
  Inviting=341, Summoning=342, Version=351, Who=352, NameReply=353, Links=364, EndOfLinks=365, EndOfNames=366,
  BanList=367, EndOfBanList=368, EndOfWhoWas=369, Info=371, Motd=372, EndOfInfo=374, StartMotd=375, EndMotd=376,
  YouAreOperator=381, Rehashing=382, ServerTime=391, StartUsers=392, User=393, EndUsers=394, NoUsers=395, 

  // errors
  NoSuchNick=401, NoSuchServer=402, NoSuchChannel=403, CannotSendToChannel=404, TooManyChannels=405, WasNoSuchNick=406,
  TooManyTargets=407, NoOrigin=409, NoRecipient=411, NoTextToSend=412, NoTopLevel=413, WildTopLevel=414,
  UnknownCommand=421, NoMotd=422, NoAdminInfo=423, NoNicknameGiven=431, ErroneousNickname=432, NicknameInUse=433,
  NickCollision=436, UserNotInChannel=441, NotOnChannel=442, UserOnChannel=443, NoLogon=444, SummonDisabled=445,
  UserDisabled=446, NotRegistered=451, NeedMoreParams=461, AlreadyRegistered=462, NoPermissionForHost=463,
  WrongPassword=464, YouAreBanned=465, KeyAlreadySet=467, ChannelIsFull=471, UnknownMode=472, InviteOnlyChannel=473,
  BannedFromChannel=474, WrongChannelKey=475, ServerPermissionDenied=481, ChannelPermissionDenied=482,
  CantKillServer=483, NonOperatorHost=491, UnknownUserModeFlag=501, CantChangeAnotherUsersMode=502
}
#endregion

#region ChannelUser
/// <summary>Represents a user within an IRC channel.</summary>
public struct ChannelUser
{
  public ChannelUser(User user, ChannelUserFlags flags)
  {
    User  = user;
    Flags = flags;
  }

  public bool HasFlag(ChannelUserFlags flag)
  {
    return (Flags & flag) != 0;
  }

  public override string ToString()
  {
    string prefix = null;
    if(HasFlag(ChannelUserFlags.IsOperator)) prefix = "@";
    else if(HasFlag(ChannelUserFlags.CanSpeak)) prefix = "+";
    return prefix + User.Name;
  }

  public readonly User User;
  public readonly ChannelUserFlags Flags;
}
#endregion

#region Channel
/// <summary>Represents an IRC channel.</summary>
public class Channel : IrcEntity
{
  internal Channel(string name)
  {
    Name  = name;
    Users = new ChannelUserList();
  }

  #region ChannelUserList
  public sealed class ChannelUserList : IrcClient.IrcNameDictionary<ChannelUser>
  {
    internal ChannelUserList() : base(true) { }

    public override bool Contains(ChannelUser item)
    {
      return Items.ContainsKey(item.User.Name);
    }
  }
  #endregion

  public DateTime? CreationTime
  {
    get; internal set;
  }

  public ChannelFlags Flags
  {
    get; internal set;
  }

  public string Password
  {
    get; internal set;
  }

  public string Topic
  {
    get; internal set;
  }

  public DateTime? TopicSetTime
  {
    get; internal set;
  }

  public string TopicSetBy
  {
    get; internal set;
  }

  public int UserLimit
  {
    get; internal set;
  }

  public ChannelUserList Users
  {
    get; private set;
  }

  public bool HasFlag(ChannelFlags flag)
  {
    return (Flags & flag) != 0;
  }

  public override string ToString()
  {
    StringBuilder sb = new StringBuilder();
    string args = null;

    sb.Append(Name);
    if(Flags != ChannelFlags.None)
    {
      sb.Append(" (+");
      if(HasFlag(ChannelFlags.IsInviteOnly)) sb.Append('i');
      if(HasFlag(ChannelFlags.Moderated)) sb.Append('m');
      if(HasFlag(ChannelFlags.NoExternalMessages)) sb.Append('n');
      if(HasFlag(ChannelFlags.IsPrivate)) sb.Append('p');
      if(HasFlag(ChannelFlags.IsSecret)) sb.Append('s');
      if(HasFlag(ChannelFlags.RestrictedTopic)) sb.Append('t');
      if(HasFlag(ChannelFlags.HasUserLimit))
      {
        sb.Append('l');
        args += " " + UserLimit.ToString(CultureInfo.InvariantCulture);
      }
      if(HasFlag(ChannelFlags.HasPassword))
      {
        sb.Append('k');
        if(!string.IsNullOrEmpty(Password)) args += " " + Password;
      }
      sb.Append(")").Append(args);
    }

    return sb.ToString();
  }

  internal void UpdateUser(User user, ChannelUserFlags flagsToAdd, ChannelUserFlags flagsToRemove)
  {
    ChannelUser channelUser;
    if(!Users.TryGetValue(user.Name, out channelUser)) channelUser = new ChannelUser(user, ChannelUserFlags.None);
    Users[user.Name] = new ChannelUser(user, channelUser.Flags & ~flagsToRemove | flagsToAdd);
  }
}
#endregion

#region IrcEntity
public abstract class IrcEntity
{
  public string Name
  {
    get; internal set;
  }
}
#endregion

#region User
public class User : IrcEntity
{
  internal User(string name)
  {
    Name = name;
  }

  public UserFlags Flags
  {
    get; internal set;
  }

  public string HostName
  {
    get; internal set;
  }

  public string UserName
  {
    get; internal set;
  }

  public bool HasFlag(UserFlags flag)
  {
    return (Flags & flag) != 0;
  }

  public override string ToString()
  {
    StringBuilder sb = new StringBuilder();

    sb.Append(Name);
    if(Flags != UserFlags.None)
    {
      sb.Append(" (+");
      if(HasFlag(UserFlags.Invisible)) sb.Append('i');
      if(HasFlag(UserFlags.IsServerOperator)) sb.Append('o');
      if(HasFlag(UserFlags.ReceivesServerNotices)) sb.Append('s');
      if(HasFlag(UserFlags.ReceivesWallops)) sb.Append('w');
      sb.Append(")");
    }

    return sb.ToString();
  }
}
#endregion

#region NameComparer
public sealed class NameComparer : IComparer<string>, IEqualityComparer<string>
{
  public int Compare(string a, string b)
  {
    return IrcClient.CompareNames(a, b);
  }

  public bool Equals(string a, string b)
  {
    return IrcClient.AreNamesEqual(a, b);
  }

  public int GetHashCode(string name)
  {
    return IrcClient.NameToLower(name).GetHashCode();
  }

  public static readonly NameComparer Instance = new NameComparer();
}
#endregion

#region UserComparer
public sealed class UserComparer : IComparer<User>, IEqualityComparer<User>
{
  public int Compare(User a, User b)
  {
    return IrcClient.CompareNames(a == null ? null : a.Name, b == null ? null : b.Name);
  }

  public bool Equals(User a, User b)
  {
    return IrcClient.AreNamesEqual(a == null ? null : a.Name, b == null ? null : b.Name);
  }

  public int GetHashCode(User user)
  {
    return user == null ? 0 : IrcClient.NameToLower(user.Name).GetHashCode();
  }

  public static readonly UserComparer Instance = new UserComparer();
}
#endregion

#region JoinReply
public class JoinReply
{
  public JoinReply(Channel channel, IrcResponseCodes error)
  {
    Channel = channel;
    Error   = error;
  }

  public readonly Channel Channel;
  public readonly IrcResponseCodes Error;
}
#endregion

#region NickReply
public class NickReply
{
  public NickReply(string oldNick, string newNick, IrcResponseCodes error)
  {
    OldNick = oldNick;
    NewNick = newNick;
    Error   = error;
  }

  public readonly string OldNick, NewNick;
  public readonly IrcResponseCodes Error;
}
#endregion

public class IrcClient
{
  public IrcClient()
  {
    JoinedChannels = new IrcEntityList<Channel>(true);
    KnownChannels  = new IrcEntityList<Channel>(true);
    KnownUsers     = new IrcUserList(true);
  }

  #region IrcNameDictionary
  public class IrcNameDictionary<T> : ICollection<T>, IDictionary<string, T>
  {
    public IrcNameDictionary() : this(false) { }

    public IrcNameDictionary(bool readOnly)
    {
      this._readOnly = readOnly;
    }

    #region ICollection<T> Members
    public int Count
    {
      get { return Items.Count; }
    }

    public bool IsReadOnly
    {
      get { return _readOnly; }
    }

    void ICollection<T>.Add(T item)
    {
      Add(item);
    }

    public void Clear()
    {
      AssertNotReadOnly();
      Items.Clear();
    }

    public virtual bool Contains(T item)
    {
      return Items.ContainsValue(item);
    }

    public void CopyTo(T[] array, int arrayIndex)
    {
      Items.Values.CopyTo(array, arrayIndex);
    }

    bool ICollection<T>.Remove(T item)
    {
      return Remove(item);
    }
    #endregion

    #region IEnumerable<T> Members
    public IEnumerator<T> GetEnumerator()
    {
      return Items.Values.GetEnumerator();
    }
    #endregion

    #region IEnumerable Members
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
    {
      return Items.Values.GetEnumerator();
    }
    #endregion

    #region IDictionary<string,T> Members
    public void Add(string key, T value)
    {
      AssertNotReadOnly();
      Items.Add(key, value);
    }

    public bool ContainsKey(string key)
    {
      return Items.ContainsKey(key);
    }

    public ICollection<string> Keys
    {
      get { return Items.Keys; }
    }

    public bool Remove(string key)
    {
      AssertNotReadOnly();
      return Items.Remove(key);
    }

    public bool TryGetValue(string key, out T value)
    {
      return Items.TryGetValue(key, out value);
    }

    public ICollection<T> Values
    {
      get { return Items.Values; }
    }

    public T this[string key]
    {
      get { return Items[key]; }
      set
      {
        AssertNotReadOnly();
        Items[key] = value;
      }
    }
    #endregion

    #region ICollection<KeyValuePair<string,T>> Members
    void ICollection<KeyValuePair<string, T>>.Add(KeyValuePair<string, T> pair)
    {
      AssertNotReadOnly();
      Items.Add(pair.Key, pair.Value);
    }

    void ICollection<KeyValuePair<string, T>>.Clear()
    {
      Clear();
    }

    bool ICollection<KeyValuePair<string, T>>.Contains(KeyValuePair<string, T> pair)
    {
      T item;
      return Items.TryGetValue(pair.Key, out item) && object.Equals(pair.Value, item);
    }

    public void CopyTo(KeyValuePair<string, T>[] array, int arrayIndex)
    {
      ((ICollection<KeyValuePair<string,T>>)Items).CopyTo(array, arrayIndex);
    }

    bool ICollection<KeyValuePair<string, T>>.Remove(KeyValuePair<string, T> pair)
    {
      AssertNotReadOnly();
      T item;
      return Items.TryGetValue(pair.Key, out item) && object.Equals(item, pair.Value) && Items.Remove(pair.Key);
    }
    #endregion

    #region IEnumerable<KeyValuePair<string,T>> Members
    IEnumerator<KeyValuePair<string, T>> IEnumerable<KeyValuePair<string, T>>.GetEnumerator()
    {
      return Items.GetEnumerator();
    }
    #endregion

    public IEnumerable<KeyValuePair<string, T>> EnumeratePairs()
    {
      return this;
    }

    public virtual void OnNameChanged(string oldName, string newName)
    {
      T item;
      if(Items.TryGetValue(oldName, out item))
      {
        Items.Remove(oldName);
        Items[newName] = item;
      }
    }

    protected virtual void Add(T item)
    {
      throw new InvalidOperationException();
    }

    protected void AssertNotReadOnly()
    {
      if(IsReadOnly) throw new InvalidOperationException();
    }

    protected virtual bool Remove(T item)
    {
      throw new InvalidOperationException();
    }

    protected internal Dictionary<string, T> Items = new Dictionary<string, T>(NameComparer.Instance);

    readonly bool _readOnly;
  }
  #endregion

  #region IrcEntityList
  public class IrcEntityList<T> : IrcNameDictionary<T> where T : IrcEntity
  {
    public IrcEntityList() : this(false) { }
    public IrcEntityList(bool readOnly) : base(readOnly) { }

    protected override void Add(T item)
    {
      Add(item.Name, item);
    }

    public override bool Contains(T item)
    {
      T entity;
      return Items.TryGetValue(item.Name, out entity) && item == entity;
    }

    protected override bool Remove(T item)
    {
      AssertNotReadOnly();
      T entity;
      return Items.TryGetValue(item.Name, out entity) && item == entity && Items.Remove(item.Name);
    }
  }
  #endregion

  #region IrcUserList
  public sealed class IrcUserList : IrcEntityList<User>
  {
    public IrcUserList() : this(false) { }
    public IrcUserList(bool readOnly) : base(readOnly) { }

    public override void OnNameChanged(string oldName, string newName)
    {
      User user;
      if(Items.TryGetValue(oldName, out user))
      {
        Items.Remove(oldName);
        Items[newName] = user;
        user.Name = newName;
      }
    }
  }
  #endregion

  public bool CanProcessData
  {
    get { return socket != null; }
  }

  public bool IsConnected
  {
    get { return socket != null && socket.Connected && (!socket.Poll(0, SelectMode.SelectRead) || socket.Available != 0); }
  }

  public IrcEntityList<Channel> JoinedChannels
  {
    get; private set;
  }

  public IrcEntityList<Channel> KnownChannels
  {
    get; private set;
  }

  public IrcUserList KnownUsers
  {
    get; private set;
  }

  public string Nickname
  {
    get; private set;
  }

  public EndPoint RemoteEndPoint
  {
    get; private set;
  }

  public User User
  {
    get; private set;
  }

  public void Connect(string server)
  {
    Connect(server, 6667);
  }

  public void Connect(string server, int port)
  {
    Connect(server, port, null, null, null, null, null);
  }

  public void Connect(EndPoint endPoint)
  {
    Connect(endPoint, null, null, null, null, null);
  }

  public void Connect(string server, int port, string userName, string password,
                      string hostName, string serverName, string realName)
  {
    Connect(new IPEndPoint(Dns.GetHostEntry(server).AddressList[0], port), userName, password, hostName, serverName, realName);
  }

  public void Connect(EndPoint endPoint, string userName, string password, string hostName, string serverName, string realName)
  {
    if(endPoint == null) throw new ArgumentNullException();

    if(IsConnected) Disconnect();

    Socket socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    socket.Connect(endPoint);

    try
    {
      textBuffer = new byte[512];

      this.socket    = socket;
      RemoteEndPoint = socket.RemoteEndPoint;

      if(!string.IsNullOrEmpty(password)) SendRawCommand("PASS " + password);
      if(string.IsNullOrEmpty(Nickname)) Nickname = GetRandomNick();
      if(string.IsNullOrEmpty(userName)) userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
      if(string.IsNullOrEmpty(hostName)) hostName = Dns.GetHostName();
      if(string.IsNullOrEmpty(serverName)) serverName = hostName;
      if(string.IsNullOrEmpty(realName)) realName = userName;

      SendRawCommand("NICK " + Nickname);
      SendRawCommand("USER {0} {1} {2} :{3}", userName, hostName, serverName, realName);

      for(int i=0; i<300 && IsConnected && !registered; i++) ProcessData(100);
      if(!registered) throw new SocketException((int)SocketError.ConnectionAborted);
      OnConnect();
    }
    catch
    {
      Reset();
      throw;
    }
  }

  public void Disconnect()
  {
    Disconnect("");
  }

  public void Disconnect(string reason)
  {
    if(IsConnected)
    {
      SendRawCommand(string.IsNullOrEmpty(reason) ? "QUIT" : "QUIT :" + reason);
      socket.Shutdown(SocketShutdown.Send);
      socket.Close();
      OnDisconnect(true);
    }
  }

  public void Join(string channel)
  {
    Join(channel, null, null);
  }

  public void Join(string channel, ReplyHandler<JoinReply> handler)
  {
    Join(new string[] { channel }, null, handler);
  }

  public void Join(string channel, string password)
  {
    Join(channel, password, null);
  }

  public void Join(string channel, string password, ReplyHandler<JoinReply> handler)
  {
    Join(new string[] { channel }, password, handler);
  }

  public void Join(IEnumerable<string> channels, string password, ReplyHandler<JoinReply> handler)
  {
    // only add handlers for channels we're not already on, because the server will give no reply at all for channels
    // we're on, preventing the handler from getting executed
    foreach(string channel in channels) 
    {                                   
      if(!JoinedChannels.ContainsKey(channel)) AddReplyHandler(channel, "JOIN", handler);
    }

    SendRawCommand("JOIN " + MakeTargetList(channels) +
                   (string.IsNullOrEmpty(password) ? null : " " + password));
  }

  public void Kick(string channel, string user)
  {
    Kick(channel, user, null);
  }

  public void Kick(string channel, string user, string comment)
  {
    Kick(new string[] { channel }, new string[] { user }, comment);
  }

  public void Kick(IEnumerable<string> channels, IEnumerable<string> users, string comment)
  {
    SendRawCommand("KICK " + MakeTargetList(channels) + " " + MakeTargetList(users) +
                   (string.IsNullOrEmpty(comment) ? null : " :" + comment));
  }

  public void Part(string channel)
  {
    Part(new string[] { channel });
  }

  public void Part(IEnumerable<string> channels)
  {
    SendRawCommand("PART " + MakeTargetList(channels));
  }

  public bool ProcessData(int waitMs)
  {
    if(socket == null)
    {
      return false;
    }
    else if(!IsConnected)
    {
      OnDisconnect(false);
      return false;
    }
    else if(waitMs >= 0 && !socket.Poll(waitMs*1000, SelectMode.SelectRead))
    {
      return false;
    }

    byte[] buffer = new byte[4096];
    byte[] line   = null;
    int startIndex = 0, bytesRead;

    try { bytesRead = socket.Receive(buffer, SocketFlags.None); }
    catch(SocketException)
    {
      if(!socket.Connected)
      {
        OnDisconnect(false);
        return false;
      }
      else throw;
    }

    if(bytesRead == 0) return false;

    for(int newLine; startIndex < bytesRead; startIndex = newLine+1)
    {
      newLine = Array.IndexOf(buffer, (byte)'\n', startIndex, bytesRead - startIndex);

      if(newLine == -1)
      {
        break;
      }
      else if(newLine != 0 ? buffer[newLine-1] == (byte)'\r'
                           : textBufferBytes != 0 && textBuffer[textBufferBytes-1] == (byte)'\r')
      {
        int lineLength = textBufferBytes + newLine - startIndex - 1;
        if(line == null || line.Length < lineLength) line = new byte[Math.Max(lineLength, 512)];

        Array.Copy(textBuffer, line, textBufferBytes);
        Array.Copy(buffer, startIndex, line, textBufferBytes, newLine - startIndex - 1);
        textBufferBytes = 0;
        OnRawInput(encoding.GetString(line, 0, lineLength));
      }
    }

    int bytesToBuffer = bytesRead - startIndex;
    if(textBuffer.Length < bytesToBuffer)
    {
      int newLength = textBuffer.Length;
      do newLength *= 2; while(newLength < bytesToBuffer);
      textBuffer = new byte[newLength];
    }
    Array.Copy(buffer, startIndex, textBuffer, 0, bytesToBuffer);

    return true;
  }

  public void SendMessage(string to, string text)
  {
    SendMessage(new string[] { to }, text);
  }

  public void SendMessage(IEnumerable<string> to, string text)
  {
    if(text == null) throw new ArgumentNullException();
    SendRawCommand("PRIVMSG " + MakeTargetList(to) + " :" + text);
    OnMessageSent(to, text);
  }

  public void SendNotice(string to, string text)
  {
    SendNotice(new string[] { to }, text);
  }

  public void SendNotice(IEnumerable<string> to, string text)
  {
    if(text == null) throw new ArgumentNullException();
    SendRawCommand("NOTICE " + MakeTargetList(to) + " :" + text);
  }

  public void SendCTCPMessage(string to, string text)
  {
    SendCTCPMessage(new string[] { to }, text);
  }

  public void SendCTCPMessage(IEnumerable<string> to, string text)
  {
    if(text == null) throw new ArgumentNullException();
    SendRawCommand("PRIVMSG " + MakeTargetList(to) + " :\x01" + text + "\x01");
  }

  public void SendCTCPNotice(string to, string text)
  {
    SendCTCPNotice(new string[] { to }, text);
  }

  public void SendCTCPNotice(IEnumerable<string> to, string text)
  {
    if(text == null) throw new ArgumentNullException();
    SendRawCommand("NOTICE " + MakeTargetList(to) + " :\x01" + text + "\x01");
  }

  public void SendRawCommand(string text)
  {
    if(text == null) throw new ArgumentNullException();
    AssertConnected();
    socket.Send(encoding.GetBytes(text));
    socket.Send(crlf);
    OnRawOutput(text);
  }

  public void SendRawCommand(string format, params object[] args)
  {
    SendRawCommand(string.Format(CultureInfo.InvariantCulture, format, args));
  }

  public void SetNickname(string newNickname)
  {
    SetNickname(newNickname, null);
  }

  public void SetNickname(string newNickname, ReplyHandler<NickReply> handler)
  {
    if(newNickname == null) throw new ArgumentNullException();

    if(!string.Equals(newNickname, Nickname, StringComparison.Ordinal))
    {
      AddReplyHandler(newNickname, "NICK", handler);
      if(IsConnected) SendRawCommand("NICK " + newNickname);
    }
  }

  public static bool AreNamesEqual(string a, string b)
  {
    if(a != null && b != null && a.Length != b.Length) return false;
    else return CompareNames(a, b) == 0;
  }

  public static int CompareNames(string a, string b)
  {
    if(a == null && b == null) return 0;
    else if(a == null) return -1;
    else if(b == null) return 1;

    a = a.ToLowerInvariant();
    b = b.ToLowerInvariant();

    int length = Math.Min(a.Length, b.Length);
    for(int i=0; i < length; i++)
    {
      char ca = a[i], cb = b[i];
      if(ca != cb)
      {
        // the IRC protocol considers these characters to be upper/lowercase versions of each other, due to its
        // Scandanavian origin
        if(ca=='[' && cb=='{'  || ca=='{'  && cb=='[' || ca==']' && cb=='}'  || ca=='}'  && cb==']' ||
           ca=='|' && cb=='\\' || ca=='\\' && cb=='|')
        {
          continue;
        }
        else return ca - cb;
      }
    }

    return a.Length == b.Length ? 0 : a.Length < b.Length ? -1 : 1;
  }

  public static string NameToLower(string name)
  {
    if(name == null) throw new ArgumentNullException();
    char[] newName = new char[name.Length];
    for(int i=0; i<name.Length; i++)
    {
      char c = char.ToLowerInvariant(name[i]);
      if(c == '[') c = '{';
      else if(c == ']') c = '}';
      else if(c == '\\') c = '|';
      newName[i] = c;
    }
    return new string(newName);
  }

  public static string NameToUpper(string name)
  {
    if(name == null) throw new ArgumentNullException();
    char[] newName = new char[name.Length];
    for(int i=0; i<name.Length; i++)
    {
      char c = char.ToUpperInvariant(name[i]);
      if(c == '{') c = '[';
      else if(c == '}') c = ']';
      else if(c == '|') c = '\\';
      newName[i] = c;
    }
    return new string(newName);
  }

  protected Channel EnsureChannelKnown(string channelName)
  {
    Channel channel;
    if(!KnownChannels.TryGetValue(channelName, out channel))
    {
      KnownChannels.Items[channelName] = channel = new Channel(channelName);
    }
    return channel;
  }

  protected ChannelUser EnsureChannelUserKnown(Channel channel, string nickname)
  {
    ChannelUser user;
    if(!channel.Users.TryGetValue(nickname, out user))
    {
      channel.Users.Items[nickname] = user = new ChannelUser(EnsureUserKnown(nickname), ChannelUserFlags.None);
    }
    return user;
  }

  protected User EnsureUserKnown(string name)
  {
    User user;
    if(!KnownUsers.TryGetValue(name, out user)) KnownUsers.Items[name] = user = new User(name);
    return user;
  }

  protected bool IsChannelName(string target)
  {
    if(target == null) throw new ArgumentNullException();
    return target.Length != 0 && (target[0] == '#' || target[0] == '&');
  }

  protected virtual void OnCommand(IrcResponseCodes command, string from, string[] args)
  {
    switch(command)
    {
      case IrcResponseCodes.ChannelCreatedAt:
        OnChannelCreatedAt(args[1], ParseTimestamp(args[2]));
        break;

      case IrcResponseCodes.ChannelModeIs:
        ProcessMode(null, args[1], args, 2);
        break;

      case IrcResponseCodes.NickCollision: case IrcResponseCodes.NicknameInUse:
        if(!registered) SetNickname(GetRandomNick()); // if we haven't been registered yet, try a random nick
        else ExecuteReplyHandler(args[0], "NICK", new NickReply(Nickname, args[0], command));
        break;

      case IrcResponseCodes.Inviting:
        OnInvite(Nickname, args[0], args[1]);
        break;

      case IrcResponseCodes.NoTopic:
        OnTopic(null, args[0], "");
        break;

      case IrcResponseCodes.Topic:
        OnTopic(null, args[1], args[2]);
        break;

      case IrcResponseCodes.TopicInfo:
        OnTopicInfo(GetNickAndUpdateUser(args[2]), args[1], ParseTimestamp(args[3]));
        break;

      case IrcResponseCodes.UserIsAway:
        OnUserIsAway(args[0], args[1]);
        break;

      case IrcResponseCodes.UserIsOn:
        OnUsersAreOn(args[0].Split(' '));
        break;

      case IrcResponseCodes.NameReply:
      {
        Channel channel = EnsureChannelKnown(args[2]);
        char type = args[1][0];
        switch(type)
        {
          case '@': channel.Flags |= ChannelFlags.IsSecret; break;
          case '*': channel.Flags |= ChannelFlags.IsPrivate; break;
          case '=': channel.Flags &= ~(ChannelFlags.IsPrivate | ChannelFlags.IsSecret); break;
        }

        foreach(string nickWithFlag in args[3].Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
          string nick = nickWithFlag;
          ChannelUserFlags userFlags = ChannelUserFlags.None;
          if(nick[0] == '+' || nick[0] == '@')
          {
            nick = nick.Substring(1);
            userFlags = nick[0] == '+' ? ChannelUserFlags.CanSpeak : ChannelUserFlags.IsOperator;
          }
        }
        break;
      }

      case IrcResponseCodes.EndOfNames:
      {
        Channel channel = EnsureChannelKnown(args[1]);
        ExecuteReplyHandlers(channel.Name, "JOIN", new JoinReply(channel, IrcResponseCodes.None));
        break;
      }

      case IrcResponseCodes.BannedFromChannel: case IrcResponseCodes.InviteOnlyChannel:
      case IrcResponseCodes.WrongChannelKey: case IrcResponseCodes.ChannelIsFull:
      case IrcResponseCodes.TooManyChannels: case IrcResponseCodes.NoSuchChannel:
      {
        Channel channel = EnsureChannelKnown(args[1]);
        ExecuteReplyHandlers(channel.Name, "JOIN", new JoinReply(channel, command));
        break;
      }

      case IrcResponseCodes.StartMotd:
        FinishRegistration();
        stringBuffer.Clear();
        break;

      case IrcResponseCodes.Motd:
        stringBuffer.Add(args[0]);
        break;

      case IrcResponseCodes.EndMotd:
        OnMotd(stringBuffer.ToArray());
        break;

      case IrcResponseCodes.Welcome:
        FinishRegistration();
        break;
    }
  }

  protected virtual void OnCommand(string command, string from, string[] args)
  {
    switch(command)
    {
      case "PRIVMSG": case "NOTICE":
      {
        string message = args[1];
        bool isNotice = command[0] == 'N';

        if(message.Length != 0 && message[0] == '\x01') // if it's a CTCP message
        {
          string ctcpCommand;
          string[] ctcpArgs;
          int cmdSep = message.IndexOf(' ', 1);
          if(cmdSep == -1)
          {
            ctcpCommand = message.Substring(1, message.Length-2);
            ctcpArgs    = new string[0];
          }
          else
          {
            ctcpCommand = message.Substring(1, cmdSep-1);
            ctcpArgs    = GetParameterStrings(parmsRe.Matches(message.Substring(cmdSep+1, message.Length-cmdSep-2)));
          }

          if(isNotice) OnCTCPNotice(from, args[0], ctcpCommand, ctcpArgs);
          else OnCTCPMessage(from, args[0], ctcpCommand, ctcpArgs);
        }
        else
        {
          if(isNotice) OnNotice(from, args[0], message);
          else OnMessageReceived(from, args[0], message);
        }
        break;
      }

      case "JOIN":
        OnJoin(from, args[0]);
        break;

      case "PART":
        OnPart(from, args[0]);
        break;

      case "MODE":
        FinishRegistration();
        ProcessMode(from, args[0], args, 1);
        break;

      case "KICK":
        OnKick(from, args[1], args[0], args[2]);
        break;

      case "NICK":
        OnNick(from, args[0]);
        break;

      case "PING":
        OnPing(args[0]);
        break;

      case "INVITE":
        OnInvite(from, args[0], args[1]);
        break;

      case "TOPIC":
        OnTopic(from, args[0], args[1]);
        break;
    }
  }

  protected virtual void OnChannelCreatedAt(string channelName, DateTime? creationTime)
  {
    EnsureChannelKnown(channelName).CreationTime = creationTime;
  }

  protected virtual void OnChannelMode(string whoChangedIt, string channelName, ChannelFlags flagsAdded,
                                       ChannelFlags flagsRemoved, int newUserLimit)
  {
    Channel channel = EnsureChannelKnown(channelName);
    channel.Flags = channel.Flags & ~flagsRemoved | flagsAdded;
    if((flagsAdded & ChannelFlags.HasUserLimit) != 0) channel.UserLimit = newUserLimit;
  }

  protected virtual void OnChannelUserMode(string whoChangedIt, string channelName, string affectedUser,
                                           ChannelUserFlags flagsAdded, ChannelUserFlags flagsRemoved)
  {
    EnsureChannelKnown(channelName).UpdateUser(EnsureUserKnown(affectedUser), flagsAdded, flagsRemoved);
  }

  protected virtual void OnConnect()
  {
  }

  protected virtual void OnCTCPMessage(string from, string to, string command, string[] args)
  {
    if(AreNamesEqual(to, Nickname)) // if it was sent to us...
    {
      if(string.Equals(command, "PING", StringComparison.OrdinalIgnoreCase))
      {
        if(args.Length != 0) SendCTCPNotice(from, "PING " + args[0]);
      }
      else if(string.Equals(command, "TIME", StringComparison.OrdinalIgnoreCase))
      {
        SendCTCPNotice(from, "TIME " + DateTime.Now.ToString("r", CultureInfo.InvariantCulture));
      }
      else if(string.Equals(command, "VERSION", StringComparison.OrdinalIgnoreCase))
      {
        SendCTCPNotice(from, "VERSION IrcLib " + System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString());
      }
    }
  }

  protected virtual void OnCTCPNotice(string from, string to, string command, string[] args)
  {
  }

  protected virtual void OnDisconnect(bool intentional)
  {
    Reset();
    if(intentional) RemoteEndPoint = null;
  }

  protected virtual void OnInvalidInput(string line)
  {
  }

  protected virtual void OnInvite(string inviter, string invited, string channelName)
  {
  }

  protected virtual void OnJoin(string user, string channelName)
  {
    Channel channel = EnsureChannelKnown(channelName);
    EnsureChannelUserKnown(channel, user);

    if(AreNamesEqual(user, Nickname) && !JoinedChannels.ContainsKey(channelName))
    {
      JoinedChannels.Items[channelName] = channel;
      // if we joined the channel, reset these to default values because they could have changed while we were out,
      // and the new values aren't known yet
      channel.Topic = channel.TopicSetBy = null;
      channel.TopicSetTime = channel.CreationTime = null;
      channel.Flags = ChannelFlags.None;
      channel.UserLimit = 0;
      SendRawCommand("MODE " + channelName); // and then request that the server update the channel mode
    }
  }

  protected virtual void OnKick(string kicker, string kicked, string channelName, string kickText)
  {
    OnUserLeftChannel(kicked, channelName);
  }

  protected virtual void OnMessageReceived(string from, string to, string text)
  {
  }

  protected virtual void OnMessageSent(IEnumerable<string> to, string text)
  {
  }

  protected virtual void OnMotd(string[] motdLines)
  {
  }

  protected virtual void OnNick(string oldNick, string newNick)
  {
    KnownUsers.OnNameChanged(oldNick, newNick);

    // TODO: this may be too much of a hit when KnownChannels contains a lot of items (for instance after a LIST command)
    foreach(Channel channel in KnownChannels) channel.Users.OnNameChanged(oldNick, newNick);

    if(Nickname == null || AreNamesEqual(oldNick, Nickname))
    {
      Nickname = newNick;
      ExecuteReplyHandler(newNick, "NICK", new NickReply(oldNick, newNick, IrcResponseCodes.None));
    }
  }

  protected virtual void OnNotice(string from, string to, string text)
  {
  }

  protected virtual void OnPart(string user, string channelName)
  {
    OnUserLeftChannel(user, channelName);
  }

  protected virtual void OnPing(string server)
  {
    SendRawCommand("PONG " + server);
  }

  protected virtual void OnRawInput(string line)
  {
    Match m = messageRe.Match(line);
    if(!m.Success)
    {
      OnInvalidInput(line);
      return;
    }

    string command = m.Groups["command"].Value, from = m.Groups["from"].Value, nickname = GetNickAndUpdateUser(from);
    string[] args = GetParameterStrings(parmsRe.Matches(m.Groups["params"].Value));

    if(char.IsDigit(command[0]))
    {
      OnCommand((IrcResponseCodes)int.Parse(command), nickname, args);
    }
    else
    {
      OnCommand(command.ToUpperInvariant(), nickname, args);
    }
  }

  protected virtual void OnRawOutput(string line)
  {
  }

  protected virtual void OnTopic(string whoChangedIt, string channelName, string newTopic)
  {
    EnsureChannelKnown(channelName).Topic = newTopic;
  }

  protected virtual void OnTopicInfo(string whoSetIt, string channelName, DateTime? setTime)
  {
    Channel channel = EnsureChannelKnown(channelName);
    channel.TopicSetBy   = whoSetIt;
    channel.TopicSetTime = setTime;
  }

  protected virtual void OnUsersAreOn(string[] users)
  {
  }

  protected virtual void OnUserIsAway(string user, string awayMessage)
  {
  }

  protected virtual void OnUserMode(string user, UserFlags flagsAdded, UserFlags flagsRemoved)
  {
    User userObj = EnsureUserKnown(user);
    userObj.Flags = userObj.Flags & ~flagsRemoved | flagsAdded;
  }

  protected string MakeTargetList(IEnumerable<string> targets)
  {
    if(targets == null) throw new ArgumentNullException();

    StringBuilder sb = new StringBuilder();
    foreach(string target in targets)
    {
      if(sb.Length != 0) sb.Append(',');
      sb.Append(target);
    }
    if(sb.Length == 0) throw new ArgumentException("No target given.");
    return sb.ToString();
  }

  protected string[] ParseTargetList(string targets)
  {
    return targets.Split(',');
  }

  protected static int GetCurrentTimestamp()
  {
    return GetTimestamp(DateTime.Now);
  }

  protected static int GetTimestamp(DateTime time)
  {
    return (int)Math.Round((time - new DateTime(1970, 1, 1, 0, 0, 0, time.Kind)).TotalSeconds);
  }

  protected static DateTime? ParseTimestamp(string arg)
  {
    int unixTime;
    if(int.TryParse(arg, out unixTime)) return new DateTime(1970, 1, 1).AddSeconds(unixTime);
    else return null;
  }

  protected static string StripControlCharacters(string text)
  {
    if(text == null) throw new ArgumentNullException();

    char[] chars = new char[text.Length];
    int newLength = 0;
    for(int i=0; i<text.Length; i++)
    {
      char c = text[i];
      if(c >= 32) chars[newLength++] = c;
    }
    return new string(chars, 0, newLength);
  }

  void AddReplyHandler<T>(string name, string type, ReplyHandler<T> handler)
  {
    if(handler != null)
    {
      List<Delegate> handlerList;
      string key = name + " " + type;
      if(!handlers.TryGetValue(key, out handlerList)) handlers[key] = handlerList = new List<Delegate>(4);
      handlerList.Add(handler);
    }
  }

  void AssertConnected()
  {
    if(!IsConnected) throw new InvalidOperationException("The is client not connected.");
  }

  void ExecuteReplyHandler<T>(string name, string type, T reply)
  {
    ExecuteReplyHandlers(name, type, reply, true);
  }

  void ExecuteReplyHandlers<T>(string name, string type, T reply)
  {
    ExecuteReplyHandlers(name, type, reply, false);
  }

  void ExecuteReplyHandlers<T>(string name, string type, T reply, bool stopAfterFirst)
  {
    List<Delegate> handlerList;
    if(handlers.TryGetValue(name + " " + type, out handlerList))
    {
      for(int i=0; i<handlerList.Count; )
      {
        ReplyHandler<T> handler = handlerList[i] as ReplyHandler<T>;
        if(handler != null)
        {
          handler(reply);
          handlerList.RemoveAt(i);
          if(stopAfterFirst) break;
        }
        else i++;
      }
    }
  }

  void FinishRegistration()
  {
    User = EnsureUserKnown(Nickname);
    registered = true;
  }

  /// <summary>Given a nickname or user ID, returns the nickname. If a user ID was given, the corresponding
  /// <see cref="User"/> will be updated, if it is known.
  /// </summary>
  string GetNickAndUpdateUser(string userId)
  {
    int bang = userId.IndexOf('!');
    if(bang == -1)
    {
      return userId;
    }
    else
    {
      string nickname = userId.Substring(0, bang);

      User user;
      if(KnownUsers.TryGetValue(nickname, out user))
      {
        int at = userId.IndexOf('@', bang+1);
        if(at == -1)
        {
          user.UserName = userId.Substring(bang+1);
        }
        else
        {
          user.UserName = userId.Substring(bang+1, at-(bang+1));
          user.HostName = userId.Substring(at+1);
        }
      }

      return nickname;
    }
  }

  void OnUserLeftChannel(string user, string channelName)
  {
    if(AreNamesEqual(user, Nickname))
    {
      JoinedChannels.Items.Remove(channelName);
    }
    else
    {
      EnsureChannelKnown(channelName).Users.Items.Remove(user);
    }
  }

  void ProcessMode(string whoChangedIt, string target, string[] args, int index)
  {
    string modeString = args[index++];
    bool adding = true;

    if(IsChannelName(target))
    {
      Channel channel = EnsureChannelKnown(target);
      foreach(char c in modeString)
      {
        ChannelFlags flag = ChannelFlags.None;
        ChannelUserFlags userFlag = ChannelUserFlags.None;

        if(c == '+') adding = true;
        else if(c == '-') adding = false;
        else if(c == 'p') flag = ChannelFlags.IsPrivate;
        else if(c == 's') flag = ChannelFlags.IsSecret;
        else if(c == 'i') flag = ChannelFlags.IsInviteOnly;
        else if(c == 't') flag = ChannelFlags.RestrictedTopic;
        else if(c == 'n') flag = ChannelFlags.NoExternalMessages;
        else if(c == 'm') flag = ChannelFlags.Moderated;
        else if(c == 'l') flag = ChannelFlags.HasUserLimit;
        else if(c == 'k') flag = ChannelFlags.HasPassword;
        else if(c == 'o') userFlag = ChannelUserFlags.IsOperator;
        else if(c == 'v') userFlag = ChannelUserFlags.CanSpeak;
        else if(c == 'b' || c == 'I') index++; // ban mask or invite mask

        if(flag != ChannelFlags.None)
        {
          if(adding) channel.Flags |= flag;
          else channel.Flags &= ~flag;

          if(flag == ChannelFlags.HasUserLimit)
          {
            if(!adding) channel.UserLimit = 0;
            else if(index < args.Length) channel.UserLimit = int.Parse(args[index++]);
          }
          else if(flag == ChannelFlags.HasPassword)
          {
            if(!adding) channel.Password = null;
            else if(index < args.Length) channel.Password = args[index++];
          }
        }
        else if(userFlag != ChannelUserFlags.None)
        {
          if(index < args.Length)
          {
            ChannelUser user = EnsureChannelUserKnown(channel, args[index++]);
            if(adding) user = new ChannelUser(user.User, user.Flags | userFlag);
            else user = new ChannelUser(user.User, user.Flags & ~userFlag);
            channel.Users.Items[user.User.Name] = user;
          }
        }
      }
    }
    else
    {
      User user = EnsureUserKnown(target);
      foreach(char c in modeString)
      {
        UserFlags flag = UserFlags.None;
        if(c == '+') adding = true;
        else if(c == '-') adding = false;
        else if(c == 'i') flag = UserFlags.Invisible;
        else if(c == 's') flag = UserFlags.ReceivesServerNotices;
        else if(c == 'w') flag = UserFlags.ReceivesWallops;
        else if(c == 'o') flag = UserFlags.IsServerOperator;

        if(flag != UserFlags.None)
        {
          if(adding) user.Flags |= flag;
          else user.Flags &= flag;
        }
      }
    }
  }

  void Reset()
  {
    if(socket != null)
    {
      socket.Close();
      socket = null;
    }

    textBuffer = null;
    User = null;
    JoinedChannels.Items.Clear();
    KnownChannels.Items.Clear();
    KnownUsers.Items.Clear();
    handlers.Clear();
    stringBuffer.Clear();
    registered = false;
  }

  List<string> stringBuffer = new List<string>();
  Dictionary<string, List<Delegate>> handlers = new Dictionary<string, List<Delegate>>();
  Socket socket;
  byte[] textBuffer;
  int textBufferBytes;
  bool registered;

  static string[] GetParameterStrings(MatchCollection matches)
  {
    string[] values = new string[matches.Count];
    for(int i=0; i<values.Length; i++)
    {
      values[i] = matches[i].Value[0] == ':' ? matches[i].Value.Substring(1) : matches[i].Value;
    }
    return values;
  }

  static string GetRandomNick()
  {
    Random rand = new Random();
    char[] chars = new char[9]; // 9 characters in the maximum nickname length in the IRC standard
    for(int i=0; i<chars.Length; i++) chars[i] = (char)(rand.Next(26) + 'a');
    return new string(chars);
  }

  static readonly Regex messageRe = new Regex(@"
    ^(:(?<from>\S+)?\x20+)?
     (?<command>([a-zA-Z]+|\d\d\d))
     (\x20+(?<params>.*))?$", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture |
                              RegexOptions.IgnorePatternWhitespace | RegexOptions.Singleline);
  
  static readonly Regex parmsRe =
    new Regex(@":[^\x00\r\n]*|[^:\x00\x20\r\n][^\x00\x20\r\n]*", RegexOptions.Compiled | RegexOptions.Singleline);

  static readonly byte[] crlf = { 13, 10 };

  static readonly Encoding encoding = Encoding.Default;
}

} // namespace IrcLib