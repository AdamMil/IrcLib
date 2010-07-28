using System;
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("IrcLib")]
[assembly: AssemblyDescription("A library that implements an IRC client.")]
#if DEBUG
[assembly: AssemblyConfiguration("Debug")]
#else
[assembly: AssemblyConfiguration("Release")]
#endif
[assembly: AssemblyProduct("AdamMil.net")]
[assembly: AssemblyCopyright("Copyright © Adam Milazzo 2009-2010")]

[assembly: ComVisible(false)]

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

[assembly: CLSCompliant(true)]