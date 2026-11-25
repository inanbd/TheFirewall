# Third-party notices

TheFirewall is released under the MIT License (see [LICENSE](LICENSE)). It includes or builds on the following work.

## IPBan

TheFirewall is inspired by [IPBan](https://github.com/DigitalRuby/IPBan). The Windows Firewall COM interface layouts
(`src/TheFirewall.Service/Windows/FirewallCom.cs`) and several login detection expressions
(`src/TheFirewall.Core/Configuration/BuiltInSources.cs`) are adapted from IPBan.

```
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## DB-IP (country database, downloaded at runtime)

The country database is downloaded from [db-ip.com](https://db-ip.com) and is not distributed with TheFirewall.
"IP to Country Lite" by DB-IP is licensed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
The app shows the required attribution ("IP geolocation by DB-IP") on the Countries and About pages.

## flag-icons (country flags)

The country flags in `src/TheFirewall.App/Assets/Flags` are rendered from [flag-icons](https://github.com/lipis/flag-icons)
7.6.0 by `build/generate-flags.py`.

```
The MIT License (MIT)

Copyright (c) 2013 Panayiotis Lipiridis

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Libraries

| Package | License |
| --- | --- |
| .NET runtime, WPF, Windows Forms, Microsoft.Extensions.*, System.Diagnostics.EventLog, System.ServiceProcess.ServiceController | MIT, (c) .NET Foundation and Contributors |
| Microsoft.Data.Sqlite | MIT, (c) .NET Foundation and Contributors |
| SQLitePCLRaw | Apache License 2.0, (c) Zumero, LLC |
| SQLite | Public domain |
| CommunityToolkit.Mvvm | MIT, (c) .NET Foundation and Contributors |
| xUnit.net (tests only) | Apache License 2.0 |
| WiX Toolset 5 (build tool for the installer, not redistributed) | MS-RL |

## Threat feeds

Threat feeds are optional and disabled by default. Each list is downloaded directly from its publisher
(Emerging Threats, Spamhaus, blocklist.de, CINS Army, IPsum) and is subject to that publisher's terms of use.
