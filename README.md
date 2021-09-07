

# PyHook

PyHook is the python implementation of my [SharpHook](https://github.com/IlanKalendarov/SharpHook) project, It uses various API hooks in order to give us the desired credentials.

PyHook Uses frida to inject it's dependencies into the target process

# Supported Processes

| Process               | API Call                          | Description                                                  | Progress |
| --------------------- | --------------------------------- | ------------------------------------------------------------ | -------- |
| mstsc                 | `CredUnPackAuthenticationBufferW` | Hooks `CredUnPackAuthenticationBufferW` from mstsc and outputs username and password | DONE     |
| runas                 | `CreateProcessWithLogonW`         | Hooks `CreateProcessWithLogonW` from runas and outputs username, password and a domain name. | DONE     |
| PowerShell            | `CreateProcessWithLogonW`         | Hooks `CreateProcessWithLogonW` from PowerShell and outputs username, password and a domain name (e.g - `Start-Process cmd -Credential X`). | DONE     |
| cmd                   | `RtlInitUnicodeStringEx`          | Hooks `RtlInitUnicodeStringEx` from cmd and outputs data from specific filters (e.g - "-p", "password" etc). | DONE     |
| MobaXterm             | `CharUpperBuffA`                  | Hooks `CharUpperBuffA` from MobaXterm and outputs credentials for RDP and SSH logins. | DONE     |
| explorer (UAC Prompt) | `CredUnPackAuthenticationBufferW` | Hooks `CredUnPackAuthenticationBufferW` from explorer and outputs username, password and a domain name. | DONE     |

# Demo

![](https://github.com/IlanKalendarov/PyHook/blob/main/Demo/Demo.gif)

Link my blog post covering this topic: https://ilankalendarov.github.io/posts/offensive-hooking
