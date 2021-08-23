

# PyHook

PyHook is the python implementation of my [SharpHook](https://github.com/IlanKalendarov/SharpHook) project, It uses various API hooks in order to give us the desired credentials.

PyHook Uses frida to inject it's dependencies into the target process

# Supported Processes

| Process               | API Call                          | Description                                                  | Progress |
| --------------------- | --------------------------------- | ------------------------------------------------------------ | -------- |
| mstsc                 | `CredUnPackAuthenticationBufferW` | This will hook into mstsc and should give you Username and Password | DONE     |
| runas                 | `CreateProcessWithLogonW`         | This will hook into runas and should give you Username, Password and the domain name | DONE     |
| cmd                   | `RtlInitUnicodeStringEx`          | This should hook into cmd and then would be able to filter keywords like: PsExec,password etc.. | DONE     |
| MobaXterm             | `CharUpperBuffA`                  | This will hook into MobaXterm and should give you credentials for SSH and RDP logins | DONE     |
| explorer (UAC Prompt) | `CredUnPackAuthenticationBufferW` | This will hook into explorer and should give you Username, Password and the Domain name from the UAC Prompt | DONE     |

# Demo

![](https://github.com/IlanKalendarov/PyHook/blob/main/Demo/Demo.gif)

Link my blog post covering this topic: https://ilankalendarov.github.io/posts/offensive-hooking
