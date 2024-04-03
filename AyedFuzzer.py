import pykd
import datetime
import os
import random
import multiprocessing
import shutil

def mutate_files(target_program):
    print("\n\t[+] FILE MUTATOR [+]\t\n")

    target_folder = f".\\testcases\\{target_program}"
    os.makedirs(target_folder, exist_ok=True)

    num_fuzz_corpus = int(input("Enter the number of fuzz corpus: "))

    testcases_per_corpus = []

    for i in range(num_fuzz_corpus):
        num_testcases = int(input(f"Enter the number of testcases for fuzz corpus {i+1}: "))
        testcases_per_corpus.append(num_testcases)

    input_files = []
    for i in range(num_fuzz_corpus):
        input_file = input(f"Enter the path of fuzz corpus {i+1}: ")
        input_files.append(input_file)

    extension_type = input("Enter the extension of output: ")

    for i, num_testcases in enumerate(testcases_per_corpus):
        corpus_folder = f"{target_folder}\\corpus_{i+1}\\"
        os.makedirs(corpus_folder, exist_ok=True)
        input_file = input_files[i]
        
        print(f"\nCorpus {i+1}:")
        print(f"Number of Test Cases: {num_testcases}")

        for testcase_index in range(1, num_testcases + 1):
            output_file = f"{corpus_folder}\\testcase_{i+1}_{testcase_index}.{extension_type}"
            mutationTypes = ["ab", "bd", "bf", "bi", "br", "bp", "bed", "ber", "sr", "ld", "lds", "lr2", "li", "ls", "lis", "ui", "num", "fo", "fn"]
            number_of_elements_to_choose = random.randint(1, 19)
            random.shuffle(mutationTypes)
            selected_elements = mutationTypes[:number_of_elements_to_choose]
            result = ",".join(selected_elements)
            command = f"radamsa.exe -m {result} {input_file} > {output_file}"
            os.system(command)
            print(f"Mutation type for testcase {testcase_index}: {result}")
            print(f"Output saved to: {output_file}\n")

    total_testcases = sum(testcases_per_corpus)
    print(f"\n\n[+] Testcases saved successfully.")
    print(f"Total testcases: {total_testcases}\n\n\n")
    main()


class ExceptionHandler(pykd.eventHandler):
    def __init__(self):
        pykd.eventHandler.__init__(self)
        self.accessViolationOccured = False
        self.bOver=0
        self.address = 0
        self.type = 0
        self.code = 0
    def onException(self, exceptInfo):        
        print("[+] Exception code {}\n".format(hex(exceptInfo.exceptionCode)))

        self.accessViolationOccured = exceptInfo.exceptionCode == 0xC0000005
       
        if self.accessViolationOccured:
            self.bOver = 1
            self.type = exceptInfo.parameters[0]
            self.address = exceptInfo.parameters[1]
            self.code = exceptInfo.exceptionCode
            return pykd.eventResult.Break

        if exceptInfo.firstChance:
            return pykd.eventResult.NoChange

        return pykd.eventResult.Break



def windbg_monitr(target_program):
    
    print("\n\t[+] Welcome to WinDBG Monitor [+]\n")
    print("\n\tUsage:\t Enter <target program>\n\t\t Enter <argument>\n\n")

    process_path = input("\nEnter the path of executable: ")
    process_args = input("Please Enter the argument: ")
    
    log = "\n===============================\nExecutable Path : " + process_path + "\n" + "Arguments : " + process_args + "\n===============================\n"
    print(log)
  
    while (True):

        pykd.startProcess(process_path + " " + process_args, pykd.ProcessDebugOptions.BreakOnStart | pykd.ProcessDebugOptions.DebugChildren)
        

        command = input("PyKD> ")
        result = pykd.dbgCommand(command)
        print(result)

        expHandler = ExceptionHandler()

        if expHandler.accessViolationOccured:
            print("\n[+] CRASH FOUND [+]\n")
            logging(process_args, target_program)
        elif command == "exit":
            print("\n[x] Exiting..\n")
            main()
        else:
            print("NO CRASH HAPPEND [X]")

        
    


def logging(testcase_crash_caused, target_program):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        log_folder = f".\\logs\\{target_program}_logs"
        os.makedirs(log_folder, exist_ok=True)
        log_path = f"{log_folder}\\log_{current_time}.txt"

        pykd.loadExt(".\\MSEC.dll")
        exploitable_check = pykd.dbgCommand("!exploitable")
        exploitable_result_str = str(exploitable_check)
    
        new_hash = str(exploitable_result_str.split("=")[1].split(")")[0])    
        print(f"Major & Minor are: {new_hash}")

        g_hashes_file = ".\\logs\\unique\\hashes.txt"
        hashes_file = open(g_hashes_file, "r")
        hashes_lines = hashes_file.readlines()
        hashes_counter = 0
        for x in hashes_lines:
            if(str(new_hash + '\n') == str(x)):
                hashes_counter = hashes_counter + 1
        
        hashes_file.close()
        print("[+] Number of hashes found: " + str(hashes_counter))
        if(hashes_counter < 1):
            hashes_file = open(g_hashes_file, "a") # "a" > "w"
            log_unique = "-----------------------------------------------------\n"
            log_unique += f"[+] Log Path: {log_path}"
            log_unique += f"[+] Testcase number: {testcase_crash_caused}\n"
            log_unique += f"[+] Major & Minor hash: {new_hash}\n"
            hashes_file.write(str(log_unique))
            hashes_file.close()

        expHandler = ExceptionHandler()
        with open(log_path, "w") as f:
            logs = "\n=================CRASH LOG DETAILS===================\n"
            logs += "-----------------------------------------------------\n"
            logs += "|_________________Exception Type:___________________|\n"
            logs += str(expHandler.type) + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|________________Exception Address:_________________|\n"
            logs += hex(expHandler.address) + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|________________Disassembly before:________________|\n"
            logs += pykd.dbgCommand("ub") + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|________________Disassembly after:_________________|\n"
            logs += pykd.dbgCommand("u") + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|_____________________Registers:____________________|\n"
            logs += pykd.dbgCommand("r") + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|____________________call stack:____________________|\n"
            logs += pykd.dbgCommand("kvn") + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|_____________________modules:______________________|\n"
            logs += pykd.dbgCommand("lm") + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|________________Exploitable Check:_________________|\n"
            logs += str(exploitable_check) + "\n\n"
            logs += "-----------------------------------------------------\n"
            logs += "|________________Vulnerable Testcase:_________________|\n\n"
            logs += f"[+] testcase causes the crash is: {testcase_crash_caused}\n"
            logs += "\n-----------------------------------------------------\n"
            logs += "-----------------------------------------------------\n"
            logs += "=====================================================\n\n"
            f.write(logs)
        f.close()
        print(f"\n[+] Crash log saved to: {log_path}")




def fuzz_single_testcase(corpus_folder, testcase, process_path, target_program):
    pykd.initialize()
    expHandler = ExceptionHandler()
    pid = pykd.startProcess(process_path + " " + testcase, pykd.ProcessDebugOptions.BreakOnStart | pykd.ProcessDebugOptions.DebugChildren)
    pykd.dbgCommand("g")
    pykd.dbgCommand("g")

    if expHandler.accessViolationOccured:
        print("\n\n\n[+] !!! CRASH !!!")
        logging(testcase, target_program)
        print(f"\n\n{testcase}\n\n")
        pykd.killProcess(pid)
    else:
        print("NO CRASH HAPPENED [X]")
        pykd.killProcess(pid)


def fuzz_single_corpus(corpus_folder, process_path, testcases_dir, target_program, num_processes):
    corpus_path = os.path.join(testcases_dir, corpus_folder)
    testcases = [os.path.join(corpus_path, f) for f in os.listdir(corpus_path) if os.path.isfile(os.path.join(corpus_path, f))]

    processes = []
    for i in range(0, len(testcases), num_processes):
        chunk = testcases[i:i + num_processes]
        for testcase in chunk:
            p = multiprocessing.Process(target=fuzz_single_testcase, args=(corpus_folder, testcase, process_path, target_program))
            processes.append(p)
            p.start()

        for p in processes:
            p.join()

    print(f"[+] Fuzzing for testcases in {corpus_folder} ends successfully.")


def fuzzer_multiprocessing(target_program):
    print("\n\t[+] Welcome to Multi-Processing Fuzzer [+]\n")

    target_folder = f".\\testcases\\{target_program}"
    os.makedirs(target_folder, exist_ok=True)

    pykd.initialize()
    expHandler = ExceptionHandler()

    process_path = input("Enter the process path: ")
    process_args = input("Enter the arguments of the executable: ")
    testcases_dir = target_folder

    if not os.path.exists(process_path):
        print("\n[x] Invalid program path.")
        return
    if not os.path.exists(testcases_dir):
        print("\n[x] No current testcases files.")
        return

    log = "\n===============================\nExecutable Path: " + process_path + "\n" + "Arguments: " + process_args + "\n" + "Testcases Directory: " + testcases_dir + "\n===============================\n"
    print(log)

    corpus_folders = [f for f in os.listdir(target_folder) if os.path.isdir(os.path.join(target_folder, f))]
    sorted_corpus_folders = sorted(corpus_folders, key=lambda x: int(''.join(filter(str.isdigit, x.replace("corpus", "")))))

    fuzz_all_corpora = input("Do you want to fuzz all the corpus directories? (Y/n): ")

    if fuzz_all_corpora.lower() == "n":
        print("\nAvailable corpus directories:")
        for i, corpus_folder in enumerate(sorted_corpus_folders, start=1):
            print(f"{i}. {corpus_folder}")
        corpus_choice = input("\nEnter the corpus number to fuzz: ")
        if corpus_choice.isdigit() and int(corpus_choice) in range(1, len(sorted_corpus_folders) + 1):
            corpus_choice = sorted_corpus_folders[int(corpus_choice) - 1]
        else:
            print("\n[x] Invalid corpus number.")
            return
        sorted_corpus_folders = [corpus_choice]
    
    num_processes_per_corpus = int(input("\nEnter the number of multi-processes per corpus directory: "))

    processes = []
    for corpus_folder in sorted_corpus_folders:
        p = multiprocessing.Process(target=fuzz_single_corpus, args=(corpus_folder, process_path, testcases_dir, target_program, num_processes_per_corpus))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    print("[+] Fuzzing ends successfully.")




def save_target(target_program):
    existing_targets = set()
    if os.path.exists("target_programs.txt"):
        with open("target_programs.txt", 'r') as file:
            existing_targets = set(file.read().splitlines())

    if target_program not in existing_targets:
        with open("target_programs.txt", 'a') as file:
            file.write(target_program + '\n')
        print(f"Target program '{target_program}' saved.")
    else:
        print(f"Target program '{target_program}' already exists.")

def display_existing_targets():
    if os.path.exists("target_programs.txt"):
        with open("target_programs.txt", 'r') as file:
            targets = file.read().splitlines()
            print("Existing Targets:")
            for target in targets:
                print(f"- {target}")
            print()

    
def main():

    ascii_art = '''

    

 ░░░░░░███████ ]▄▄▄▄▄▄▄▄ -->  [+] AyedFuzzer [+]
 ▂▄▅█████████▅▄▃▂        
[███████████████████]. 
◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤.. 
Twitter: @lus33r
'''

    print(ascii_art)
    print("\n")
    
    display_existing_targets()
    target_program = input("Enter your target: ")
    save_target(target_program)
    print("\n",target_program)
    
    print("\nPlease select an option:")
    print("\n1. File mutating")
    print("2. Interacting WinDBG monitor")
    print("3. Fuzzing Multi-Processing")
    print("4. Exit")

    option = input("\nEnter your choice (from 1 to 4): ")
    if option == "1":
        mutate_files(target_program)
    elif option == "2":
        windbg_monitr(target_program)
    elif option == "3":
        fuzzer_multiprocessing(target_program)
    elif option == "4":
        print("\nExiting..\n")
        exit(1)
    else:
        print("\n[x] Invalid choice. Please select either from (1-5).")
        main()



if __name__ == "__main__":
    main()