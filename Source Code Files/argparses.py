import pymongo
import argparse
import sys

# import analysis.gather_syzfixpoc_trace
from analysis import gather_syzfixpoc_trace
# import argexec
from analysis import analy_poclognor_strace
from analysis import analy_poclogbug_strace

labname = "AimLab"
datasetname = "DongTing Dataset"
version = "2022"


def get_version():
    verinfo = f"Labname: {labname}\nDS name: {datasetname}\nVersion: {version}"
    return verinfo

def system_init():
    mydbclient = pymongo.MongoClient("mongodb://localhost:27017/")
    databaselist = mydbclient.list_database_names()
    if "syzbot_DB" not in databaselist:
        print("Database syzbot_DB does not exist, creating...")
        mydb = mydbclient["syzbot_DB"]
        mycol = mydb["test1"]
        mylist = {"test": "test1"}
        mycol.insert_one(mylist)
        msg="Database initialized successfully"
    else:
        msg="The detection database is successful, and no initialization is required."
    return msg

def argv_input():
    # 1 level command
    parser = argparse.ArgumentParser(description="AimLab DongTing DataSet",
                                     epilog="Example:\n python *.py -g -add  Add lab server data.\n")
    parser.add_argument("-g", "--gather", help="Enable the gather", action="store_true")
    # parser.add_argument("-c", "--classes", help="Enable classifiers", action="store_true")
    parser.add_argument("-a", "--analysis", help="Enable profiler", action="store_true")
    parser.add_argument("-q", "--quit", help="Exit pro", action="store_true")
    parser.add_argument("-v", "--version", help="Display version", action="version", version=get_version())
    parser.add_argument("-i", "--init", help="System init", action="version", version=system_init())

    # # 2 level command
    parser.add_argument("-add", "--addserver", help="add lab server", action="store_true")
    parser.add_argument("-syz", "--syzbot", help="Only syzbot classification is performed", action="store_true")
    # parser.add_argument("-exp", "--exploitdb", help="Only syzbot classification is performed", action="store_true")
    # parser.add_argument("-cve", "--cve", help="Only cve classification is performed", action="store_true")
    # parser.add_argument("-cvd", "--cnnvd", help="Only cnvd classification is performed", action="store_true")
    parser.add_argument("-nor", "--normal", help="Only analysis normal strace", action="store_true")
    # 3 level command
    parser.add_argument("-lot", "--lot", type=int, default=1, help="gather lot", nargs='*')

    our_args = parser.parse_args()
    # print(our_args)
    if True not in our_args.__dict__.values():
        print("Warning: To use this program, you need to enter commands. \n"
              "Example1: python *.py -a -all  It is enable Analyze all the data.\n"
              "Example2: python *.py -q       Exit pro.\n")
    return our_args


def argv_exec():
    args = argv_input()
    osclass = "linux"

    if args.gather:
        if args.addserver:
            gather_syzfixpoc_trace.Analysis_main("all", "add", "1")
        elif args.syzbot:
            print("---------DongTing Part1:Syzbot Bug Strace Log collected---------")
            lot_list = args.lot
            if len(lot_list) < 1:
                print("Batch not entered")
            else:
                for lot_s in lot_list:
                    print(lot_s)
                    gather_syzfixpoc_trace.Analysis_main("All", "stopadd", str(lot_s))
                    print(f"Completed batch {lot_s}")
            # print(args.syzbot)
            # print(args.lot)

        elif args.normal:
            print("---------DongTing Part1: normal Bug Strace Log 收集---------")
            print(2)

    elif args.analysis:
        if args.syzbot:
            print("---------DongTing Part2:Syzbot Bug Strace Log System call sequence data analysis---------")
            src_path = "poc_out_syz"
            pocsource = "syzbot"
            analy_poclogbug_strace.Analy_main(src_path, pocsource)

        elif args.normal:
            # argexec.analysis_strace_dataandcount()
            print("---------DongTing Part2:Normal Strace Log System call sequence data analysis---------")
            analy_poclognor_strace.Analy_main()
            print("Strace Normal Log and MlSeq Analysis is ok")
    # exit system
    elif args.quit:
        print("Exit the program when the current task is completed.")
        sys.exit(0)

# Instructions for using the command
###################################################################
# -i,init             # Initialize the database
# -g,gather           # Enable LOG collection
#   -add              # Add experimental server
#   -syz              # Collect the LOG of the POC in syz
#       -lot num      # Open the batch for collecting LOG, num can be multiple integers, separated by spaces
#   -nor              # Collect LOG in suit
# -a,analysis         # Enable analysis of syscalls
#   -syz              # Analyze syz source data
#   -nor              # Analyze the normal data of strace
# -q,quit             # quit program
# -v,version          # Version information
###################################################################

if __name__ == "__main__":
    argv_exec()
    # argv_input()
