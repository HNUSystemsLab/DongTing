import argparses
import datetime as t
import sys

'''
The following operations need to be done before executing MAIN all.
1, the local database Monogo is installed and can run normally (Note: the experimental version is not encrypted).
2, run Main.py, the database, collection program will be automatically created.
'''

def main():
    try:
        argparses.argv_exec()
        exec_start = False
    except:
        exec_start = True

    if exec_start:
        print(f"Network error ({t.datetime.now().strftime('%m-%d %H:%M:%S')}),"
              f"The system is reconnecting! To stop, please Kill the process.")

if __name__ == "__main__":
    main()
