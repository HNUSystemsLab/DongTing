import pymongo

mydbclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = mydbclient["syzbot_DB"]


def listwrite(listname, listdata):
    mycol = mydb[listname]
    mycol.insert_many(listdata)


def listreadall(listname):
    dblist = mydb.list_collection_names()
    if listname not in dblist:
        print(f"Input error: The collection{listname} does not exist in the database.")
    else:
        mycol = mydb[listname]
        i = 0
        for myselectall in mycol.find():
            i += 1
            print(myselectall)
        print(f"Total {str(i)} records!")


def listread_detection(listname, field, fieldvaule):
    mycol = mydb[listname]
    myselectcount = mycol.count_documents({field: fieldvaule})
    return myselectcount


if __name__ == "__main__":
    listname = "kernel_fixed_listtable"
    field = "fixed_defect_title"
    fieldvaule = "UBSAN: shift-out-of-bounds in qdisc_get_rtab"
    # listreadall(listname)
    print(listread_detection(listname, field, fieldvaule))
