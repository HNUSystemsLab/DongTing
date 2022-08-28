#!/bin/bash
#echo "*************** Win backup db start **************"
.\mongodump -h 127.0.0.1:27017 -d syzbot_DB -o D:\dbbak

# or

echo "*************** Ubuntu backup db start **************"
# mongodb copy dir
#mongodbcpdir=/home/z/kernel-security/mongodb-cp
cp_local_src_dir=/home/admin/mongodbbak/src
# mongodb database
re_local_dst_dir=/home/admin/mongodbbak/localdata

echo "*************** backup db start **************"
mongodump -h 127.0.0.1:27017 -d syzbot_DB -o $cp_local_src_dir >/dev/null
RV1=$?
if [ $RV1 -ne 0 ]; then
    echo "database back-up failed!!!!"
    exit 0
fi
echo "*************** backup db successfully **************"

# Ubuntu restore from local
echo "*************** restore db start **************"
mongorestore -h 127.0.0.1:27017 -d syzbot_DB $cp_local_src_dir >/dev/null
RV2=$?
if [ $RV2 -ne 0 ]; then
    echo "database restore failed!!!!"
    exit 0
fi
echo "*************** restore db successfully **************"

echo "*************** backup and restore db successfully **************"
