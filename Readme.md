# DongTing: A Large-scale Dataset for Anomaly Detection of the Linux Kernel

DongTing is the first large-scale dataset dedicated to Linux kernel anomaly detection. The dataset covers Linux kernels released in the last five years and includes a total of 18,966 well-labeled normal and attack sequences. The entire dataset is 85GB in size (after decompression). The attack data covers 26 major kernel releases and contains a total of 12,116 system call sequences collected from running 17,855 bug-triggering programs. The normal data comes from 6,850 normal programs in four kernel regression test suites. We maintain the dataset and source code in Zenodo and Github, respectively, and back up the dataset and code in Baidu netdisk.

```bib
@article{DUAN2023111745,
title = {DongTing: A large-scale dataset for anomaly detection of the Linux kernel},
journal = {Journal of Systems and Software},
volume = {203},
pages = {111745},
year = {2023},
issn = {0164-1212},
doi = {https://doi.org/10.1016/j.jss.2023.111745},
url = {https://www.sciencedirect.com/science/article/pii/S0164121223001401},
author = {Guoyun Duan and Yuanzhi Fu and Minjie Cai and Hao Chen and Jianhua Sun}
}
```

## Dataset

The dataset is stored at [http://doi.org/10.5281/zenodo.6627050](http://doi.org/10.5281/zenodo.6627050). The following is a brief introduction.

- The data includes `abnormal_data`, `normal_data`, `models`, `npz` and baseline data, with a total volume of nearly 87GB (including 85GB for abnormal data and normal data, it`s after decompression files size).
- The `Abnormal_data` directory contains 12,116 files containing system call sequence for 26 kernel releases, and the `Normal_data` directory contains 6,850 files containing system call sequences collected from four regression test suites. all of which are raw sequences.
- CNN/RNN, LSTM, and Wavenet (three sets of hyper-parameters per model) machine learning models are selected, the ECOD model (without hyperparameters) was also chosen for the evaluation of DT. DT_abnormal, DT_normal, ADFA-LD, and PLAID are used for training respectively. The results of DT training models are stored in the directory `Models-DongTing`, and the results of ADFA-LD and PLAID training models are stored in the  directory `Models-Comparison`. 
- The directory `npz `stores the encoded dataset of DongTing, ADFA-LD, and PLAID (sequence length varies from  8 to 4495), according to syscall_64.tbl in Linux kernel 5.17, including the training set, validation set, and test set.
- The file `Baseline.xlsx` contains all the information about DongTing dataset, which can be used in training machine learning models. For example, the whole dataset is  randomly divided into three sets with the ratio of 80%:10%:10% (training: validation: test). The implementation of dataset division can be found in the source code.

## Source Code

The source code for dataset development is stored at [https://github.com/HNUSystemsLab/DongTing](https://github.com/HNUSystemsLab/DongTing) and the following is a brief introduction.

- The source code contains three folders, i.e., `Source Code Files`, `Documents` and `DB`, where `Documents `stores the detailed  documents related to development, `DB` stores samples data, and `Source Code Files` stores the source code related to the development of our dataset.
- The detailed description about the source code can be found in `Documents/Documentation.pdf`. The document consists of four parts: environment requirements, database, program structure and working steps, model training and evaluation (including training and evaluation). It details the preparation of the environment, data import method, functional description of each file in the source code directory, how model training and evaluation work and other related contents.

We additionally maintain the dataset and source code on Baidu.com [https://pan.baidu.com/s/1vu1WGZpf2DqMIoyGayNu3w?pwd=dtds](https://pan.baidu.com/s/1vu1WGZpf2DqMIoyGayNu3w?pwd=dtds) to facilitate the access from China.
