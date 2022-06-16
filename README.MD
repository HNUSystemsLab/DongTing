# DongTing Dataset release stage 1:

We plan to release the DongTing Dataset at two stages. Currently at the first stage, we have released a testing subset (4.15GB) of the dataset together with trained models for paper submission. At the second stage, we would release all the dataset (85G) upon the acceptance of the paper. With the data and the models released at the first stage, the experiment results in Section 5 of the submission can be obtained. The data and code we provide at current stage mainly include:

- Raw system call sequence files of the DongTing testing subset, including  1688 normal and abnormal sequence files with a total size of 4.15GB..
- Encoding vectors of raw sequence files for machine learning. The vectors encoding normal sequences and abnormal sequences (based on syscall\_64.tbl in kernel 5.17) are provided in 2 npz files (1.38MB).
- The CNN/RNN, LSTM and WaveNet models trained using the training set of the DongTing Dataset. For each model architecture, 2 models are trained with normal and abnormal data respectively. A total of 6 model files (662MB) are provided.
- Source code for our experiment results. Part of the code is adapted from the release code for the paper "Methods for Host-based Intrusion Detection with Deep Learning".

When our dataset is fully released to the public, a permanent connection (DOI) would also be established in the managed warehouse for users to download. 
