# DongTing Dataset Phase 1 Data

The DongTing Dataset is publishing in two stage, one stage is to publish part of the dataset when the paper is submitted, which is a test subset of the DongTing benchmark data; the other stage is to publish the full data and documents of the dataset after the paper is published. The current submission is a part of the dataset (4.15GB in 85G), which can properly complete the validation experiments in Section 5 of the paper. The data we provide at this stage mainly include:

- The original data of DongTing test subset sequence files, including Normal and Abnormal sequence files, a total of 1688 (4.15GB).
- On the basis of the DongTing dataset, the NPZ files after coding and initialization, including two files of normal sequence and abnormal sequence (1.38MB).
- The CNN/RNN, LSTM and WaveNet deep learning models trained by the Abnormal and Normal data in the DongTing Dataset, a total of 6 model files (662MB).
- Deep learning verification source code. This part of the code comes from the document "Methods for Host-based Intrusion Detection with Deep Learning", which can be downloaded through the link of this article.
The test subset sequence files serve as a representation of our work and collection of sequence result data in the form of raw sequences that are not encoded by machine learning. The data of the two NPZ files after sequence length selection (Select Sequences length 8-4495), machine learning encoding (based on syscall_64.tbl in kernel 5.17), including training set, validation set and test set. The deep learning models were trained separately through the normal and abnormal data in DongTing. A total of 18 models were obtained after training. After importing, they can be prepared for the verification of the experiment. The models in the data at this stage are represented by 6 randomly selected models.

DongTing Dataset分两个阶段发布，一个阶段是论文提交时公布数据集的部分数据，这部分数据是DongTing基准数据的测试子集；另一阶段是论文发表后将发布数据集的全部数据和文档。当前提交的文件为数据集中的一部分（4.15GB in 85G），能正常完成文中第5章的验证实验。这阶段我们提供的数据主要包括：
1、DongTing测试子集序列文件原始数据，包括Normal和Abnormal两部分序列文件，共1688条(4.15GB)。
2、在DongTing数据集基础上，经编码初始化之后的NPZ文件，包括正常序列和异常序列2个文件(1.38MB)。
3、采用DongTing Dataset中Abnormal和Normal两类数据训练好的CNN/RNN、LSTM和WaveNet深度学习模型，共6个模型文件(662MB)。
4、深度学习验证源代码。此部分代码来源于文献“Methods for Host-based Intrusion Detection with Deep Learning”，可通过此文章的链接下载。
测试子集序列文件作为我们工作和收集序列结果数据形式的代表，他们都是未经机器学习编码的的原始序列。两个NPZ文件经过序列长度选择（Select Sequences length 8-4495）、机器学习编码（以内核5.17中的syscall_64.tbl为基准）后的数据，包括训练集、验证集和测试集。通过DongTing中正常和异常数据分别训练深度学习模型，训练后共获得18个模型，导入后可为实验的验证做准备，本阶段数据中的模型经随机挑选的6个模型做为代表。


#########################



DongTing is the first large-scale dataset for kernel anomaly detection based on Linux system calls. The detailed description will be uploaded after the paper goes online. The DongTing dataset, We will release it when the paper is published.