#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""Computes and loads data splits for ADFA-LD and PLAID

    Provides computing and loading of data splits used in training and evaluation see below for main external use cases.
    Operates on pre-processed data sets from adfa_preprocessing.py and plaid_preprocessing.py.
        - get_data : Provides data splits for training and evaluation at the trace level
        - load_nested_test : Provides test set for evaluation at the application level

"""

from itertools import chain
from pathlib import Path
from typing import Hashable

import numpy as np
import tensorflow as tf


def load_files(data_set, nested=False):
    """Loads requested system call data set from disk

    Parameters
    ----------
    data_set : {"adfa", "plaid"}
        The data set to be returned.
    nested : bool
        Return attack sequences nested by application. Default False returns a flat list.

    Returns
    -------
    attack_sequences : List[List[str]] or List[List[List[str]]]
        List of attack system call sequences. When nested=False each element is an attack sequence represented as a list
        of strings. If nested=True each element is a list of all attack sequences belonging to a single application.
    base_sequences : List[List[str]]
        List of baseline system call sequences.

    """
    if data_set not in ["adfa", "plaid"]:
        raise ValueError("data_set must be on of (adfa, plaid)")

    def get_seq(files):
        ret = []
        for f in files:
            with open(f) as file:
                seq = file.read().strip().split(" ")
                if 4495 >= len(seq) >= 8:
                    ret.append(seq)
        return ret

    if data_set == "plaid":
        attack_files = sorted(list(Path("../data/PLAID/attack").rglob("*.txt")))
        baseline_files = Path("../data/PLAID/baseline").rglob("*.txt")
    else:
        root_path = Path("../data/ADFA_decoded_i386/")
        attack_files = sorted(list((root_path / "Attack_Data_Master").rglob("*.txt")))
        baseline_files = list((root_path / "Validation_Data_Master").rglob("*.txt"))
        baseline_files.extend((root_path / "Training_Data_Master").rglob("*.txt"))

    if nested:
        attack_sequences = []
        folders = set([x.parent for x in attack_files])
        for folder in folders:
            tmp = [x for x in attack_files if x.parent == folder]
            attack_sequences.append(get_seq(tmp))
    else:
        attack_sequences = get_seq(attack_files)
    base_sequences = get_seq(baseline_files)
    return attack_sequences, base_sequences


class Encoder:
    """Converts data to a dense integer encoding

    Attributes:
        file_path: location to save/load syscall map
        syscall_map: mapping from item to encoded value
    """

    file_path = Path()
    syscall_map: dict = dict()

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        if self.file_path.exists():
            self.syscall_map = np.load(self.file_path, allow_pickle=True).item()

    def encode(self, syscall: Hashable) -> int:
        """Encodes an individual item

        Unique items are sequentially encoded (ie first item -> 0 next unique item -> 1). The mapping dict is updated
        with new encodings as necessary and immediately written to disk.

        Args:
            syscall: item to encode

        Returns:
            integer encoding of syscall
        """
        if syscall in self.syscall_map:
            return self.syscall_map[syscall]
        else:
            print("error!!! unknown syscall")
            return 666
        # syscall_enc = len(self.syscall_map) + 1
        # self.syscall_map[syscall] = syscall_enc
        # np.save(self.file_path, self.syscall_map)

        # return syscall_enc


def load_data_splits(data_set, train_pct=1.0, ratio=1.0):
    """[Internal] Lazy-loads data splits for training, validation, and evaluation

    Internal function for processing and loading training, validation, and evaluation splits for specified data set.
    For external use get_data.
    Calls with the same data set and ratio will use the same split.
    Training percentage affects only existing training split (repeat calls will not cause data leakage).

    Parameters
    ----------
    data_set : {"adfa", "plaid"}
        Data set to be loaded and split.
    train_pct : float (0, 1]
        Percentage of training data to be returned
    ratio : float
        Ratio of baseline to attack sequences in the testing split

    Returns
    -------
        train : tf.data.Dataset
            Data set for training seq-seq system call language model. Consists of only baseline sequences.
        val : tf.data.Dataset
            Validation dataset for seq-seq system call language model. Consists of only baseline sequences.
        test_val : tf.data.Dataset
            Baseline system call sequences for use in final model evaluation.
        atk : tf.data.Dataset
            Attack system call sequences for use in final model evaluation.

    """
    val_split = 0.2
    if data_set not in ["adfa", "plaid", "DongTing_normal", "DongTing_abnormal"]:
        raise ValueError("data_set must be on of (adfa, plaid, DongTing_normal, DongTing_abnormal)")

    if ratio != 1:
        out_path = Path(f"../out/{data_set}_{ratio}.npz")
    else:
        out_path = Path(f"../out/{data_set}.npz")

    if out_path.exists():
        train, val, test_val, atk = np.load(out_path, allow_pickle=True)["arr_0"]
    else:
        out_path.parent.mkdir(exist_ok=True, parents=True)
        encoder = Encoder(f"../data/{data_set}_encoder.npy")

        atk_files, normal_files = load_files(data_set)

        # create test with 1:1 ratio attack and val
        normal_idxs = np.arange(len(normal_files))
        np.random.shuffle(normal_idxs)
        test_val_files = []
        for idx in normal_idxs[: len(atk_files) * ratio]:
            test_val_files.append(normal_files[idx])

        normal_idxs = normal_idxs[len(atk_files) * ratio :]
        n_val = np.int(np.round(len(normal_idxs) * val_split))
        val_files = []
        for idx in normal_idxs[:n_val]:
            val_files.append(normal_files[idx])

        train_files = []
        for idx in normal_idxs[n_val:]:
            train_files.append(normal_files[idx])

        vec_encode = np.vectorize(encoder.encode)
        train = [vec_encode(row).astype(np.float32) for row in train_files]
        val = [vec_encode(row).astype(np.float32) for row in val_files]
        atk = [vec_encode(row).astype(np.float32) for row in atk_files]
        test_val = [vec_encode(row).astype(np.float32) for row in test_val_files]

        np.savez_compressed(out_path, [train, val, test_val, atk])

    if train_pct < 1:
        train_idxs = np.arange(int(len(train) * train_pct))
        np.random.shuffle(train_idxs)
        tmp = []
        for idx in train_idxs:
            tmp.append(train[idx])
        train = tmp

    train = tf.data.Dataset.from_tensor_slices(tf.ragged.constant(train))
    val = tf.data.Dataset.from_tensor_slices(tf.ragged.constant(val))
    return train, val, test_val, atk


def get_data(data_set, batch_size=64, train_pct=1.0, ratio=1.0):
    """Lazy-loads data splits for training, validation, and evaluation

    Converts load_data_splits outputs into ready to go data structures.

    Parameters
    ----------
    data_set : {"adfa", "plaid"}
        Data set to be loaded and split.
    batch_size : int
        Batch size for data splits
    train_pct : float (0, 1]
        Percentage of training data to be returned
    ratio : float
        Ratio of baseline to attack sequences in the testing split

    Returns
    -------
        train : tf.data.Dataset
            Data set for training seq-seq system call language model. Consists of only baseline sequences.
        val : tf.data.Dataset
            Validation dataset for seq-seq system call language model. Consists of only baseline sequences.
        (test, test_labels): (tf.data.Dataset, np.array)
            Evaluation data set and corresponding labels for each sequence; 0 for baseline, 1 for attack.

    """
    if data_set not in ["adfa", "plaid", "DongTing_normal", "DongTing_abnormal"]:
        raise ValueError("data_set must be on of (adfa, plaid, DongTing_normal, DongTing_abnormal)")

    train, val, test_val, atk = load_data_splits(
        data_set, train_pct=train_pct, ratio=ratio
    )

    def add_train_labels(x):
        return x[:-1], x[1:]

    train = (
        train.map(add_train_labels)
        .shuffle(buffer_size=1024)
        .padded_batch(batch_size, padded_shapes=([None], [None]))
    )
    val = val.map(add_train_labels).padded_batch(
        batch_size,
        padded_shapes=(
            [None],
            [None],
        ),
    )
    test = (
        tf.data.Dataset.from_tensor_slices(tf.ragged.constant(test_val + atk))
        .map(lambda x: x)
        .padded_batch(batch_size, padded_shapes=(None,))
    )
    test_labels = np.zeros(len(test_val) + len(atk))
    test_labels[len(test_val) :] = 1
    return (
        train,
        val,
        (test, test_labels),
    )

def load_nested_test_for_cross_validation(data_set):
    if data_set in ["DongTing_normal", "DongTing_abnormal"]:
        cross_val_datas = ["adfa", "plaid"]
        for cross_data in cross_val_datas:
            test_val_new, atk_new = load_nested_test(cross_data)
            yield cross_data, test_val_new, atk_new
    elif data_set in ["adfa", "plaid"]:
        cross_val_datas = ["DongTing_normal", "DongTing_abnormal"]
        for cross_data in cross_val_datas:
            test_val_new, atk_new = load_nested_test(cross_data)
            yield cross_data, test_val_new, atk_new
    else:
        raise valueError("data_set must be one of (adfa, plaid, DongTing)")

def load_nested_test(data_set):
    """Loads nested version of the testing set

    Loads testing set nested by application. Baseline sequences are randomly assigned to an application such that there
    is an equal number of test and attack applications with a given number of traces.

    Parameters
    ----------
    data_set : {"adfa", "plaid"}
        Data set to load test split of

    Returns
    -------
        test_val_new : List[List[List[int]]]
            Baseline sequences nested by application
        atk_new : List[List[List[int]]]
            Attack sequences nested by application

    """
    if data_set in ["DongTing_normal", "DongTing_abnormal"]:
        test_list = load_data_splits(data_set)[2]
        atk_list = load_data_splits(data_set)[3]
        # len_base = len(test_list)//2
        len_base = len(test_list) - len(atk_list)
        test_base = test_list[:len_base]
        test_atk = test_list[len_base:]
        for idx in range(len(test_base)):
            test_base[idx] = test_base[idx][:1000]
        for idx in range(len(test_atk)):
            test_atk[idx] = test_atk[idx][:1000]
        nested_test_atk = []
        for one_attack in test_atk:
            tmp_atk = []
            tmp_atk.append(one_attack)
            nested_test_atk.append(tmp_atk)
    
    elif data_set in ["adfa", "plaid"]:
        test_base = load_data_splits(data_set)[2]
        test_atk = load_files(data_set, nested=True)[0]
        nested_test_atk = test_atk
        encoder = Encoder(f"../data/unified_encoder.npy")
        vec_encode = np.vectorize(encoder.encode)
    
    else:
        raise ValueError("data_set must be on of (adfa, plaid, DongTing_nor, DongTing_abnor)")

    attack_lens = [len(x) for x in nested_test_atk]
    nested_test_atk = list(chain(*nested_test_atk))

    idx = 0
    test_base_new = []
    atk_new = []
    for folder_len in attack_lens:
        # subdir_val = []
        subdir_atk = []
        for _ in range(folder_len):
            # subdir_val.append(test_base[idx])
            if data_set in ["DongTing_normal", "DongTing_abnormal"]:
                subdir_atk.append(nested_test_atk[idx])
            else:
                subdir_atk.append(vec_encode(nested_test_atk[idx]))
            idx += 1
        # test_base_new.append(subdir_val)
        atk_new.append(subdir_atk)
    for index in range(len(test_base)):
        subdir_val = []
        subdir_val.append(test_base[index]) 
        test_base_new.append(subdir_val)
    return test_base_new, atk_new


if __name__ == "__main__":
    adfa_data = load_data_splits("adfa")
    plaid_data = load_data_splits("plaid")
    print(len(list(adfa_data[0])), len(list(plaid_data[0])))
    for data in [adfa_data, plaid_data]:
        for elm in data:
            print(len(list(elm)))
    enc = np.load("../data/adfa_encoder.npy", allow_pickle=True).item()
    print("ADFA vocab size ", len(enc) + 1)
    enc = np.load("../data/plaid_encoder.npy", allow_pickle=True).item()
    print("PLAID vocab size ", len(enc) + 1)
