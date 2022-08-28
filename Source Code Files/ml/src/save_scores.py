#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""
    Tools to evaluate previously trained models and save results to disk.
    Used by scripts/run_trials for automating jobs on DeepGreen.
"""

import argparse
import time
from itertools import chain
from pathlib import Path

import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model

from data_processing import get_data, load_nested_test, load_nested_test_for_cross_validation

gpu_devices = tf.config.experimental.list_physical_devices("GPU")
for device in gpu_devices:
    tf.config.experimental.set_memory_growth(device, True)

tf.get_logger().setLevel("ERROR")


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=f"Evaluate trained models and save scores.",
    )
    parser.add_argument(
        "--data_set",
        default="adfa",
        choices=["adfa", "plaid", "DongTing_normal", "DongTing_abnormal"],
        help="Data set to evaluate on.",
    )
    # add for wavenet3
    parser.add_argument(
        "--batch_size",
        default=32,
        type=int,
        help="Batch Size"
    )
    parser.add_argument(
        "--path",
        help="Location of model checkpoint.",
    )
    parser.add_argument(
        "--crossval",
        default=0,
        type=int,
        help="whether cross validation or not.",
    )

    return parser


def get_scores(model, x_data, nll=False):
    """Calculates the probability of each sequence occurring.

    Parameters
    ----------
    model : tf.keras model
        Model to get probabilities from.
    x_data : obj
        Data to score.

    Returns
    -------
    Array of scores.

    """

    def predict_gen(model, x_data):
        it = iter(x_data)
        while True:
            try:
                data = next(it)
                #t0 = time.time()
                preds = model(data).numpy()
                new_preds = []
                #new_preds.append(preds)
                for pred, elm in zip(preds, data):
                    cutoff = np.argmax(elm == 0)
                    if cutoff != 0:
                        new_preds.append(pred[:cutoff])
                    else:
                        new_preds.append(pred)
                #t1 = time.time()
                #print("trace length:", data.shape[1])
                #print("one trace eval time:", t1-t0)
                yield new_preds
                #yield new_preds, (data.shape[1], data)
            except StopIteration:
                break

    preds = []
    #tracelen_trace = []
    for x in predict_gen(model, x_data):
        preds.extend(x)
        #tracelen_trace.append(t_t)
    #probs = np.array([pred.max(axis=-1).prod(axis=-1) for pred in preds])
    probs = np.array([np.mean(pred.max(axis=-1)) for pred in preds])

    if nll:
        return np.clip(-np.log2(probs), a_min=0, a_max=1e100)
        # return -np.log2(probs), probs
    else:
        return probs


def save_scores(path, data_set, batch_size=32, crossval=0):
    """Save scores for a given model to disk

    Parameters
    ----------
    path : str
        Path to model checkpoint
    data_set : {"adfa", "plaid"}

    Returns
    -------

    """
    path = Path(path)
    tokens = path.stem.split("_")
    # new_path = path.parent / f"eval_{tokens[1]}_{tokens[2]}"
    if crossval == 1:
        yield_data = load_nested_test_for_cross_validation(data_set)
        for one_data in yield_data:
            new_path = path.parent / f"eval_{one_data[0]}_{tokens[1]}_{tokens[2]}"
            save_scores_helper(path, new_path, data_set, batch_size, one_data[1], one_data[2])
    elif crossval == 0:
        val, attack = load_nested_test(data_set)
        new_path = path.parent / f"eval_{tokens[1]}_{tokens[2]}"
        save_scores_helper(path, new_path, data_set, batch_size, val, attack)
    else: 
        data_sets = ["adfa", "plaid"]
        data_sets.remove(data_set)
        val, attack = load_nested_test(data_sets[0])
        new_path = path.parent / f"eval_{data_sets[0]}_{tokens[1]}_{tokens[2]}"
        save_scores_helper(path, new_path, data_set, batch_size, val, attack)

def save_scores_helper(path, new_path, data_set, batch_size, val, attack):
    train_gen = get_data(data_set=data_set, batch_size=batch_size)[0]

    attack = list(chain(*attack))
    val = list(chain(*val))
    test = (
        tf.data.Dataset.from_tensor_slices(tf.ragged.constant(val + attack))
        .map(lambda x: x)
        #.padded_batch(1, padded_shapes=(None,))
        .padded_batch(batch_size, padded_shapes=(None,))
    )

    # tokens = path.stem.split("_")
    # new_path = path.parent / f"eval_{tokens[1]}_{tokens[2]}"
    if not Path(str(new_path) + ".npz").exists():
        model = load_model(str(path))
        t0 = time.time()
        scores = get_scores(model, test, nll=True)
        t1 = time.time()
        s = get_scores(model, train_gen.map(lambda x, y: x), nll=True)
        baseline = np.median(s)

        # scores, baseline, time
        np.savez_compressed(new_path, [scores, baseline, t1 - t0])
        print(new_path, t1 - t0)

        #print("-----------scores-----------")
        #for idx in range(len(scores)):
        #    print(scores[idx], "-", tracelen_trace[idx][0])
        
        #print("------------trace length and eval time-------------")
        #time_list = []
        #for t_t in tracel_time:
        #    print(t_t[0], ":", t_t[1])
        #    time_list.append(t_t[1])
        #print("avg:", np.mean(time_list))
        #print("var:", np.var(time_list, ddof=1))


if __name__ == "__main__":
    parser = create_parser()
    save_scores(**vars(parser.parse_args()))
