#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""
    Submits jobs to run all model training and evaluation on DeepGreen.
"""

from pathlib import Path

from submitter import main as submitter


def main(data_set):
    """
    Goal is 30 trials of each run
    300 epochs ADFA, 30 Epochs PLAID
    """
#    models = ["cnnrnn", "lstm", "wavenet"]
#    for i in range(30):
#        for model in models:
#            for single_model in range(1, 4):
#                py_call = "python ../src/train_ensemble.py "
#                job = f"{py_call} --epochs 300 --single_flag {single_model} --model {model} --data_set adfa --trial {i}"
#                submitter(job, hours=10, job_name=f"{model}_a_{single_model}_{i:02d}")
#                job = f"{py_call} --epochs 30 --single_flag {single_model} --model {model} --data_set plaid --trial {i}"
#                submitter(job, hours=10, job_name=f"{model}_p_{single_model}_{i:02d}")

#    models = ["cnnrnn", "lstm", "wavenet"]
    models = ["wavenet"]
#    models = ["cnnrnn", "lstm"]
#    single_model = 1
    for model in models:
        for single_model in range(1, 4):
            py_call = "python ../src/train_ensemble.py "
            job = f"{py_call} --epochs 300 --single_flag {single_model} --model {model} --data_set {data_set} --batch_size 16"
            # job = f"{py_call} --epochs 30 --single_flag {single_model} --model {model} --data_set plaid"
            submitter(job, gpus=1, hours=60, job_name=f"{model}_{data_set}_{single_model}")


def save_scores(data_set):
    epoch = 30 if data_set == "plaid" else 300
#    models = ["cnnrnn", "lstm", "wavenet"]
    models = ["cnnrnn", "lstm"]
#    models = ["wavenet"]

    for model in models:
        paths = Path(f"../trials/{model}_{data_set}_{epoch}").glob("model_*.ckpt")
        for path in paths:
            tokens = path.stem.split("_")
            new_path = path.parent / f"eval_{tokens[1]}_{tokens[2]}"
            if not Path(str(new_path) + ".npz").exists():
                py_call = f"python ../src/save_scores.py --path {str(path)} --data_set {data_set} --batch_size 16 --crossval 0"
                submitter(py_call, gpus=1, hours=6, job_name=f"eval_{data_set}_{model}", mem=64)


if __name__ == "__main__":
#     main("DongTing_abnormal")
#    save_scores("adfa")
#    save_scores("plaid")
#    save_scores("DongTing_normal")
    save_scores("DongTing_abnormal")
